"""Audit trail: append-only, chained, org-scoped, and reconcilable."""

from __future__ import annotations

import psycopg
import pytest

from sharing import credentials
from sharing.db import admin_conn, authorized
from sharing.portal import ALL_COLUMNS, Portal


def test_chain_is_intact_after_activity(fresh):
    p = Portal("rls")
    p.read_shipments(credentials.mint(subject="mr-priya", grant_id="g-main"))
    p.read_shipments(
        credentials.mint(subject="mr-agent-1", grant_id="g-main",
                         delegation_id="d-agent1")
    )
    with admin_conn() as conn:
        r = conn.execute("SELECT * FROM portal.audit_verify()").fetchone()
    assert r["first_bad_seq"] is None
    assert r["checked"] >= 2


def test_update_and_delete_are_refused():
    with admin_conn() as conn:
        with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
            conn.execute("UPDATE portal.audit_event SET row_count=1 WHERE seq=1")
        with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
            conn.execute("DELETE FROM portal.audit_event WHERE seq=1")


def test_tampering_with_the_trail_is_detected_at_the_exact_row(fresh):
    """The insider case: trigger disabled, row rewritten. Must still be caught."""
    p = Portal("rls")
    res = p.read_shipments(credentials.mint(subject="mr-priya", grant_id="g-main"))
    seq = res.audit_seq
    with admin_conn() as conn:
        assert conn.execute(
            "SELECT * FROM portal.audit_verify()"
        ).fetchone()["first_bad_seq"] is None

        conn.execute("SET ROLE portal_owner")
        conn.execute("ALTER TABLE portal.audit_event DISABLE TRIGGER audit_no_update")
        conn.execute("UPDATE portal.audit_event SET row_count=0 WHERE seq=%s", (seq,))
        conn.execute("ALTER TABLE portal.audit_event ENABLE TRIGGER audit_no_update")
        conn.execute("RESET ROLE")

        bad = conn.execute("SELECT * FROM portal.audit_verify()").fetchone()["first_bad_seq"]
    assert bad == seq, f"tamper at seq {seq} reported at {bad}"


def test_every_read_is_audited_allow_and_deny(fresh):
    p = Portal("rls")
    with admin_conn() as conn:
        before = conn.execute(
            "SELECT count(*) AS n FROM portal.audit_event WHERE action='read'"
        ).fetchone()["n"]

    p.read_shipments(credentials.mint(subject="mr-priya", grant_id="g-main"))
    p.read_shipments("garbage-credential")

    with admin_conn() as conn:
        rows = conn.execute(
            "SELECT decision, subject FROM portal.audit_event WHERE action='read' "
            "ORDER BY seq DESC LIMIT 2"
        ).fetchall()
        after = conn.execute(
            "SELECT count(*) AS n FROM portal.audit_event WHERE action='read'"
        ).fetchone()["n"]
    assert after == before + 2, "a request went unaudited"
    decisions = {r["decision"] for r in rows}
    assert decisions == {"allow", "deny"}
    # the denial must be visibly unattributed
    deny = next(r for r in rows if r["decision"] == "deny")
    assert deny["subject"] is None


def test_denial_does_not_borrow_the_claimed_identity(fresh):
    """A forged credential's denial must not be attributed to whoever it named."""
    p = Portal("rls")
    good = credentials.mint(subject="mr-agent-1", grant_id="g-main",
                            delegation_id="d-agent1")
    p.read_shipments(credentials.tamper(good, sub="mr-priya"))
    with admin_conn() as conn:
        r = conn.execute(
            "SELECT subject, request FROM portal.audit_event "
            "WHERE action='read' ORDER BY seq DESC LIMIT 1"
        ).fetchone()
    assert r["subject"] is None, "an unverifiable request was attributed to a real principal"
    assert r["request"]["claimed_sub"] == "mr-priya", (
        "the claim was not preserved for investigation"
    )


def test_the_two_org_views_are_disjoint_and_complete(fresh):
    p = Portal("rls")
    p.read_shipments(credentials.mint(subject="mr-priya", grant_id="g-main"))
    p.read_shipments(credentials.mint(subject="co-lena", grant_id="g-contoso"))

    mr = credentials.mint_audit(subject="mr-priya", org="meridian")
    co = credentials.mint_audit(subject="co-lena", org="contoso")
    nw = credentials.mint_audit(subject="nw-dana", org="northwind")

    with authorized(None, audit_credential=mr) as conn:
        mr_rows = conn.execute(
            "SELECT seq FROM portal.audit_consumer_view WHERE action='read'"
        ).fetchall()
    with authorized(None, audit_credential=co) as conn:
        co_rows = conn.execute(
            "SELECT seq FROM portal.audit_consumer_view WHERE action='read'"
        ).fetchall()
    with authorized(None, audit_credential=nw) as conn:
        nw_rows = conn.execute(
            "SELECT seq FROM portal.audit_provider_view WHERE action='read' "
            "AND decision='allow'"
        ).fetchall()

    mr_seqs = {r["seq"] for r in mr_rows}
    co_seqs = {r["seq"] for r in co_rows}
    nw_seqs = {r["seq"] for r in nw_rows}
    assert mr_seqs and co_seqs
    assert not (mr_seqs & co_seqs), "the two consumers can see each other's reads"
    # the provider sees both partners' allowed reads of its data
    assert mr_seqs <= nw_seqs and co_seqs <= nw_seqs


def test_audit_records_exactly_which_rows_and_columns(fresh):
    """The trail must be specific enough to reconstruct an access."""
    p = Portal("rls")
    tok = credentials.mint(subject="mr-agent-1", grant_id="g-main",
                           delegation_id="d-agent1")
    res = p.read_shipments(tok, columns=ALL_COLUMNS)
    with admin_conn() as conn:
        r = conn.execute(
            "SELECT row_ids, columns_served, columns_masked, acting_for, delegation_id "
            "FROM portal.audit_event WHERE seq=%s", (res.audit_seq,)
        ).fetchone()
    assert sorted(r["row_ids"]) == res.row_ids
    assert set(r["columns_masked"]) == {
        "unit_cost_usd", "margin_pct", "contact_email", "contact_phone"
    }
    assert r["acting_for"] == "mr-priya", "the delegation chain is not recorded"
    assert r["delegation_id"] == "d-agent1"


def test_no_served_row_is_outside_its_grants_scope(fresh):
    """Reconciliation: the trail's own claims must be consistent with the grants."""
    p = Portal("rls")
    for sub, dele in [("mr-priya", None), ("mr-agent-1", "d-agent1"),
                      ("mr-agent-2", "d-agent2"), ("co-lena", None)]:
        gid = "g-contoso" if sub == "co-lena" else "g-main"
        p.read_shipments(
            credentials.mint(subject=sub, grant_id=gid, delegation_id=dele),
            columns=ALL_COLUMNS,
        )
    with admin_conn() as conn:
        bad = conn.execute(
            """
            SELECT e.seq FROM portal.audit_event e
             WHERE e.action='read' AND e.decision='allow'
               AND EXISTS (
                 SELECT 1 FROM unnest(e.row_ids) rid
                  JOIN portal.shipment s ON s.shipment_id = rid
                  JOIN portal.data_grant g ON g.grant_id = e.grant_id
                 WHERE s.owner_org <> g.provider_org
                    OR portal.class_rank(s.classification)
                       > portal.class_rank(g.max_classification)
                    OR (s.partner_org IS NOT NULL AND s.partner_org <> g.grantee_org)
               )
            """
        ).fetchall()
    assert bad == [], f"rows served outside their grant's scope: {bad}"
