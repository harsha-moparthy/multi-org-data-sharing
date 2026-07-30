"""Audit reconstruction: can both orgs answer "who saw what, and under whose authority?"

The spec requires every access to be reconstructable from audit logs, for the
granting *and* consuming organization. This script demonstrates that, then does
the part that makes it worth believing: it tries to tamper with the trail and
shows the tamper being caught at the exact row.

    python -m attacks.audit_reconstruction
"""

from __future__ import annotations

import json
from pathlib import Path

from sharing import credentials
from sharing.db import admin_conn, authorized, close_pool, init_schema
from sharing.portal import ALL_COLUMNS, Portal

RESULTS = Path(__file__).resolve().parents[1] / "results"


def _hr(title: str) -> None:
    print()
    print("=" * 74)
    print(title)
    print("=" * 74)


def main() -> int:
    init_schema()
    RESULTS.mkdir(exist_ok=True)
    portal = Portal("rls")
    report: dict = {}

    _hr("1. A day of activity: humans and agents, allowed and denied")
    # legitimate reads
    priya = credentials.mint(subject="mr-priya", grant_id="g-main")
    agent1 = credentials.mint(
        subject="mr-agent-1", grant_id="g-main", delegation_id="d-agent1"
    )
    agent2 = credentials.mint(
        subject="mr-agent-2", grant_id="g-main", delegation_id="d-agent2"
    )
    lena = credentials.mint(subject="co-lena", grant_id="g-contoso")

    portal.read_shipments(priya, columns=ALL_COLUMNS)
    portal.read_shipments(agent1, columns=ALL_COLUMNS)
    portal.read_shipments(agent2, columns=["shipment_id", "carrier"])
    portal.read_shipments(lena, columns=ALL_COLUMNS)
    # a denied attempt: contoso's agent tries meridian's grant
    portal.read_shipments(
        credentials.mint(subject="co-agent-1", grant_id="g-main", delegation_id="d-agent1"),
        columns=ALL_COLUMNS,
    )
    # a forged credential
    portal.read_shipments(
        credentials.tamper(agent1, sub="mr-priya", delegation_id=None),
        columns=ALL_COLUMNS,
    )
    print("6 requests issued: 4 legitimate, 2 that must be refused.")

    _hr("2. The PROVIDER's view (northwind): who touched our data?")
    nw_cred = credentials.mint_audit(subject="nw-dana", org="northwind")
    with authorized(None, audit_credential=nw_cred) as conn:
        rows = conn.execute(
            "SELECT seq, subject, acting_for, delegation_id, counterparty_org, "
            "decision, deny_reason, row_count, columns_served, columns_masked "
            "FROM portal.audit_provider_view WHERE action='read' ORDER BY seq"
        ).fetchall()
    print(f"{'seq':>4} {'subject':12} {'acting_for':11} {'deleg':10} "
          f"{'party':9} {'decision':8} {'rows':>4}  masked")
    for r in rows:
        print(
            f"{r['seq']:>4} {str(r['subject'] or '-'):12} {str(r['acting_for'] or '-'):11} "
            f"{str(r['delegation_id'] or '-'):10} {str(r['counterparty_org'] or '-'):9} "
            f"{r['decision']:8} {r['row_count']:>4}  "
            f"{','.join(r['columns_masked'] or []) or '-'}"
        )
    report["provider_rows"] = len(rows)
    print()
    print("Note the two denials carry subject=NULL: an unverifiable credential is")
    print("recorded as *unattributed* rather than borrowing the identity it claimed.")
    print("The claimed subject is preserved in the request payload for investigation.")

    _hr("3. The CONSUMER's view (meridian): what did our people and agents do?")
    mr_cred = credentials.mint_audit(subject="mr-priya", org="meridian")
    with authorized(None, audit_credential=mr_cred) as conn:
        rows_c = conn.execute(
            "SELECT seq, subject, acting_for, counterparty_org, decision, row_count "
            "FROM portal.audit_consumer_view WHERE action='read' ORDER BY seq"
        ).fetchall()
    for r in rows_c:
        print(
            f"  seq {r['seq']:>3}  {str(r['subject'] or '<unattributed>'):16} "
            f"acting for {str(r['acting_for'] or '-'):10} "
            f"-> {r['counterparty_org']}  {r['decision']} ({r['row_count']} rows)"
        )
    report["consumer_rows"] = len(rows_c)
    print()
    print("The two orgs see different slices of the same trail. Meridian does not")
    print("see contoso's reads, and contoso cannot see meridian's:")
    co_cred = credentials.mint_audit(subject="co-lena", org="contoso")
    with authorized(None, audit_credential=co_cred) as conn:
        n_co = conn.execute(
            "SELECT count(*) AS n FROM portal.audit_consumer_view WHERE action='read'"
        ).fetchone()["n"]
    print(f"  contoso's own consumer view: {n_co} read(s) — its own only")
    report["contoso_visible_reads"] = n_co

    _hr("4. Forged audit credential: can meridian read northwind's provider view?")
    forged = credentials.tamper(mr_cred, audit_org="northwind")
    with authorized(None, audit_credential=forged) as conn:
        n_forged = conn.execute(
            "SELECT count(*) AS n FROM portal.audit_provider_view"
        ).fetchone()["n"]
    print(f"  rows visible with a forged audit credential: {n_forged}  (must be 0)")
    report["forged_audit_rows"] = n_forged
    assert n_forged == 0, "forged audit credential leaked the provider trail"

    _hr("5. Full reconstruction of one access")
    with authorized(None, audit_credential=nw_cred) as conn:
        one = conn.execute(
            "SELECT * FROM portal.audit_provider_view "
            "WHERE decision='allow' AND delegation_id IS NOT NULL "
            "ORDER BY seq LIMIT 1"
        ).fetchone()
    print(f"  event seq        : {one['seq']}")
    print(f"  at               : {one['at']}")
    print(f"  agent            : {one['subject']}")
    print(f"  acting for human : {one['acting_for']}")
    print(f"  under grant      : {one['grant_id']}")
    print(f"  via delegation   : {one['delegation_id']}")
    print(f"  rows served      : {one['row_count']} -> {one['row_ids']}")
    print(f"  columns served   : {one['columns_served']}")
    print(f"  columns withheld : {one['columns_masked']}")
    print(f"  request          : {json.dumps(one['request'])}")

    with admin_conn() as conn:
        chain = conn.execute(
            "SELECT g.grantee_principal, g.approved_by, g.expires_at, "
            "d.delegator, d.delegatee, d.purpose, d.depth, d.expires_at AS d_exp "
            "FROM portal.data_grant g JOIN portal.delegation d ON d.grant_id=g.grant_id "
            "WHERE d.delegation_id = %s",
            (one["delegation_id"],),
        ).fetchone()
    print()
    print("  authority chain, reconstructed from the grant and delegation rows:")
    print(f"    northwind's {chain['approved_by']} approved the share")
    print(f"      -> granted to {chain['grantee_principal']} "
          f"(expires {chain['expires_at']:%Y-%m-%d})")
    print(f"      -> delegated by {chain['delegator']} to {chain['delegatee']} "
          f"(depth {chain['depth']})")
    print(f"      -> stated purpose: {chain['purpose']!r}")
    print(f"      -> delegation expires {chain['d_exp']:%Y-%m-%d %H:%M}")

    _hr("6. Tamper detection: the trail must not be quietly editable")
    with admin_conn() as conn:
        before = conn.execute("SELECT * FROM portal.audit_verify()").fetchone()
        print(f"  chain over {before['checked']} events: "
              f"{'INTACT' if before['first_bad_seq'] is None else 'BROKEN'}")

        # 6a. UPDATE is refused outright by the append-only trigger.
        try:
            conn.execute(
                "UPDATE portal.audit_event SET row_count = 999 WHERE seq = %s",
                (one["seq"],),
            )
            print("  UNEXPECTED: an UPDATE on audit_event succeeded")
            return 1
        except Exception as exc:
            print(f"  UPDATE audit_event  -> refused: {str(exc).splitlines()[0]}")

        # 6b. DELETE likewise.
        try:
            conn.execute("DELETE FROM portal.audit_event WHERE seq = %s", (one["seq"],))
            print("  UNEXPECTED: a DELETE on audit_event succeeded")
            return 1
        except Exception as exc:
            print(f"  DELETE audit_event  -> refused: {str(exc).splitlines()[0]}")

        # 6c. The determined insider: disable the trigger and rewrite history.
        # This is what a DBA with the owner role can actually do, so the question
        # is not "can it be prevented" but "is it detectable".
        print()
        print("  now the realistic threat: a privileged insider disables the")
        print("  append-only trigger and edits a row to hide what an agent saw.")
        conn.execute("SET ROLE portal_owner")
        conn.execute("ALTER TABLE portal.audit_event DISABLE TRIGGER audit_no_update")
        conn.execute(
            "UPDATE portal.audit_event SET row_count = 0, row_ids = '{}' WHERE seq = %s",
            (one["seq"],),
        )
        conn.execute("ALTER TABLE portal.audit_event ENABLE TRIGGER audit_no_update")
        conn.execute("RESET ROLE")
        after = conn.execute("SELECT * FROM portal.audit_verify()").fetchone()
        print(f"  edit succeeded (row_count now 0 for seq {one['seq']})")
        print(f"  audit_verify(): first divergent seq = {after['first_bad_seq']}  "
              f"<-- caught at the exact row")
        report["tamper_detected_at"] = after["first_bad_seq"]
        assert after["first_bad_seq"] == one["seq"], "tamper not caught at the right row"

        # restore
        conn.execute("SET ROLE portal_owner")
        conn.execute("ALTER TABLE portal.audit_event DISABLE TRIGGER audit_no_update")
        conn.execute(
            "UPDATE portal.audit_event SET row_count = %s, row_ids = %s WHERE seq = %s",
            (one["row_count"], one["row_ids"], one["seq"]),
        )
        conn.execute("ALTER TABLE portal.audit_event ENABLE TRIGGER audit_no_update")
        conn.execute("RESET ROLE")
        restored = conn.execute("SELECT * FROM portal.audit_verify()").fetchone()
        print(f"  after restoring the original values: "
              f"{'INTACT' if restored['first_bad_seq'] is None else 'still broken'}")

    _hr("7. Reconciliation: does every served row have a live authority?")
    # The audit trail claims which rows were served. Re-derive, from the grant
    # and delegation rows alone, whether each claim was authorized. A mismatch
    # means either the portal served something it should not have, or the trail
    # is lying about what it served.
    with admin_conn() as conn:
        unauth = conn.execute(
            """
            SELECT e.seq, e.subject, e.row_ids
              FROM portal.audit_event e
             WHERE e.action='read' AND e.decision='allow'
               AND EXISTS (
                 SELECT 1 FROM unnest(e.row_ids) rid
                  JOIN portal.shipment s ON s.shipment_id = rid
                  LEFT JOIN portal.data_grant g ON g.grant_id = e.grant_id
                 WHERE s.owner_org <> g.provider_org
                    OR portal.class_rank(s.classification)
                       > portal.class_rank(g.max_classification)
                    OR (s.partner_org IS NOT NULL AND s.partner_org <> g.grantee_org)
               )
            """
        ).fetchall()
        ungranted = conn.execute(
            "SELECT count(*) AS n FROM portal.audit_event e "
            "WHERE e.action='read' AND e.decision='allow' AND e.grant_id IS NOT NULL "
            "AND NOT EXISTS (SELECT 1 FROM portal.data_grant g "
            "WHERE g.grant_id=e.grant_id AND g.approved_at IS NOT NULL)"
        ).fetchone()["n"]
    print(f"  served rows outside their grant's scope : {len(unauth)}  (must be 0)")
    print(f"  reads under a never-approved grant      : {ungranted}  (must be 0)")
    report["rows_outside_scope"] = len(unauth)
    report["reads_without_approval"] = ungranted
    assert not unauth and ungranted == 0

    (RESULTS / "audit_reconstruction.json").write_text(json.dumps(report, indent=2, default=str))
    print()
    print("All audit assertions held.")
    close_pool()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
