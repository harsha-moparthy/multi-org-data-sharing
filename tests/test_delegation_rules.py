"""Delegation must narrow, never widen — enforced by the database.

These assert the *creation-time* rules. The read-time rules are covered by the
attack suite; both matter, because a system that only checks at read time
accumulates invalid delegation rows that look authoritative in the console.
"""

from __future__ import annotations

import psycopg
import pytest

from sharing.db import admin_conn


def _insert(**kw):
    cols = ", ".join(kw)
    ph = ", ".join(["%s"] * len(kw))
    with admin_conn() as conn:
        conn.execute(f"INSERT INTO portal.delegation ({cols}) VALUES ({ph})",
                     tuple(kw.values()))


def _cleanup(did):
    with admin_conn() as conn:
        conn.execute("DELETE FROM portal.delegation WHERE delegation_id=%s", (did,))


BASE = dict(
    grant_id="g-main",
    delegator="mr-priya",
    delegatee="mr-agent-x",
    depth=1,
    purpose="test",
)


def test_a_valid_narrowing_delegation_is_accepted():
    """The positive case, so the rules below are not vacuous."""
    try:
        _insert(
            delegation_id="d-test-ok",
            region_scope=["EU"],
            allow_cost=False,
            allow_contact=False,
            expires_at="2026-08-05",
            **BASE,
        )
        with admin_conn() as conn:
            n = conn.execute(
                "SELECT count(*) AS n FROM portal.delegation WHERE delegation_id='d-test-ok'"
            ).fetchone()["n"]
        assert n == 1
    finally:
        _cleanup("d-test-ok")


def test_region_wider_than_grant_is_refused():
    with pytest.raises(psycopg.errors.RaiseException, match="exceed grant scope"):
        _insert(
            delegation_id="d-test-wide",
            region_scope=["EU", "UK", "APAC"],  # grant is EU,UK
            expires_at="2026-08-05",
            **BASE,
        )


def test_column_wider_than_grant_is_refused():
    # g-main allows cost but NOT contact
    with pytest.raises(psycopg.errors.RaiseException, match="widen the column scope"):
        _insert(
            delegation_id="d-test-col",
            region_scope=["EU"],
            allow_contact=True,
            expires_at="2026-08-05",
            **BASE,
        )


def test_delegation_cannot_outlive_the_grant():
    with pytest.raises(psycopg.errors.RaiseException, match="cannot outlive grant"):
        _insert(
            delegation_id="d-test-long",
            region_scope=["EU"],
            expires_at="2099-01-01",
            **BASE,
        )


def test_only_the_grantee_may_create_a_first_hop_delegation():
    with pytest.raises(psycopg.errors.RaiseException, match="does not hold grant"):
        _insert(
            delegation_id="d-test-notmine",
            grant_id="g-main",
            delegator="mr-tomas",       # not the grantee of g-main
            delegatee="mr-agent-x",
            depth=1,
            purpose="test",
            region_scope=["EU"],
            expires_at="2026-08-05",
        )


def test_delegatee_must_be_an_agent_not_a_human():
    with pytest.raises(psycopg.errors.RaiseException, match="must be an agent"):
        _insert(
            delegation_id="d-test-human",
            grant_id="g-main",
            delegator="mr-priya",
            delegatee="mr-tomas",       # a human
            depth=1,
            purpose="test",
            region_scope=["EU"],
            expires_at="2026-08-05",
        )


def test_subdelegation_cannot_widen_beyond_parent():
    """d-agent1 is EU-only with no cost; a child asking for UK must fail."""
    with pytest.raises(psycopg.errors.RaiseException, match="exceed parent"):
        _insert(
            delegation_id="d-test-sub",
            grant_id="g-main",
            delegator="mr-agent-1",
            delegatee="mr-agent-x",
            depth=2,
            parent_delegation="d-agent1",
            region_scope=["EU", "UK"],
            purpose="test",
            expires_at="2026-08-02",
        )


def test_subdelegation_cannot_outlive_parent():
    with pytest.raises(psycopg.errors.RaiseException, match="outlive parent"):
        _insert(
            delegation_id="d-test-sublong",
            grant_id="g-main",
            delegator="mr-agent-1",
            delegatee="mr-agent-x",
            depth=2,
            parent_delegation="d-agent1",
            region_scope=["EU"],
            purpose="test",
            expires_at="2026-08-20",   # d-agent1 expires in 7 days
        )


def test_subdelegation_requires_holding_the_parent():
    with pytest.raises(psycopg.errors.RaiseException, match="does not hold parent"):
        _insert(
            delegation_id="d-test-notparent",
            grant_id="g-main",
            delegator="mr-agent-x",    # does not hold d-agent1
            delegatee="mr-agent-2",
            depth=2,
            parent_delegation="d-agent1",
            region_scope=["EU"],
            purpose="test",
            expires_at="2026-08-02",
        )


def test_depth_must_increase_by_one_along_the_chain():
    with pytest.raises(psycopg.errors.RaiseException, match="exactly 1"):
        _insert(
            delegation_id="d-test-skip",
            grant_id="g-main",
            delegator="mr-agent-1",
            delegatee="mr-agent-x",
            depth=3,                   # parent is depth 1
            parent_delegation="d-agent1",
            region_scope=["EU"],
            purpose="test",
            expires_at="2026-08-02",
        )


def test_grants_cannot_be_issued_to_agents():
    """An agent must never hold standing authority of its own."""
    with admin_conn() as conn:
        with pytest.raises(psycopg.errors.RaiseException, match="grants are issued to humans"):
            conn.execute(
                """
                INSERT INTO portal.data_grant
                  (grant_id, provider_org, grantee_org, grantee_principal,
                   region_scope, max_classification, expires_at)
                VALUES ('g-test-agent','northwind','meridian','mr-agent-1',
                        ARRAY['EU'],'public', now() + interval '1 day')
                """
            )


def test_approval_requires_a_human_on_the_provider_side():
    with admin_conn() as conn:
        conn.execute(
            """
            INSERT INTO portal.data_grant
              (grant_id, provider_org, grantee_org, grantee_principal,
               region_scope, max_classification, expires_at)
            VALUES ('g-test-approve','northwind','meridian','mr-priya',
                    ARRAY['EU'],'public', now() + interval '1 day')
            ON CONFLICT (grant_id) DO NOTHING
            """
        )
        # the consuming org cannot approve its own access
        with pytest.raises(psycopg.errors.RaiseException, match="cannot approve"):
            conn.execute("SELECT portal.approve_grant('g-test-approve','mr-priya')")
        # nor can an agent
        with pytest.raises(psycopg.errors.RaiseException, match="must be a human"):
            conn.execute("SELECT portal.approve_grant('g-test-approve','mr-agent-1')")
        # the provider's human can
        conn.execute("SELECT portal.approve_grant('g-test-approve','nw-omar')")
        r = conn.execute(
            "SELECT approved_by FROM portal.data_grant WHERE grant_id='g-test-approve'"
        ).fetchone()
        assert r["approved_by"] == "nw-omar"
        conn.execute("DELETE FROM portal.data_grant WHERE grant_id='g-test-approve'")
