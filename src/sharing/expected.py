"""The independent oracle: what SHOULD a given credential see?

This module deliberately does not query the views, the policies, or
``current_auth()``. It re-derives the answer from the raw fixture rows and the
raw grant/delegation rows, in Python, from the rules as written in prose.

That independence is the whole value. A test that asks the system what it
returned and then asserts the system returned it proves nothing. A test that
compares the system against a separately-derived answer can fail — and
therefore can pass meaningfully. It catches over-blocking (a policy so strict it
serves nothing, which no attack test would notice) as well as under-blocking.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

CLASS_RANK = {"public": 1, "internal": 2, "restricted": 3}

COST_COLUMNS = ("unit_cost_usd", "margin_pct")
CONTACT_COLUMNS = ("contact_email", "contact_phone")


@dataclass
class Expectation:
    row_ids: list[int]
    visible_columns: set[str]
    masked_columns: set[str]


def _fetch_all(conn) -> tuple[list[dict], dict[str, dict], dict[str, dict], dict[str, dict]]:
    """Read the raw fixture with the superuser connection, bypassing the views.

    The connection must be the bootstrap superuser, which holds BYPASSRLS. It
    cannot be ``portal_owner``: ``shipment`` is FORCE ROW LEVEL SECURITY, so the
    owner is bound by the policy too, and ``SET row_security = off`` is refused
    for a role that cannot bypass ("query would be affected by row-level security
    policy"). Reading ground truth therefore requires a genuinely privileged
    identity — which is itself evidence the policy has no owner-shaped hole.
    """
    with conn.transaction():
        ships = conn.execute("SELECT * FROM portal.shipment").fetchall()
        grants = {g["grant_id"]: g for g in conn.execute(
            "SELECT * FROM portal.data_grant").fetchall()}
        delegs = {d["delegation_id"]: d for d in conn.execute(
            "SELECT * FROM portal.delegation").fetchall()}
        prins = {p["principal_id"]: p for p in conn.execute(
            "SELECT * FROM portal.principal").fetchall()}
    return ships, grants, delegs, prins


def expect_for(
    conn,
    *,
    subject: str,
    grant_id: str,
    delegation_id: str | None,
    requested_columns: list[str],
    now: Any = None,
) -> Expectation | None:
    """Derive the correct answer, or ``None`` if the request must be denied.

    The rules, stated once, in prose, and implemented directly below:

    * the grant must be approved, unrevoked and unexpired;
    * a direct (non-delegated) request must come from the grant's own grantee;
    * a delegated request must come from the delegation's delegatee, the whole
      chain must be alive, and the effective scope is the *intersection* of the
      grant and every hop;
    * rows must be owned by the provider org, inside the effective regions, at or
      below the classification ceiling, and either unattributed or concerning the
      grantee org;
    * cost/contact columns are visible only if every hop and the grant allow them.
    """
    ships, grants, delegs, prins = _fetch_all(conn)
    g = grants.get(grant_id)
    if g is None:
        return None
    now = now or _now(conn)

    if g["approved_at"] is None or g["revoked_at"] is not None or g["expires_at"] <= now:
        return None

    if delegation_id is None:
        if subject != g["grantee_principal"]:
            return None
        if prins.get(subject, {}).get("disabled_at") is not None:
            return None
        regions = set(g["region_scope"])
        allow_cost = g["allow_cost"]
        allow_contact = g["allow_contact"]
    else:
        d = delegs.get(delegation_id)
        if d is None or d["grant_id"] != grant_id or d["delegatee"] != subject:
            return None
        # walk the chain to the root; any dead hop kills it
        regions = set(d["region_scope"])
        allow_cost, allow_contact = d["allow_cost"], d["allow_contact"]
        hop, seen = d, 0
        while True:
            if hop["revoked_at"] is not None or hop["expires_at"] <= now:
                return None
            if prins.get(hop["delegatee"], {}).get("disabled_at") is not None:
                return None
            if hop["parent_delegation"] is None:
                break
            seen += 1
            if seen > 8:
                return None
            hop = delegs.get(hop["parent_delegation"])
            if hop is None or hop["grant_id"] != grant_id:
                return None
            regions &= set(hop["region_scope"])
            allow_cost = allow_cost and hop["allow_cost"]
            allow_contact = allow_contact and hop["allow_contact"]
        if hop["delegator"] != g["grantee_principal"] or hop["depth"] != 1:
            return None
        if prins.get(g["grantee_principal"], {}).get("disabled_at") is not None:
            return None
        regions &= set(g["region_scope"])
        allow_cost = allow_cost and g["allow_cost"]
        allow_contact = allow_contact and g["allow_contact"]

    ceiling = CLASS_RANK[g["max_classification"]]
    row_ids = sorted(
        s["shipment_id"]
        for s in ships
        if s["owner_org"] == g["provider_org"]
        and s["region"] in regions
        and CLASS_RANK[s["classification"]] <= ceiling
        and (s["partner_org"] is None or s["partner_org"] == g["grantee_org"])
    )

    masked = set()
    if not allow_cost:
        masked |= {c for c in requested_columns if c in COST_COLUMNS}
    if not allow_contact:
        masked |= {c for c in requested_columns if c in CONTACT_COLUMNS}
    visible = set(requested_columns) - masked
    return Expectation(row_ids=row_ids, visible_columns=visible, masked_columns=masked)


def _now(conn):
    with conn.transaction():
        return conn.execute("SELECT now() AS n").fetchone()["n"]
