"""The attack suite: four families named in the spec, plus what they imply.

Every attack targets a *specific* piece of data it must not obtain. The targets
come from the seeded fixture:

* row 1004 — EU/restricted/meridian: above the grant's classification ceiling
* rows 1007-1009 — EU rows concerning **contoso**: another partner's data
* rows 1015-1019 — APAC: outside the grant's region scope
* row 3003 — owned by contoso: a different provider entirely
* ``unit_cost_usd``/``margin_pct`` on any row for a delegated agent — masked
* ``contact_email``/``contact_phone`` anywhere under g-main — masked
"""

from __future__ import annotations

from attacks.framework import Attack
from sharing import credentials
from sharing.db import admin_conn
from sharing.portal import ALL_COLUMNS, BASE_COLUMNS, Portal

# Data the attacker is after, straight from the fixture.
RESTRICTED_ROW = 1004
CONTOSO_ROWS = [1007, 1008, 1009, 1014, 1019]
APAC_ROWS = [1015, 1016, 1017, 1018, 1019]
OTHER_PROVIDER_ROWS = [3001, 3002, 3003, 2001, 2002]
OUT_OF_SCOPE = sorted(set([RESTRICTED_ROW, 1012] + CONTOSO_ROWS + APAC_ROWS + OTHER_PROVIDER_ROWS))

# Actual secret values that must never be served (checked as values, not rows,
# so a masked column that leaks is caught even when the row is legitimate).
COST_SECRETS = [
    (1001, "unit_cost_usd", "4.50"),
    (1002, "unit_cost_usd", "6.25"),
    (1001, "margin_pct", "12.50"),
]
CONTACT_SECRETS = [
    (1001, "contact_email", "ops1@meridian.example"),
    (1002, "contact_phone", "+49-30-2222"),
]


# The delegated agent legitimately sees exactly these 5 rows (EU, <=internal,
# meridian-or-unattributed). Aggregate attacks assert against this number.
AGENT_VISIBLE_ROWS = [1001, 1002, 1003, 1005, 1006]
AGENT_VISIBLE_COUNT = len(AGENT_VISIBLE_ROWS)


def _tok(sub, grant="g-main", dele=None, **kw):
    return credentials.mint(subject=sub, grant_id=grant, delegation_id=dele, **kw)


def _order_by_leaks(results) -> str | None:
    """A masked sort key must not influence the returned order.

    If ORDER BY on a masked column produces a different sequence than its
    reverse, the engine sorted on values the caller is not allowed to see, and
    the ordering itself discloses them.
    """
    if len(results) < 2:
        return None
    desc = [r["shipment_id"] for r in results[0].rows]
    asc = [r["shipment_id"] for r in results[1].rows]
    if not desc or not asc:
        return None
    if desc != asc:
        return (
            f"ORDER BY a masked column changed the row order "
            f"(desc={desc} vs asc={asc}), disclosing the hidden ranking"
        )
    return None


def _predicate_leaks(results) -> str | None:
    """A predicate over a masked column must not partition the result set.

    If different thresholds return different row sets, the caller can binary
    search each hidden value. Identical result sets across every threshold mean
    the predicate saw NULL and therefore learned nothing.
    """
    sets = [tuple(r.row_ids) for r in results]
    distinct = set(sets)
    if len(distinct) > 1:
        return (
            "a predicate over a masked column partitioned the results "
            f"({sorted(distinct)}), so each hidden value is binary-searchable"
        )
    return None


def _agg_check(results, *, allowed: set[int], what: str) -> str | None:
    """Assert an aggregate's value, since the leak here is a number not a row.

    The aggregate is aliased to ``shipment_id`` so it arrives through the same
    result plumbing; ``Result.row_ids`` therefore holds the aggregate value.
    """
    got = {v for r in results for v in r.row_ids}
    if not got:
        return None  # denied outright: no leak
    bad = got - allowed
    if bad:
        return f"{what} — got {sorted(got)}"
    return None


def _sql(query: str, params=None):
    """Run privileged SQL for attack setup/teardown."""
    with admin_conn() as c:
        c.execute(query, params)


# ===========================================================================
# FAMILY 1: FORGED IDENTITIES
# ===========================================================================
def family_forged() -> list[Attack]:
    good = _tok("mr-agent-1", dele="d-agent1")

    return [
        Attack(
            name="forge_subject_keep_signature",
            family="forged_identity",
            description=(
                "Take the agent's own valid credential and rewrite `sub` to the "
                "human analyst (who has a wider grant), keeping the original "
                "signature."
            ),
            run=lambda p: p.read_shipments(
                credentials.tamper(good, sub="mr-priya", delegation_id=None),
                columns=ALL_COLUMNS,
            ),
            forbidden_rows=OUT_OF_SCOPE,
            forbidden_values=COST_SECRETS + CONTACT_SECRETS,
            must_deny=True,
        ),
        Attack(
            name="forge_widen_grant_reference",
            family="forged_identity",
            description=(
                "Rewrite `grant_id` to the never-approved grant g-unapproved, "
                "which would allow APAC + restricted + all columns."
            ),
            run=lambda p: p.read_shipments(
                credentials.tamper(good, grant_id="g-unapproved"), columns=ALL_COLUMNS
            ),
            forbidden_rows=OUT_OF_SCOPE,
            forbidden_values=COST_SECRETS + CONTACT_SECRETS,
            must_deny=True,
        ),
        Attack(
            name="forge_extend_expiry",
            family="forged_identity",
            description="Rewrite `exp` far into the future on an expired credential.",
            run=lambda p: p.read_shipments(
                credentials.tamper(
                    credentials.mint(
                        subject="mr-agent-1", grant_id="g-main",
                        delegation_id="d-agent1", exp=1_000_000_000,
                    ),
                    exp=99_999_999_999,
                ),
                columns=BASE_COLUMNS,
            ),
            forbidden_rows=OUT_OF_SCOPE + [1001, 1002, 1003, 1005, 1006],
            must_deny=True,
        ),
        Attack(
            name="forge_wrong_signing_key",
            family="forged_identity",
            description=(
                "Mint a perfectly well-formed credential with an attacker-chosen "
                "key — the case where the attacker understands the format."
            ),
            run=lambda p: p.read_shipments(
                credentials.forge_with_wrong_key(
                    b"attacker-key",
                    subject="mr-priya", grant_id="g-unapproved",
                ),
                columns=ALL_COLUMNS,
            ),
            forbidden_rows=OUT_OF_SCOPE + [1001, 1002, 1003, 1005, 1006],
            forbidden_values=COST_SECRETS + CONTACT_SECRETS,
            must_deny=True,
        ),
        Attack(
            name="forge_unsigned_credential",
            family="forged_identity",
            description="Present bare claims with no signature at all.",
            run=lambda p: p.read_shipments(
                credentials._encode({"sub": "mr-priya", "grant_id": "g-main",
                                     "exp": 99_999_999_999}),
                columns=ALL_COLUMNS,
            ),
            forbidden_rows=OUT_OF_SCOPE + [1001],
            must_deny=True,
        ),
        Attack(
            name="forge_empty_credential",
            family="forged_identity",
            description="Present nothing. Must fail closed, not fail open.",
            run=lambda p: p.read_shipments("", columns=ALL_COLUMNS),
            forbidden_rows=OUT_OF_SCOPE + [1001],
            must_deny=True,
        ),
        Attack(
            name="forge_agent_holds_grant_directly",
            family="forged_identity",
            description=(
                "An agent presents a credential with no delegation, claiming the "
                "grant directly — the 'non-human identity with its own standing "
                "authority' anti-pattern."
            ),
            run=lambda p: p.read_shipments(
                _tok("mr-agent-1", dele=None), columns=ALL_COLUMNS
            ),
            forbidden_rows=OUT_OF_SCOPE + [1001, 1002, 1003, 1005, 1006],
            must_deny=True,
        ),
        Attack(
            name="forge_foreign_org_agent",
            family="forged_identity",
            description=(
                "Contoso's agent presents meridian's grant id — cross-partner "
                "credential confusion."
            ),
            run=lambda p: p.read_shipments(
                _tok("co-agent-1", grant="g-main", dele="d-agent1"),
                columns=ALL_COLUMNS,
            ),
            forbidden_rows=OUT_OF_SCOPE + [1001, 1002, 1003, 1005, 1006],
            must_deny=True,
        ),
    ]


# ===========================================================================
# FAMILY 2: EXPIRED / REVOKED GRANTS
# ===========================================================================
def family_expiry() -> list[Attack]:
    attacks = []

    attacks.append(
        Attack(
            name="expired_grant",
            family="expired_or_revoked",
            description=(
                "g-short expires 2 seconds after seeding; wait it out and read. "
                "The credential itself is freshly minted and validly signed, so "
                "only the *grant's* expiry can stop this."
            ),
            setup=lambda: _sql(
                "UPDATE portal.data_grant SET expires_at = now() - interval '1 second' "
                "WHERE grant_id = 'g-short'"
            ),
            run=lambda p: p.read_shipments(
                _tok("mr-tomas", grant="g-short"), columns=BASE_COLUMNS
            ),
            forbidden_rows=OUT_OF_SCOPE + [1001, 1005],
            must_deny=True,
        )
    )

    attacks.append(
        Attack(
            name="unapproved_grant",
            family="expired_or_revoked",
            description=(
                "Read under a grant that was requested but never approved by the "
                "provider. Approval is the human control; skipping it must not work."
            ),
            run=lambda p: p.read_shipments(
                _tok("mr-priya", grant="g-unapproved"), columns=ALL_COLUMNS
            ),
            forbidden_rows=OUT_OF_SCOPE + [1001],
            must_deny=True,
        )
    )

    attacks.append(
        Attack(
            name="revoked_grant_valid_credential",
            family="expired_or_revoked",
            description=(
                "The killer case for token-only systems: revoke the grant, then "
                "present a credential minted BEFORE the revocation that is still "
                "within its TTL. Nothing about the token is wrong."
            ),
            setup=lambda: _sql(
                "SELECT portal.revoke_grant('g-main','nw-dana','attack: revoked mid-flight')"
            ),
            teardown=lambda: _sql(
                "UPDATE portal.data_grant SET revoked_at=NULL, revoked_reason=NULL "
                "WHERE grant_id='g-main'"
            ),
            run=lambda p: p.read_shipments(
                _tok("mr-agent-1", dele="d-agent1"), columns=ALL_COLUMNS
            ),
            forbidden_rows=OUT_OF_SCOPE + [1001, 1002, 1003, 1005, 1006],
            must_deny=True,
        )
    )

    attacks.append(
        Attack(
            name="revoked_delegation_valid_credential",
            family="expired_or_revoked",
            description="Same, but revoking the delegation rather than the grant.",
            setup=lambda: _sql(
                "SELECT portal.revoke_delegation('d-agent1','mr-priya','attack')"
            ),
            teardown=lambda: _sql(
                "UPDATE portal.delegation SET revoked_at=NULL, revoked_reason=NULL "
                "WHERE delegation_id='d-agent1'"
            ),
            run=lambda p: p.read_shipments(
                _tok("mr-agent-1", dele="d-agent1"), columns=ALL_COLUMNS
            ),
            forbidden_rows=OUT_OF_SCOPE + [1001, 1002, 1003, 1005, 1006],
            must_deny=True,
        )
    )

    attacks.append(
        Attack(
            name="disabled_principal",
            family="expired_or_revoked",
            description=(
                "The human analyst leaves the company (principal disabled). Their "
                "agent's delegation is untouched and its credential is valid — "
                "the classic orphaned-agent case."
            ),
            setup=lambda: _sql(
                "UPDATE portal.principal SET disabled_at = now() WHERE principal_id='mr-priya'"
            ),
            teardown=lambda: _sql(
                "UPDATE portal.principal SET disabled_at = NULL WHERE principal_id='mr-priya'"
            ),
            run=lambda p: p.read_shipments(
                _tok("mr-agent-1", dele="d-agent1"), columns=ALL_COLUMNS
            ),
            forbidden_rows=OUT_OF_SCOPE + [1001, 1002, 1003, 1005, 1006],
            must_deny=True,
        )
    )

    return attacks


# ===========================================================================
# FAMILY 3: DELEGATION-CHAIN ABUSE
# ===========================================================================
def family_delegation() -> list[Attack]:
    attacks = []

    attacks.append(
        Attack(
            name="delegation_widen_at_creation",
            family="delegation_chain",
            description=(
                "Try to CREATE a delegation wider than the grant (APAC, cost "
                "columns). Must be refused by the database, not merely ignored "
                "at read time."
            ),
            run=lambda p: _attempt_widen_delegation(p),
            forbidden_rows=APAC_ROWS,
            forbidden_values=COST_SECRETS,
            must_deny=True,
        )
    )

    attacks.append(
        Attack(
            name="subdelegation_widen_beyond_parent",
            family="delegation_chain",
            description=(
                "The agent sub-delegates to a second agent with MORE scope than "
                "it holds itself — privilege escalation down the chain."
            ),
            run=lambda p: _attempt_widen_subdelegation(p),
            forbidden_rows=APAC_ROWS + [RESTRICTED_ROW],
            forbidden_values=COST_SECRETS,
            must_deny=True,
        )
    )

    attacks.append(
        Attack(
            name="orphan_chain_mid_revocation",
            family="delegation_chain",
            description=(
                "Revoke the MIDDLE of a 2-hop chain and use the deepest "
                "credential. The leaf delegation row is untouched and unexpired, "
                "so only walking the chain to its root can catch this."
            ),
            setup=lambda: _sql(
                "SELECT portal.revoke_delegation('d-agent1','mr-priya','attack: mid-chain')"
            ),
            teardown=lambda: _sql(
                "UPDATE portal.delegation SET revoked_at=NULL WHERE delegation_id='d-agent1'"
            ),
            run=lambda p: p.read_shipments(
                _tok("mr-agent-2", dele="d-agent2"), columns=ALL_COLUMNS
            ),
            forbidden_rows=OUT_OF_SCOPE + [1001, 1002, 1003, 1005, 1006],
            must_deny=True,
        )
    )

    attacks.append(
        Attack(
            name="expired_parent_live_child",
            family="delegation_chain",
            description=(
                "Expire the parent delegation while the child's own expiry is "
                "still in the future."
            ),
            setup=lambda: _sql(
                "UPDATE portal.delegation SET expires_at = now() - interval '1 minute' "
                "WHERE delegation_id='d-agent1'"
            ),
            teardown=lambda: _sql(
                "UPDATE portal.delegation SET expires_at = now() + interval '7 days' "
                "WHERE delegation_id='d-agent1'"
            ),
            run=lambda p: p.read_shipments(
                _tok("mr-agent-2", dele="d-agent2"), columns=ALL_COLUMNS
            ),
            forbidden_rows=OUT_OF_SCOPE + [1001, 1002, 1003, 1005, 1006],
            must_deny=True,
        )
    )

    attacks.append(
        Attack(
            name="delegation_credential_swap",
            family="delegation_chain",
            description=(
                "An agent presents someone else's delegation id — one it is not "
                "the delegatee of."
            ),
            run=lambda p: p.read_shipments(
                _tok("mr-agent-x", dele="d-agent1"), columns=ALL_COLUMNS
            ),
            forbidden_rows=OUT_OF_SCOPE + [1001, 1002, 1003, 1005, 1006],
            must_deny=True,
        )
    )

    attacks.append(
        Attack(
            name="unauthorized_agent_self_delegation",
            family="delegation_chain",
            description=(
                "An agent belonging to a different analyst creates its own "
                "delegation under a grant it does not hold."
            ),
            run=lambda p: _attempt_self_delegation(p),
            forbidden_rows=OUT_OF_SCOPE + [1001, 1002, 1003, 1005, 1006],
            must_deny=True,
        )
    )

    attacks.append(
        Attack(
            name="delegation_outlives_grant",
            family="delegation_chain",
            description=(
                "Create a delegation whose expiry is after the grant's, so the "
                "agent would outlive the share it depends on."
            ),
            run=lambda p: _attempt_long_delegation(p),
            forbidden_rows=OUT_OF_SCOPE,
            must_deny=True,
        )
    )

    return attacks


def _attempt_widen_delegation(p: Portal):
    """Create a wider-than-grant delegation, then try to use it."""
    from attacks.framework import Attack  # noqa: F401  (local import for clarity)

    created = False
    try:
        _sql(
            """
            INSERT INTO portal.delegation
              (delegation_id, grant_id, delegator, delegatee, depth, region_scope,
               allow_cost, allow_contact, purpose, expires_at)
            VALUES ('d-attack-wide','g-main','mr-priya','mr-agent-x',1,
                    ARRAY['EU','UK','APAC'], true, true, 'attack',
                    now() + interval '1 day')
            """
        )
        created = True
    except Exception:
        # The database refused the widening outright: the desired outcome.
        pass

    if not created:
        return p.read_shipments(_tok("mr-agent-x", dele="d-attack-wide"),
                                columns=ALL_COLUMNS)
    try:
        return p.read_shipments(_tok("mr-agent-x", dele="d-attack-wide"),
                                columns=ALL_COLUMNS)
    finally:
        _sql("DELETE FROM portal.delegation WHERE delegation_id='d-attack-wide'")


def _attempt_widen_subdelegation(p: Portal):
    created = False
    try:
        _sql(
            """
            INSERT INTO portal.delegation
              (delegation_id, grant_id, delegator, delegatee, depth,
               parent_delegation, region_scope, allow_cost, allow_contact,
               purpose, expires_at)
            VALUES ('d-attack-sub','g-main','mr-agent-1','mr-agent-x',2,'d-agent1',
                    ARRAY['EU','UK'], true, true, 'attack',
                    now() + interval '1 day')
            """
        )
        created = True
    except Exception:
        pass
    try:
        return p.read_shipments(_tok("mr-agent-x", dele="d-attack-sub"),
                                columns=ALL_COLUMNS)
    finally:
        if created:
            _sql("DELETE FROM portal.delegation WHERE delegation_id='d-attack-sub'")


def _attempt_self_delegation(p: Portal):
    created = False
    try:
        _sql(
            """
            INSERT INTO portal.delegation
              (delegation_id, grant_id, delegator, delegatee, depth, region_scope,
               allow_cost, allow_contact, purpose, expires_at)
            VALUES ('d-attack-self','g-main','mr-tomas','mr-agent-x',1,
                    ARRAY['EU'], false, false, 'attack', now() + interval '1 day')
            """
        )
        created = True
    except Exception:
        pass
    try:
        return p.read_shipments(_tok("mr-agent-x", dele="d-attack-self"),
                                columns=ALL_COLUMNS)
    finally:
        if created:
            _sql("DELETE FROM portal.delegation WHERE delegation_id='d-attack-self'")


def _attempt_long_delegation(p: Portal):
    created = False
    try:
        _sql(
            """
            INSERT INTO portal.delegation
              (delegation_id, grant_id, delegator, delegatee, depth, region_scope,
               allow_cost, allow_contact, purpose, expires_at)
            VALUES ('d-attack-long','g-main','mr-priya','mr-agent-x',1,
                    ARRAY['EU'], false, false, 'attack', now() + interval '999 days')
            """
        )
        created = True
    except Exception:
        pass
    try:
        return p.read_shipments(_tok("mr-agent-x", dele="d-attack-long"),
                                columns=ALL_COLUMNS)
    finally:
        if created:
            _sql("DELETE FROM portal.delegation WHERE delegation_id='d-attack-long'")


# ===========================================================================
# FAMILY 4: JOIN AND AGGREGATE SIDE CHANNELS
# ===========================================================================
# These are the interesting ones. The credential is entirely legitimate; the
# attacker uses the *query* to learn about rows the policy hides. This is where
# application-level filtering and database enforcement genuinely differ.
def family_side_channels() -> list[Attack]:
    agent = _tok("mr-agent-1", dele="d-agent1")
    human = _tok("mr-priya")

    return [
        Attack(
            name="predicate_probe_hidden_row",
            family="side_channel",
            description=(
                "Ask for a specific out-of-scope row by id. The answer must be "
                "'no rows', indistinguishable from 'does not exist'."
            ),
            run=lambda p: p.read_shipments(
                agent, columns=BASE_COLUMNS, where="shipment_id = %s",
                params=(RESTRICTED_ROW,),
            ),
            forbidden_rows=[RESTRICTED_ROW],
        ),
        Attack(
            name="aggregate_count_all",
            family="side_channel",
            description=(
                "COUNT(*) through the shared view. Must count only the 5 rows "
                "this agent may see, not the base table's 24."
            ),
            run=lambda p: p.read_shipments(agent, aggregate="count(*) AS shipment_id"),
            custom_check=lambda rs: _agg_check(
                rs, allowed={AGENT_VISIBLE_COUNT},
                what=f"count(*) must be {AGENT_VISIBLE_COUNT} (visible rows only)",
            ),
        ),
        Attack(
            name="aggregate_sum_masked_column",
            family="side_channel",
            description=(
                "SUM a column the grant masks. If masking happened after "
                "aggregation, the total would leak the hidden values."
            ),
            run=lambda p: p.read_shipments(
                agent, aggregate="coalesce(sum(unit_cost_usd),0)::bigint AS shipment_id"
            ),
            # The real sum of unit_cost_usd over this agent's 5 visible rows is
            # 4.50+6.25+11.00+2.10+3.75 = 27.60 -> 27/28 as bigint. Masked, it
            # must be 0. Anything else means the aggregate saw the values.
            custom_check=lambda rs: _agg_check(
                rs, allowed={0},
                what="sum(masked column) must be 0, not the true total (~27)",
            ),
        ),
        Attack(
            name="aggregate_min_max_probe",
            family="side_channel",
            description=(
                "MAX over a masked column to recover an individual value without "
                "selecting it. True max margin_pct over visible rows is 22.50."
            ),
            run=lambda p: p.read_shipments(
                agent, aggregate="coalesce(max(margin_pct),0)::bigint AS shipment_id"
            ),
            custom_check=lambda rs: _agg_check(
                rs, allowed={0},
                what="max(masked column) must be 0, not the true max (22)",
            ),
        ),
        Attack(
            name="self_join_across_boundary",
            family="side_channel",
            description=(
                "Join the shared view to the BASE table, hoping the base table is "
                "reachable and unfiltered. Under RLS the app role has no "
                "privilege on it at all."
            ),
            run=lambda p: p.read_shipments(
                agent,
                columns=BASE_COLUMNS,
                where=(
                    "shipment_id IN (SELECT shipment_id FROM portal.shipment "
                    f"WHERE shipment_id = {RESTRICTED_ROW})"
                ),
            ),
            forbidden_rows=[RESTRICTED_ROW],
        ),
        Attack(
            name="exists_subquery_oracle",
            family="side_channel",
            description=(
                "Use a hidden row inside an EXISTS predicate as a boolean oracle: "
                "the row itself is never selected, only its existence leaks."
            ),
            run=lambda p: p.read_shipments(
                agent,
                columns=BASE_COLUMNS,
                where=(
                    "EXISTS (SELECT 1 FROM portal.shared_shipment x "
                    f"WHERE x.shipment_id = {RESTRICTED_ROW})"
                ),
            ),
            forbidden_rows=[RESTRICTED_ROW] + [1001, 1002, 1003, 1005, 1006],
        ),
        Attack(
            name="order_by_masked_column",
            family="side_channel",
            description=(
                "ORDER BY a masked column. Values are NULL in the projection, but "
                "if the sort sees the real column the returned ORDER still encodes "
                "them. Bypass condition: DESC and ASC produce different orders, "
                "i.e. the sort key was visible to the engine."
            ),
            run=lambda p: [
                p.read_shipments(agent, columns=["shipment_id"],
                                 order_by="unit_cost_usd DESC"),
                p.read_shipments(agent, columns=["shipment_id"],
                                 order_by="unit_cost_usd ASC"),
            ],
            custom_check=_order_by_leaks,
        ),
        Attack(
            name="cross_partner_row_probe",
            family="side_channel",
            description=(
                "The human grantee probes for another partner's rows by id — "
                "in scope by region and classification, but not theirs."
            ),
            run=lambda p: p.read_shipments(
                human, columns=ALL_COLUMNS,
                where="shipment_id = ANY(%s)", params=([1007, 1008, 1014],),
            ),
            forbidden_rows=[1007, 1008, 1014],
            forbidden_values=[(1007, "carrier", "DHL")],
        ),
        Attack(
            name="other_provider_data",
            family="side_channel",
            description=(
                "Reach rows owned by a third provider org (contoso) under a "
                "northwind grant."
            ),
            run=lambda p: p.read_shipments(
                human, columns=ALL_COLUMNS,
                where="owner_org <> %s", params=("northwind",),
            ),
            forbidden_rows=OTHER_PROVIDER_ROWS,
        ),
        Attack(
            name="masked_column_in_predicate",
            family="side_channel",
            description=(
                "Filter on a masked column's value. If the predicate sees the "
                "real value while the projection masks it, the filter result "
                "leaks the value bit by bit."
            ),
            run=lambda p: [
                p.read_shipments(
                    agent, columns=["shipment_id"],
                    where="unit_cost_usd > %s", params=(threshold,),
                )
                for threshold in (0, 3, 5, 10, 100)
            ],
            custom_check=_predicate_leaks,
        ),
    ]


# Where masking happens decides whether these channels exist at all, and the
# measured answer differed from the initial expectation — so both notes state
# what was observed rather than what seemed likely.
ORDER_BY_NOTE = (
    "ORDER BY on a masked column is inert in the RLS arm and live in the "
    "appfilter arm. Masking in the RLS arm is a CASE in the view's target list, "
    "so the caller's ORDER BY sorts the already-NULL output and DESC/ASC return "
    "identical orders. The appfilter arm sorts in the database and masks in "
    "Python afterwards, so the row order still ranks rows by the hidden value. "
    "Measured in results/side_channel_analysis.md."
)

MASKED_PREDICATE_NOTE = (
    "A predicate over a masked column is likewise inert under RLS and live under "
    "appfilter. `unit_cost_usd > 5` against the guarded view compares NULL and "
    "matches nothing for every threshold; against the appfilter arm it partitions "
    "the rows, making each hidden value binary-searchable. Measured in "
    "results/side_channel_analysis.md."
)


def all_attacks() -> list[Attack]:
    return (
        family_forged()
        + family_expiry()
        + family_delegation()
        + family_side_channels()
    )
