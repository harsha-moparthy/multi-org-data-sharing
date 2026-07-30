"""The positive control: legitimate requests that MUST succeed exactly.

Without this, the adversarial suite is trivially passable. A portal that returns
zero rows to everybody scores zero bypasses and is also completely useless. The
spec's requirement is "exactly the approved rows/columns" — both halves.

Every case here compares the portal against ``sharing.expected``, which derives
the answer from the raw fixture independently of the views, the policies, and
``current_auth()``. So this can fail in both directions: too few rows
(over-blocking) and too many (a bypass).
"""

from __future__ import annotations

from dataclasses import dataclass

from sharing import credentials
from sharing.db import admin_conn
from sharing.expected import expect_for
from sharing.portal import ALL_COLUMNS, Portal


@dataclass
class ControlCase:
    name: str
    description: str
    subject: str
    grant_id: str
    delegation_id: str | None
    columns: list[str]


CASES = [
    ControlCase(
        name="human_grantee_full_scope",
        description=(
            "The analyst who holds the grant reads everything the grant allows: "
            "8 rows across EU+UK at or below 'internal', cost visible, contact "
            "masked."
        ),
        subject="mr-priya",
        grant_id="g-main",
        delegation_id=None,
        columns=ALL_COLUMNS,
    ),
    ControlCase(
        name="delegated_agent_narrowed",
        description=(
            "The analyst's agent reads under a delegation narrowed to EU with no "
            "cost columns: strictly less than its delegator, and that is correct."
        ),
        subject="mr-agent-1",
        grant_id="g-main",
        delegation_id="d-agent1",
        columns=ALL_COLUMNS,
    ),
    ControlCase(
        name="subdelegated_agent_depth2",
        description="A depth-2 sub-agent inherits the intersection of both hops.",
        subject="mr-agent-2",
        grant_id="g-main",
        delegation_id="d-agent2",
        columns=ALL_COLUMNS,
    ),
    ControlCase(
        name="other_partner_wider_grant",
        description=(
            "The OTHER partner's analyst has a wider grant (all regions, "
            "restricted, all columns) and must receive all of it — proving the "
            "portal is not simply strict with everyone."
        ),
        subject="co-lena",
        grant_id="g-contoso",
        delegation_id=None,
        columns=ALL_COLUMNS,
    ),
    ControlCase(
        name="base_columns_only",
        description="A request for a subset of columns returns exactly that subset.",
        subject="mr-priya",
        grant_id="g-main",
        delegation_id=None,
        columns=["shipment_id", "region", "carrier", "status"],
    ),
]


@dataclass
class ControlOutcome:
    case: ControlCase
    passed: bool
    detail: str
    got_rows: list[int]
    want_rows: list[int]


def run_controls(portal: Portal) -> list[ControlOutcome]:
    out = []
    for case in CASES:
        tok = credentials.mint(
            subject=case.subject,
            grant_id=case.grant_id,
            delegation_id=case.delegation_id,
        )
        res = portal.read_shipments(tok, columns=case.columns)
        with admin_conn() as conn:
            exp = expect_for(
                conn,
                subject=case.subject,
                grant_id=case.grant_id,
                delegation_id=case.delegation_id,
                requested_columns=case.columns,
            )

        problems = []
        if exp is None:
            problems.append("oracle says this request should be denied")
            want: list[int] = []
        else:
            want = exp.row_ids
            if res.decision != "allow":
                problems.append(f"legitimate request was {res.decision}: {res.deny_reason}")
            if res.row_ids != want:
                missing = sorted(set(want) - set(res.row_ids))
                extra = sorted(set(res.row_ids) - set(want))
                if missing:
                    problems.append(f"OVER-BLOCKED, missing rows {missing}")
                if extra:
                    problems.append(f"LEAKED extra rows {extra}")
            if sorted(res.columns_masked) != sorted(exp.masked_columns):
                problems.append(
                    f"masking mismatch: got {sorted(res.columns_masked)} "
                    f"want {sorted(exp.masked_columns)}"
                )
            # Every column that should be visible must actually carry data in at
            # least one row: a column masked by accident is over-blocking too.
            for col in exp.visible_columns:
                if col in ("partner_org", "contact_email", "contact_phone"):
                    continue  # legitimately NULL in some fixture rows
                if res.rows and all(r.get(col) is None for r in res.rows):
                    problems.append(f"column {col} should be visible but is all-NULL")

        out.append(
            ControlOutcome(
                case=case,
                passed=not problems,
                detail="; ".join(problems) or f"exact match ({len(res.row_ids)} rows)",
                got_rows=res.row_ids,
                want_rows=want,
            )
        )
    return out
