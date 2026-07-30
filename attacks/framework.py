"""The adversarial harness.

An attack declares what it must NOT achieve, in terms of concrete data:

* ``forbidden_rows`` — shipment ids the attacker must not receive
* ``forbidden_values`` — (row, column, value) triples that must not appear
* ``must_deny`` — the request must be refused outright

An attack **fails** (i.e. a bypass is found) if any forbidden row or value comes
back. That is a claim about served bytes, not about error strings: an attack that
returns HTTP-200-with-the-data while logging a scary message still counts as a
bypass.

Two design decisions worth stating, both learned the hard way:

1. **A denial is not automatically a pass.** An attack whose request errors for
   an unrelated reason (a typo, a missing column) would "pass" while testing
   nothing, and a portal that refuses everything would pass the entire suite.
   ``positive_control.py`` is the counterweight: legitimate requests that must
   return *exactly* the approved rows and columns, checked against an oracle
   derived independently of the views. Both halves have to hold.
2. **The suite reports what it did not test.** Zero bypasses over an untested
   surface is not a security result. ``UNTESTED_SURFACES`` is printed with the
   results, and the metadata side channel found in probing is listed there.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sharing.portal import Portal, Result

# Surfaces this suite does NOT cover, stated so the headline number cannot be
# read as broader than it is.
UNTESTED_SURFACES = [
    "Base-table CARDINALITY via catalog metadata. pg_class.reltuples reports the "
    "true total row count to any role that can read the catalog, including one "
    "with no privilege on the table itself (probe Q8, reproduced by "
    "attacks/metadata_cardinality.py). RLS protects row contents, not the size "
    "of the relation. Accepted and documented rather than counted as held.",
    "Timing side channels. Row-count-dependent query latency is not measured; "
    "a determined attacker could infer cardinality from response time.",
    "Physical/backup access, log files, and replica access. Out of scope.",
    "Denial of service. An authorized partner can issue expensive queries.",
]


@dataclass
class Attack:
    """One adversarial attempt."""

    name: str
    family: str
    description: str
    run: Callable[[Portal], Result | list[Result]]
    forbidden_rows: list[int] = field(default_factory=list)
    forbidden_values: list[tuple[int, str, Any]] = field(default_factory=list)
    must_deny: bool = False
    # Some attacks need setup/teardown against the database.
    setup: Callable[[], None] | None = None
    teardown: Callable[[], None] | None = None
    # For attacks whose bypass condition is not expressible as rows or values —
    # aggregates, for instance, where the leak is a NUMBER rather than a row.
    # Returns a reason string if the attack succeeded, else None.
    custom_check: Callable[[list[Result]], str | None] | None = None


@dataclass
class Outcome:
    attack: Attack
    bypassed: bool
    detail: str
    leaked_rows: list[int] = field(default_factory=list)
    leaked_values: list[tuple] = field(default_factory=list)
    decision: str = ""
    elapsed_ms: float = 0.0
    audit_seqs: list[int] = field(default_factory=list)


def evaluate(attack: Attack, portal: Portal) -> Outcome:
    """Run one attack and decide whether it bypassed the controls."""
    t0 = time.perf_counter()
    if attack.setup:
        attack.setup()
    try:
        raw = attack.run(portal)
    except Exception as exc:  # an attack that crashes the server is a finding
        return Outcome(
            attack=attack,
            bypassed=False,
            detail=f"raised {type(exc).__name__}: {exc}",
            decision="error",
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )
    finally:
        if attack.teardown:
            attack.teardown()

    results = raw if isinstance(raw, list) else [raw]
    all_rows: set[int] = set()
    all_values: set[tuple] = set()
    decisions = []
    seqs = []
    for r in results:
        all_rows |= set(r.row_ids)
        all_values |= r.visible_values()
        decisions.append(r.decision)
        if r.audit_seq is not None:
            seqs.append(r.audit_seq)

    leaked_rows = sorted(all_rows & set(attack.forbidden_rows))
    leaked_values = sorted(
        v for v in attack.forbidden_values
        if (v[0], v[1], str(v[2])) in all_values
    )

    bypassed = bool(leaked_rows or leaked_values)
    detail_parts = []
    if leaked_rows:
        detail_parts.append(f"served forbidden rows {leaked_rows}")
    if leaked_values:
        detail_parts.append(f"served forbidden values {leaked_values}")

    if attack.custom_check is not None:
        reason = attack.custom_check(results)
        if reason:
            bypassed = True
            detail_parts.append(reason)

    # must_deny attacks are additionally required to be refused, not merely to
    # return nothing: a silent empty result and an explicit denial are different
    # products for an operator reading the audit trail.
    if attack.must_deny and not bypassed and any(d == "allow" for d in decisions):
        bypassed = True
        detail_parts.append(
            f"request was ALLOWED (decisions={decisions}) when it must be denied"
        )

    if not detail_parts:
        detail_parts.append(f"held (decisions={decisions}, rows={sorted(all_rows)})")

    return Outcome(
        attack=attack,
        bypassed=bypassed,
        detail="; ".join(detail_parts),
        leaked_rows=leaked_rows,
        leaked_values=[tuple(v) for v in leaked_values],
        decision=",".join(decisions),
        elapsed_ms=(time.perf_counter() - t0) * 1000,
        audit_seqs=seqs,
    )
