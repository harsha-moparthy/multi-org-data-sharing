"""Run the adversarial suite against both arms and write the report.

    python -m attacks.run_suite --arm rls
    python -m attacks.run_suite --arm appfilter
    python -m attacks.run_suite --both        # the comparison

The report is written to ``results/`` and is the source of every attack-related
number in the README.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from attacks.framework import UNTESTED_SURFACES, Outcome, evaluate
from attacks.positive_control import run_controls
from attacks.suite import MASKED_PREDICATE_NOTE, ORDER_BY_NOTE, all_attacks
from sharing.db import admin_conn, close_pool, init_schema
from sharing.portal import Portal

RESULTS = Path(__file__).resolve().parents[1] / "results"


def run_arm(arm: str, *, reseed: bool = True) -> dict:
    if reseed:
        init_schema()
    portal = Portal(arm)  # type: ignore[arg-type]

    controls = run_controls(portal)
    outcomes: list[Outcome] = [evaluate(a, portal) for a in all_attacks()]

    # Audit integrity after the whole run: every attack, allowed or denied, must
    # have left an intact trail.
    with admin_conn() as conn:
        chain = conn.execute("SELECT * FROM portal.audit_verify()").fetchone()
        events = conn.execute(
            "SELECT count(*) AS n, count(*) FILTER (WHERE decision='deny') AS denies,"
            " count(*) FILTER (WHERE subject IS NULL) AS unattributed"
            " FROM portal.audit_event"
        ).fetchone()

    by_family: dict[str, dict[str, int]] = {}
    for o in outcomes:
        f = by_family.setdefault(o.attack.family, {"total": 0, "bypassed": 0})
        f["total"] += 1
        f["bypassed"] += int(o.bypassed)

    return {
        "arm": arm,
        "attacks_total": len(outcomes),
        "attacks_bypassed": sum(o.bypassed for o in outcomes),
        "by_family": by_family,
        "controls_total": len(controls),
        "controls_passed": sum(c.passed for c in controls),
        "audit_events": events["n"],
        "audit_denies": events["denies"],
        "audit_unattributed": events["unattributed"],
        "audit_chain_checked": chain["checked"],
        "audit_chain_first_bad": chain["first_bad_seq"],
        "outcomes": [
            {
                "name": o.attack.name,
                "family": o.attack.family,
                "description": o.attack.description,
                "bypassed": o.bypassed,
                "detail": o.detail,
                "decision": o.decision,
                "leaked_rows": o.leaked_rows,
                "audit_seqs": o.audit_seqs,
            }
            for o in outcomes
        ],
        "controls": [
            {
                "name": c.case.name,
                "description": c.case.description,
                "passed": c.passed,
                "detail": c.detail,
                "got_rows": c.got_rows,
                "want_rows": c.want_rows,
            }
            for c in controls
        ],
    }


def chain_state(report: dict) -> str:
    bad = report["audit_chain_first_bad"]
    return "INTACT" if bad is None else f"BROKEN at {bad}"


def render(report: dict) -> str:
    lines = []
    a = report["arm"]
    lines.append(f"=== ARM: {a} ===")
    lines.append("")
    lines.append(
        f"attacks: {report['attacks_total']}  bypasses: {report['attacks_bypassed']}"
    )
    lines.append(
        f"positive controls: {report['controls_passed']}/{report['controls_total']} passed"
    )
    lines.append(
        f"audit: {report['audit_events']} events, {report['audit_denies']} denials, "
        f"{report['audit_unattributed']} unattributed; chain "
        f"{chain_state(report)}"
        f" over {report['audit_chain_checked']} rows"
    )
    lines.append("")
    lines.append("-- by family --")
    for fam, s in sorted(report["by_family"].items()):
        flag = "" if s["bypassed"] == 0 else f"   <-- {s['bypassed']} BYPASSED"
        lines.append(f"  {fam:20} {s['total'] - s['bypassed']}/{s['total']} held{flag}")
    lines.append("")
    lines.append("-- attacks --")
    for o in report["outcomes"]:
        mark = "BYPASS" if o["bypassed"] else "held  "
        lines.append(f"  [{mark}] {o['name']:38} {o['detail']}")
    lines.append("")
    lines.append("-- positive controls (must all pass, or the portal is useless) --")
    for c in report["controls"]:
        mark = "pass" if c["passed"] else "FAIL"
        lines.append(f"  [{mark}] {c['name']:32} {c['detail']}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", choices=["rls", "appfilter"], default="rls")
    ap.add_argument("--both", action="store_true", help="run both arms and compare")
    args = ap.parse_args()

    RESULTS.mkdir(exist_ok=True)
    arms = ["rls", "appfilter"] if args.both else [args.arm]
    reports = {}
    for arm in arms:
        reports[arm] = run_arm(arm)
        print(render(reports[arm]))
        print()
        (RESULTS / f"attacks-{arm}.json").write_text(
            json.dumps(reports[arm], indent=2, default=str)
        )
        (RESULTS / f"attacks-{arm}.txt").write_text(render(reports[arm]))

    if args.both:
        print("=== ARM COMPARISON ===")
        rows = []
        rls, app = reports["rls"], reports["appfilter"]
        by_name = {o["name"]: o for o in app["outcomes"]}
        for o in rls["outcomes"]:
            other = by_name[o["name"]]
            if o["bypassed"] != other["bypassed"]:
                rows.append(
                    f"  {o['name']:38} rls={'BYPASS' if o['bypassed'] else 'held'}"
                    f"  appfilter={'BYPASS' if other['bypassed'] else 'held'}"
                )
        if rows:
            print("attacks where the two arms DIVERGE:")
            print("\n".join(rows))
        else:
            print("no divergence between arms on this attack set")
        print(
            f"\n  rls:       {rls['attacks_bypassed']} bypasses, "
            f"{rls['controls_passed']}/{rls['controls_total']} controls"
        )
        print(
            f"  appfilter: {app['attacks_bypassed']} bypasses, "
            f"{app['controls_passed']}/{app['controls_total']} controls"
        )
        (RESULTS / "arm_comparison.json").write_text(
            json.dumps(
                {
                    "rls": {k: rls[k] for k in
                            ("attacks_total", "attacks_bypassed", "controls_passed")},
                    "appfilter": {k: app[k] for k in
                                  ("attacks_total", "attacks_bypassed", "controls_passed")},
                    "divergences": rows,
                },
                indent=2,
            )
        )

    print("\n-- surfaces this suite does NOT cover --")
    for s in UNTESTED_SURFACES:
        print(f"  * {s}")
    print(f"\n  * {ORDER_BY_NOTE}")
    print(f"  * {MASKED_PREDICATE_NOTE}")

    close_pool()
    worst = max(r["attacks_bypassed"] for r in reports.values())
    controls_ok = all(r["controls_passed"] == r["controls_total"] for r in reports.values())
    # The RLS arm is the deliverable: it must have zero bypasses and full
    # controls. The appfilter arm is the control experiment and is allowed to
    # fail — that is the finding.
    rls_ok = (
        "rls" not in reports
        or (reports["rls"]["attacks_bypassed"] == 0
            and reports["rls"]["controls_passed"] == reports["rls"]["controls_total"])
    )
    if not rls_ok:
        print("\nFAIL: the RLS arm must have zero bypasses and pass every control")
        return 1
    if not controls_ok and "rls" not in reports:
        return 1
    _ = worst
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
