"""The adversarial suite, run as tests.

These import the same attack definitions the reported numbers come from, so a
divergence between "what the README claims" and "what the tests check" is not
possible.
"""

from __future__ import annotations

import pytest

from attacks.framework import evaluate
from attacks.positive_control import run_controls
from attacks.suite import all_attacks
from sharing.portal import Portal

ATTACKS = all_attacks()


@pytest.fixture(scope="module")
def portal():
    return Portal("rls")


@pytest.mark.parametrize("attack", ATTACKS, ids=[a.name for a in ATTACKS])
def test_attack_is_held_by_the_rls_arm(attack, portal, fresh):
    outcome = evaluate(attack, portal)
    assert not outcome.bypassed, f"{attack.name} BYPASSED: {outcome.detail}"


def test_positive_controls_all_pass(portal, fresh):
    """The other half of the requirement: exactly the approved rows/columns.

    Without this, a portal that returns nothing to anyone would pass every
    attack test above.
    """
    outcomes = run_controls(portal)
    failed = [(o.case.name, o.detail) for o in outcomes if not o.passed]
    assert not failed, f"legitimate requests failed: {failed}"


def test_suite_covers_all_four_families_from_the_spec():
    """The spec names four attack families; none may be quietly dropped."""
    families = {a.family for a in ATTACKS}
    assert families == {
        "forged_identity",
        "expired_or_revoked",
        "delegation_chain",
        "side_channel",
    }, f"attack families drifted: {families}"
    # and each family must be more than a token single case
    for fam in families:
        n = sum(1 for a in ATTACKS if a.family == fam)
        assert n >= 5, f"family {fam} has only {n} attacks"


def test_appfilter_arm_leaks_masked_values(fresh):
    """The control arm's failure is a result, so it is asserted rather than assumed.

    If a future change made the appfilter arm safe here, this test fails and the
    side-channel document's central claim would need rewriting — which is
    exactly the signal we want.
    """
    app = Portal("appfilter")
    targeted = [
        a for a in ATTACKS
        if a.name in {
            "masked_column_in_predicate",
            "order_by_masked_column",
            "aggregate_sum_masked_column",
            "aggregate_min_max_probe",
        }
    ]
    assert len(targeted) == 4
    results = {a.name: evaluate(a, app).bypassed for a in targeted}
    assert all(results.values()), (
        "the appfilter arm no longer leaks through every masked-column channel; "
        f"results/side_channel_analysis.md is now stale: {results}"
    )
