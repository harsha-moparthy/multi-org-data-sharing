"""Revocation bounds, asserted per trial rather than reported as an average."""

from __future__ import annotations

from attacks.bench_revocation import (
    REQUEST_INTERVAL_S,
    measure_inflight,
    run_mode,
)


def test_db_checked_revocation_halts_within_its_declared_bound(fresh):
    res = run_mode("db_checked", trials=3)
    bound = REQUEST_INTERVAL_S * 2
    for t in res.trials:
        assert t.halt_latency_s <= bound, (
            f"halt took {t.halt_latency_s:.3f}s, declared bound {bound:.3f}s"
        )
        assert t.rows_after_revoke == 0, (
            f"{t.rows_after_revoke} rows served after revocation to a request "
            "that started afterwards"
        )


def test_an_inflight_request_completes_and_the_next_is_denied(fresh):
    """The honest granularity of 'immediate' revocation.

    A read already running when revocation commits finishes on its snapshot.
    That is the true bound — one in-flight request — and it is asserted rather
    than glossed, so the zero above is not read as a stronger claim.
    """
    r = measure_inflight(trials=3)
    assert r["max_rows_leaked_inflight"] > 0, (
        "expected the in-flight request to complete on its pre-revocation snapshot; "
        "if this now returns 0 the bound is tighter than documented and the README "
        "should be updated"
    )
    assert r["next_request_always_denied"]


def test_token_only_enforcement_keeps_working_after_revocation(fresh):
    """The architecture lesson, asserted as a result.

    A stateless verifier that trusts a signed credential cannot honour
    revocation; its bound is the credential TTL. This is why the deliverable
    re-derives authorization from live rows on every read.
    """
    res = run_mode("token_only", trials=3)
    assert any(t.rows_after_revoke > 0 for t in res.trials), (
        "token-only mode no longer leaks after revocation, which would mean the "
        "comparison in the README is stale"
    )
    for t in res.trials:
        assert t.within_bound, "token-only mode exceeded even its TTL-based bound"


def test_caching_authorization_widens_the_window(fresh):
    """A 5s authorization cache trades revocation latency for throughput."""
    res = run_mode("cache_5s", trials=2)
    assert all(t.rows_after_revoke > 0 for t in res.trials)
    assert all(t.within_bound for t in res.trials)
    # and it is materially worse than the db-checked arm
    assert max(t.halt_latency_s for t in res.trials) > 1.0
