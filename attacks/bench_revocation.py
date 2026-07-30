"""Revocation-latency measurement.

The spec asks for revocation that "propagates within a measured bound". The
number depends entirely on *where* the check happens, so three modes are
measured rather than one:

``db_checked``   Every read re-derives authorization from live grant/delegation
                 rows (this system's design). Revocation bites on the next
                 request, so the bound is one in-flight request.

``cache_5s``     A plausible optimization: cache the resolved authorization for
                 5 seconds to avoid re-walking the chain per request. The bound
                 becomes the cache TTL.

``token_only``   The common architecture: trust the signed credential until it
                 expires, because verifying signatures is cheap and stateless.
                 The bound becomes the credential lifetime, and revocation does
                 nothing until then.

The agent keeps working throughout; what is measured is how long it keeps
*succeeding* after revocation, and how many rows it exfiltrates in that window.
Reporting rows-after-revoke matters because latency alone understates the damage.

**Scope of the db_checked number.** The loop revokes and then issues the next
request, so it measures "how soon does a request that STARTS after the revoking
transaction commits get refused". It does not measure a request already in
flight at the instant of revocation — that one completes, because it authorized
against a snapshot taken before the revocation committed. ``measure_inflight()``
demonstrates exactly that case separately, so the headline 0-rows figure is not
read as a claim it does not support.
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path

from sharing import credentials
from sharing.db import admin_conn, close_pool, init_schema
from sharing.portal import Portal

RESULTS = Path(__file__).resolve().parents[1] / "results"

# The agent polls this often; a real one would be slower, but the interval is
# declared rather than tuned so the bound arithmetic is checkable.
REQUEST_INTERVAL_S = 0.02
# Credential lifetime for the token_only arm. Deliberately short: the measured
# bound IS this number, which is the argument for short-lived credentials.
TOKEN_TTL_S = 0.5
CACHE_TTL_S = 5.0
MAX_WAIT_S = 12.0


@dataclass
class Trial:
    mode: str
    halt_latency_s: float
    rows_after_revoke: int
    requests_after_revoke: int
    declared_bound_s: float
    within_bound: bool


@dataclass
class ModeResult:
    mode: str
    declared_bound_s: float
    trials: list[Trial] = field(default_factory=list)

    def summary(self) -> dict:
        lat = [t.halt_latency_s for t in self.trials]
        rows = [t.rows_after_revoke for t in self.trials]
        return {
            "mode": self.mode,
            "declared_bound_s": self.declared_bound_s,
            "trials": len(self.trials),
            "halt_latency_mean_s": round(statistics.mean(lat), 4),
            "halt_latency_max_s": round(max(lat), 4),
            "rows_after_revoke_max": max(rows),
            "rows_after_revoke_mean": round(statistics.mean(rows), 2),
            "within_bound": f"{sum(t.within_bound for t in self.trials)}/{len(self.trials)}",
            "all_within_bound": all(t.within_bound for t in self.trials),
        }


class CachingPortal:
    """Portal with an authorization cache — the ``cache_5s`` mode.

    Wraps the real portal and reuses the last successful authorization for
    ``ttl`` seconds without re-checking the database.
    """

    def __init__(self, ttl: float):
        self.inner = Portal("rls")
        self.ttl = ttl
        self._cached_until = 0.0
        self._cached_ok = False

    def read_shipments(self, credential, **kw):
        now = time.monotonic()
        if self._cached_ok and now < self._cached_until:
            # Serve from the cached decision: re-run the query but do not
            # re-authorize. Modeled by reading with a credential we already
            # accepted; the rows come from the last known-good authorization.
            res = self._last
            return res
        res = self.inner.read_shipments(credential, **kw)
        if res.decision == "allow":
            self._cached_ok = True
            self._cached_until = now + self.ttl
            self._last = res
        else:
            self._cached_ok = False
        return res


class TokenOnlyPortal:
    """Portal that trusts a validly-signed credential — the ``token_only`` mode.

    It verifies the signature and expiry (which the database still does for it)
    but ignores grant/delegation revocation entirely. This is what a stateless
    edge verifier looks like.
    """

    def __init__(self):
        self.inner = Portal("rls")

    def read_shipments(self, credential, **kw):
        claims = credentials.decode_unverified(credential) or {}
        # Signature+expiry check via the database, without the liveness join.
        with admin_conn() as conn:
            ok = conn.execute(
                "SELECT portal.verify_credential(%s) IS NOT NULL AS ok", (credential,)
            ).fetchone()["ok"]
            if not ok:
                from sharing.portal import Result

                return Result(decision="deny", deny_reason="bad_or_expired_credential")
            # It trusts the token, so it reads with owner privileges and applies
            # only what the token claims — no revocation check anywhere.
            rows = conn.execute(
                """
                SELECT s.shipment_id FROM portal.shipment s
                 JOIN portal.delegation d ON d.delegation_id = %s
                 WHERE s.owner_org = 'northwind' AND s.region = ANY(d.region_scope)
                   AND portal.class_rank(s.classification) <= portal.class_rank('internal')
                   AND (s.partner_org IS NULL OR s.partner_org = 'meridian')
                """,
                (claims.get("delegation_id"),),
            ).fetchall()
        from sharing.portal import Result

        return Result(decision="allow", rows=rows)


def _reset_delegation() -> None:
    with admin_conn() as conn:
        conn.execute(
            "UPDATE portal.delegation SET revoked_at=NULL, revoked_reason=NULL "
            "WHERE delegation_id='d-agent1'"
        )


def _revoke() -> float:
    """Revoke and return the wall-clock instant of revocation."""
    with admin_conn() as conn:
        t = time.monotonic()
        conn.execute(
            "SELECT portal.revoke_delegation('d-agent1','mr-priya','revocation bench')"
        )
    return t


def run_mode(mode: str, trials: int) -> ModeResult:
    if mode == "db_checked":
        bound = REQUEST_INTERVAL_S * 2  # one in-flight request plus scheduling
    elif mode == "cache_5s":
        bound = CACHE_TTL_S + REQUEST_INTERVAL_S * 2
    else:
        bound = TOKEN_TTL_S + REQUEST_INTERVAL_S * 2

    out = ModeResult(mode=mode, declared_bound_s=bound)

    for _ in range(trials):
        _reset_delegation()
        if mode == "db_checked":
            portal: object = Portal("rls")
        elif mode == "cache_5s":
            portal = CachingPortal(CACHE_TTL_S)
        else:
            portal = TokenOnlyPortal()

        ttl = TOKEN_TTL_S if mode == "token_only" else 300
        tok = credentials.mint(
            subject="mr-agent-1", grant_id="g-main",
            delegation_id="d-agent1", ttl_seconds=ttl,
        )

        # Warm up: the agent is working normally before revocation.
        for _ in range(3):
            r = portal.read_shipments(tok)  # type: ignore[attr-defined]
            assert r.decision == "allow", f"{mode}: agent could not work pre-revoke"
            time.sleep(REQUEST_INTERVAL_S)

        revoked_at = _revoke()
        rows_after = 0
        reqs_after = 0
        halt_latency = None
        while time.monotonic() - revoked_at < MAX_WAIT_S:
            r = portal.read_shipments(tok)  # type: ignore[attr-defined]
            reqs_after += 1
            if r.decision == "allow" and r.rows:
                rows_after += len(r.rows)
                time.sleep(REQUEST_INTERVAL_S)
                continue
            halt_latency = time.monotonic() - revoked_at
            break

        if halt_latency is None:
            halt_latency = MAX_WAIT_S  # never stopped within the window

        out.trials.append(
            Trial(
                mode=mode,
                halt_latency_s=halt_latency,
                rows_after_revoke=rows_after,
                requests_after_revoke=reqs_after,
                declared_bound_s=bound,
                within_bound=halt_latency <= bound,
            )
        )

    _reset_delegation()
    return out


def measure_inflight(trials: int = 5) -> dict:
    """The case the main loop cannot see: revocation DURING a read.

    A read that has already begun holds a transaction snapshot from before the
    revoking commit, so it finishes and returns its rows. This is not a flaw to
    hide — it is the true granularity of "revocation is immediate", and an
    operator needs the honest version: the bound is one in-flight request, and
    the blast radius is that request's rows.
    """
    import threading

    leaked = []
    for _ in range(trials):
        _reset_delegation()
        portal = Portal("rls")
        tok = credentials.mint(
            subject="mr-agent-1", grant_id="g-main", delegation_id="d-agent1"
        )
        box: dict = {}

        # Bind the loop variables explicitly. The thread is joined inside this
        # iteration so late binding is harmless in practice, but an unbound
        # closure over a loop variable is the kind of thing that silently starts
        # measuring the wrong trial when someone later moves the join.
        def read(portal=portal, tok=tok, box=box):
            box["res"] = portal.read_shipments(tok)

        t = threading.Thread(target=read)
        t.start()
        _revoke()          # revoke while the read is running
        t.join()
        res = box["res"]
        leaked.append(len(res.rows) if res.decision == "allow" else 0)

        # and the very next request must be refused
        after = portal.read_shipments(tok)
        assert after.decision == "deny", "post-revocation request was allowed"

    _reset_delegation()
    return {
        "trials": trials,
        "rows_served_by_inflight_request": leaked,
        "max_rows_leaked_inflight": max(leaked),
        "next_request_always_denied": True,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=10)
    args = ap.parse_args()

    init_schema()
    RESULTS.mkdir(exist_ok=True)

    results = [run_mode(m, args.trials) for m in ("db_checked", "cache_5s", "token_only")]
    summaries = [r.summary() for r in results]

    hdr = (
        f"{'mode':12} {'halt mean':>10} {'halt max':>9} {'rows after':>11} "
        f"{'bound':>7} {'within':>7}"
    )
    print(f"revocation propagation, {args.trials} trials per mode, "
          f"agent requesting every {REQUEST_INTERVAL_S * 1000:.0f}ms")
    print()
    print(hdr)
    print("-" * len(hdr))
    for s in summaries:
        print(
            f"{s['mode']:12} {s['halt_latency_mean_s']:>9.3f}s {s['halt_latency_max_s']:>8.3f}s "
            f"{s['rows_after_revoke_max']:>11} {s['declared_bound_s']:>6.2f}s "
            f"{s['within_bound']:>7}"
        )

    inflight = measure_inflight()
    print()
    print("in-flight request at the instant of revocation (db_checked):")
    print(
        f"  rows served by the already-running read: "
        f"{inflight['rows_served_by_inflight_request']} "
        f"(max {inflight['max_rows_leaked_inflight']})"
    )
    print("  the next request after it: denied in every trial")
    print(
        "  => the honest bound is ONE in-flight request, not zero. The 0 in the\n"
        "     table above is for requests starting after the revoke commits."
    )

    (RESULTS / "revocation_bench.json").write_text(
        json.dumps(
            {
                "trials_per_mode": args.trials,
                "request_interval_s": REQUEST_INTERVAL_S,
                "token_ttl_s": TOKEN_TTL_S,
                "cache_ttl_s": CACHE_TTL_S,
                "modes": summaries,
                "inflight": inflight,
            },
            indent=2,
        )
    )
    close_pool()

    # db_checked is the deliverable's mode and must hold its bound.
    db = next(s for s in summaries if s["mode"] == "db_checked")
    if not db["all_within_bound"]:
        print("\nFAIL: db_checked mode exceeded its declared bound")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
