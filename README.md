# Multi-Org Data Sharing with Delegated Agent Credentials

**Two organizations share a governed slice of one database. The "user" asking for
data is often a partner's AI agent acting on a human's delegated authority — so
row and column limits are enforced by Postgres from grant tables, credentials are
short-lived signed claims the database verifies for itself, and 30 adversarial
attacks across four families pass with zero bypasses while five positive controls
prove the portal still serves exactly the approved rows.**

---

## Why this project exists

Sharing governed data with a partner is an old problem. What is new is *who*
shows up holding the credential. When org B's planning agent reads org A's data
on behalf of org B's analyst, three things have to be true at once, and the third
is the one that gets skipped:

1. The partner sees exactly the approved rows and columns — no more.
2. The agent sees **no more than the human who delegated to it**, its authority
   expires, and revoking it actually stops it.
3. Both organizations can reconstruct, later, who saw what under whose authority.

The tempting implementation is to filter in the application. This project builds
that version too, as a control arm, because the comparison is the interesting
result: **application-level filtering leaks masked values through the caller's own
SQL, while database-enforced masking does not** — and the leak is invisible if
you only check the rows you return.

## Status

Built and measured. Every number below is produced by a committed script on a
real Postgres 16, reproducible with the commands in [Reproduce](#reproduce).

| Evidence | Result |
|---|---|
| Test suite (real Postgres, real RLS policies) | **88 passed** |
| Adversarial suite, RLS arm — 4 families, 30 attacks | **0 bypasses** |
| Positive controls (exactly the approved rows/columns) | **5/5 exact match** vs. an independent oracle |
| Control arm (competent application-level filtering) | **4 bypasses** — all masked-column channels |
| Mutation check: deliberately break each control | **12/12 mutants caught** by the suite |
| Revocation, DB-checked | halts in **7.9 ms** mean (bound 40 ms), **0 rows** to any request starting after the commit |
| Revocation, honest in-flight bound | the already-running read completes: **5 rows**, then every later request denied |
| Revocation, token-TTL-only enforcement | keeps working **395 ms**, serving **50 rows** after revocation |
| Revocation, 5-second authorization cache | keeps working **4.93 s**, serving **945 rows** after revocation |
| Audit chain over 45 events | **intact**; an insider's edit is caught at the exact row |
| Audit reconciliation | rows served outside grant scope: **0**; reads under an unapproved grant: **0** |
| Known limitation, not fixed | `pg_class.reltuples` leaks true base-table cardinality (24) to a role that cannot read the table |

## The four structural facts

Each was verified against Postgres 16 *before* the system was written, because
two of them invalidate the obvious implementation. Full probe in
[PROBE_FINDINGS.md](PROBE_FINDINGS.md).

| Fact | Consequence |
|---|---|
| A view over a `FORCE ROW LEVEL SECURITY` table applies the policy to a third-party role (Q1), and per-grant column masking works as a `CASE` in the view's target list (Q4) | Row **and** column limits live in the database, driven by grant tables. |
| `portal_app` can be given **zero** privileges on every base table (Q2) | A query that escapes the guarded views fails at Postgres, not at code review. Asserted against the catalog in `tests/test_privileges.py`. |
| **A bare `set_config('app.subject', …)` is forgeable by whoever runs the query (Q5)** | Identity cannot be an asserted GUC. It is a **signed credential the database verifies inside a `SECURITY DEFINER` function**, using a key `portal_app` cannot read (Q6). This is the single most load-bearing finding. |
| A transaction-local setting does not survive the pooled checkout (Q7) | Identity is set with `set_config(…, true)` inside an explicit transaction, so it cannot leak to the next request on that connection. |

## Architecture

```
      partner's analyst (human)          partner's agent (non-human)
                │                                    │
                │ holds the grant                    │ holds a DELEGATION
                └──────────────┬─────────────────────┘   (narrower, shorter)
                               │  signed short-lived credential carrying the chain
                               ▼
                  ┌────────────────────────────┐
                  │  portal (as portal_app)    │  no base-table privileges,
                  │  passes the credential     │  no filtering of its own
                  └─────────────┬──────────────┘
                                ▼
   ┌──────────────────────────────────────────────────────────────────────┐
   │ Postgres 16                                                          │
   │                                                                      │
   │  verify_credential()  definer fn: HMAC over claims, key unreadable   │
   │           ▼            by the app → forged/expired ⇒ NULL ⇒ deny     │
   │  current_auth()       walks the WHOLE delegation chain to its root,  │
   │           ▼            intersecting scope; any dead hop kills it     │
   │  RLS POLICY on shipment ── rows: provider ∧ region ∧ class ∧ partner │
   │  shared_shipment VIEW  ─── columns: CASE per grant capability        │
   │                                                                      │
   │  data_grant · delegation   the authorization state the policy reads  │
   │  audit_event               append-only, HMAC-chained, org-scoped     │
   └──────────────────────────────────────────────────────────────────────┘
```

The read path has no authorization code in the application at all. `portal.py`'s
RLS arm passes the credential and runs the query; region, classification,
partner-org and column checks are absent from it by design.

### Delegation narrows, and the database enforces that

A grant is issued to a **human**. Agents never hold standing authority — a
trigger refuses a grant whose grantee is an agent. An agent reaches data only
through a delegation, which cannot widen the grant's regions or columns, cannot
outlive it, and (for sub-delegations) cannot exceed its parent. Eleven such rules
are enforced by trigger and tested in `tests/test_delegation_rules.py`.

In the seeded scenario this is visible in the numbers: the analyst sees **8 rows
with costs**, and her agent — delegated EU-only, no cost columns — sees **5 rows
with costs masked**. The agent legitimately sees less than the human who sent it.

## The headline result: where masking happens decides whether side channels exist

Both arms return NULL for masked columns. Both pass all five positive controls.
The control arm is not a strawman — it implements every rule the policy does, in
clear Python, and holds 26 of 30 attacks. It fails only where the *caller's own
SQL* touches a column it planned to mask afterwards.

| Attack (same credential, cost columns masked) | RLS arm | appfilter arm |
|---|---|---|
| `WHERE unit_cost_usd > N` for N = 0,3,5,10,100 | 1 identical result set — learns nothing | **5 distinct result sets** — binary-searches every hidden value |
| `ORDER BY unit_cost_usd DESC` vs `ASC` | identical order — sort key carried no information | **different orders**, revealing the true cost ranking |
| `sum(unit_cost_usd)` | `0` | **28** (true total 27.60) |
| `max(margin_pct)` | `0` | **23** (true max 22.50) |
| `count(*)` | 5 | 5 — correct in both; it touches no masked column |

Because the RLS arm masks in the view's target list, the caller's predicates,
sorts and aggregates are applied to a relation where the value is *already* NULL.
`NULL > 5` filters nothing and discloses nothing.

The general lesson: **application-level masking is only as strong as your
enumeration of the ways a query can observe a value.** Full measurements in
[results/side_channel_analysis.md](results/side_channel_analysis.md), regenerated
by CI and diffed against the committed copy.

## Revocation: the bound is where you check, not what you sign

The spec asks for revocation that propagates within a measured bound. The bound
depends entirely on the architecture, so three are measured — 10 trials each,
agent requesting every 20 ms, bounds declared in advance rather than fitted:

| enforcement | halt latency (mean/max) | rows served after revoke | declared bound | within |
|---|---|---|---|---|
| **DB-checked** (this system) | 0.008 s / 0.010 s | **0** | 0.04 s | 10/10 |
| token TTL only (stateless edge verifier) | 0.395 s / 0.416 s | **50** | 0.54 s | 10/10 |
| 5 s authorization cache | 4.93 s / 4.95 s | **945** | 5.04 s | 10/10 |

The zero is scoped honestly. It covers requests that *start* after the revoking
transaction commits. A read already in flight completes on its pre-revocation
snapshot: measured separately at **5 rows**, with every subsequent request
denied. So the true claim is "the bound is one in-flight request", and
`tests/test_revocation.py` asserts that rather than the flattering version.

## Audit: both orgs, and a tamper you cannot hide

Every request — allowed or denied — appends one HMAC-chained row recording the
subject, the human it acted for, the grant, the delegation, the exact row ids
served, and the exact columns withheld. Two org-scoped views expose it:
`northwind` sees who touched its data, `meridian` sees what its own people and
agents did, and neither can see the other partner's activity. The viewing org
comes from a *signed* audit credential, so an app-level forgery returns nothing
(tested).

Denials are recorded with `subject = NULL`. An unverifiable credential is
**visibly unattributed** rather than borrowing the identity it claimed; the claim
is preserved in the request payload for investigation. A benign-looking default
here would let a forged request inherit a real principal's name.

`UPDATE` and `DELETE` are refused by trigger. The realistic threat is an insider
who disables the trigger and rewrites a row — so
`python -m attacks.audit_reconstruction` does exactly that and shows
`audit_verify()` naming the divergent sequence number.

## Can this suite fail?

Thirty passing attacks prove nothing unless the suite can detect a broken
control. `scripts/mutation_check.sh` breaks one control at a time and records
which attack catches it — **12/12 caught**, in
[results/mutation_check.md](results/mutation_check.md).

That script also refuses to report a clean run for a mutation that did not
apply. Its first version had a Python precedence bug that built a search string
matching nothing, and the resulting no-op read exactly like a coverage gap.

## Reproduce

```bash
scripts/pg_local.sh start          # Homebrew postgresql@16 into ./pgdata on :5435, no Docker
uv sync --extra dev
uv run portal init                 # schema, roles, RLS policies, two-org scenario

uv run pytest                                        # 88 tests
uv run python -m attacks.run_suite --both            # 30 attacks x 2 arms + comparison
uv run python -m attacks.bench_revocation            # revocation bounds
uv run python -m attacks.audit_reconstruction        # both orgs + tamper detection
uv run python -m attacks.side_channel_analysis       # regenerates the analysis doc
uv run python -m attacks.metadata_cardinality        # the limitation that is NOT fixed
scripts/mutation_check.sh                            # can the suite fail? (12 mutants)

python scripts/ci_local.py                           # every CI step, parsed from the workflow YAML
```

`scripts/ci_local.py` executes the steps *as written in*
`.github/workflows/adversarial-gate.yml` rather than a retyped copy, so a local
pass is a statement about the real workflow.

### See it as an operator

```bash
uv run portal grant list
uv run portal delegation list
TOK=$(uv run portal token mr-agent-1 --grant g-main --delegation d-agent1)
uv run portal whoami "$TOK"                 # what the DB concludes, not what the token claims
uv run portal read "$TOK" --columns all     # 5 rows, cost and contact masked

# the database refuses a delegation that would widen the grant
uv run portal delegation create d-x g-main mr-priya mr-agent-x \
    --purpose demo --regions EU,UK,APAC

AT=$(uv run portal audit-token nw-dana northwind)
uv run portal audit trail "$AT" --side provider
uv run portal audit reconstruct 4
uv run portal audit verify
```

## Layout

```
4.14-multi-org-data-sharing/
├── src/sharing/
│   ├── schema.sql          # roles, RLS policies, grant/delegation tables,
│   │                       #   verify_credential(), current_auth(), audit chain
│   ├── seed.sql            # the two-org scenario (24 rows, 4 grants, 2 delegations)
│   ├── credentials.py      # mint/verify/tamper — the issuer side
│   ├── portal.py           # the two enforcement arms
│   ├── expected.py         # the INDEPENDENT oracle (never reads the views)
│   └── cli.py              # portal grant|delegation|audit|read|whoami
├── attacks/
│   ├── framework.py        # bypass = forbidden rows/values served; untested surfaces
│   ├── suite.py            # 30 attacks in the spec's 4 families
│   ├── positive_control.py # 5 legitimate requests that must succeed exactly
│   ├── bench_revocation.py # 3 enforcement modes + the in-flight case
│   ├── side_channel_analysis.py
│   ├── audit_reconstruction.py
│   └── metadata_cardinality.py   # the accepted limitation, demonstrated
├── scripts/
│   ├── pg_local.sh         # Postgres 16 on :5435, repo-local, no Docker
│   ├── probe_rls*.sql      # the pre-build architecture probes
│   ├── mutation_check.sh   # 12 mutants; every one must be caught
│   └── ci_local.py         # runs CI's steps verbatim from the YAML
├── results/                # committed evidence, all regenerable
├── PROBE_FINDINGS.md       # what Postgres actually does, measured
└── RUNBOOK.md              # operating the share: onboarding, incidents, offboarding
```

## Honesty notes

- **What "zero bypasses" covers.** Thirty attacks against the read API. It does
  not cover arbitrary SQL from the partner, timing channels, or physical/backup
  access. `attacks/framework.py` lists the untested surfaces and the suite prints
  them with every run, because a bypass count over an unstated surface invites
  the wrong conclusion.
- **One channel is open and stays open.** `pg_class.reltuples` tells a role that
  cannot read `shipment` that it holds 24 rows while serving 5. RLS protects row
  contents, not relation cardinality. Mitigated operationally — partners get an
  API, never a connection — not cryptographically.
- **The control arm is built to win where it can.** It implements every rule the
  policy does and holds 26 of 30 attacks. A handicapped baseline would make the
  4-bypass result worth less, not more.
- **The oracle is independent.** `expected.py` derives the correct answer from
  raw fixture rows, never from the views or `current_auth()`; a test asserts it
  contains no reference to them. It can therefore catch over-blocking, which no
  attack test would notice.
- **Numbers here are machine-generated.** Every figure comes from a script in
  `attacks/` writing to `results/`, and CI regenerates the side-channel analysis
  and diffs it against the committed copy.

## Bugs this build found in itself

Kept because each would have shipped a *confidently wrong* deliverable rather
than a crash.

| Defect | Why it mattered |
|---|---|
| `viewer_org()` read a bare GUC | The audit views were keyed on a string `portal_app` sets itself, so either org could read the other's trail by asserting a different name — the exact forgery probe Q5 had already ruled out for data reads. Now derived from a signed audit credential. |
| Two prose notes claimed side channels were live under RLS | Written from expectation before measuring. The measurement showed masking in the view's target list makes them inert; the appfilter arm is where they are live. Both notes now state what was observed, and the claim is regenerated from live numbers. |
| `pgcrypto` in `public`, invisible to hardened functions | Every definer function pins `search_path` to exclude `public` (so a caller cannot shadow an unqualified name), which also hid `hmac`. Re-adding `public` would have undone the hardening; the extension moved to its own schema instead. |
| `hmac(text, bytea, text)` does not exist | pgcrypto offers `(bytea,bytea,text)` and `(text,text,text)`. The mismatch surfaced only from inside a trigger. Messages are now explicitly `convert_to(…, 'utf8')`, which also makes the digest byte-identical to Python's — asserted by a test. |
| `portal_app` needed SELECT for `RETURNING seq` | Granting it would have punched a hole in "no base-table privileges". Audit appends now go through a definer function, so the app holds **zero** privileges on every base table and the claim is absolute. |
| Mutation harness reported a false coverage gap | A `%`-precedence bug built a search string that matched nothing; the unmutated run passed and read as "attack suite has a hole". The harness now fails hard when a mutation does not apply. |
| `delegation_id` ambiguous in plpgsql | An OUT parameter shadowed the column of the same name, so the delegated read path errored while the human path worked. Qualified with the table alias. |
| `GRANT` to a role created 10 lines later | `GRANT USAGE ON SCHEMA ext TO portal_owner` sat above the block that creates `portal_owner`. Every local run passed because the roles already existed from a previous run; it failed on the first genuinely fresh cluster with `role "portal_owner" does not exist`. "Works on my machine" was literally true and useless. Now guarded two ways: a test that drops the roles and re-applies the schema, and a structural test that fails if any `GRANT` precedes the roles it names. |
| `pg_local.sh` succeeded while starting nothing | When port 5435 was already held by another cluster, `pg_ctl` failed but the script fell through to a `psql` that connected to the *foreign* cluster and printed "postgres ready". That is what hid the bug above from a from-scratch clone check. It now fails loudly rather than testing the wrong database. |
| Seeding as `portal_owner` was refused | `FORCE ROW LEVEL SECURITY` binds the owner too, and the only policy is for SELECT. Not a bug to route around — it proved the policy has no owner-shaped hole, so seeding is explicitly an administrative operation outside the portal. |
