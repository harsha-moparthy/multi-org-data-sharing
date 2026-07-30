# Probe findings — measured on this machine before writing the system

Postgres 16.14 (Homebrew), `scripts/probe_rls.sql` + `scripts/probe_rls2.sql`.
Each row is a design decision, not trivia. Re-run with:

```bash
scripts/pg_local.sh psql -X -q -f scripts/probe_rls.sql
scripts/pg_local.sh psql -X -q -f scripts/probe_rls2.sql
```

| # | Question | Result | Consequence for the design |
|---|---|---|---|
| Q1 | Does a view over an RLS table apply the policy to a *third-party* role? | **Yes** — `agent-x` saw rows 1,2 of 3 | Row limits can live in the database. |
| Q2 | Can the app role reach the base tables directly? | **No** — `permission denied for table rows_t`, and for the grant table | The app role gets `SELECT` on guarded views only; a query that escapes them fails at Postgres, not at code review. |
| Q3 | With **no** identity set, does the policy deny or error? | **Denies**, 0 rows | Missing identity fails closed. `current_setting(..., true)` returns NULL and NULL never matches a grant. |
| Q4 | Is per-grant **column** masking enforced by the engine? | **Yes** — same rows, `revenue` NULL for `agent-x`, present for `agent-y` | Column limits are a `CASE` in the view target list keyed on the grant, not application post-processing. |
| Q5 | **Can the app role forge an identity by asserting it?** | **Blocked once the claim is signed** — forged signature → 0 rows, unsigned → 0 rows | Load-bearing. A bare `set_config('app.subject', ...)` *is* forgeable by whoever runs the query, so identity must be a **signed token the database verifies itself** inside a `SECURITY DEFINER` function. |
| Q6 | Can the app role mint a token (read the signing key)? | **No** — `permission denied for table keys_t` | The app holds bearer tokens but cannot manufacture one. Verification is a definer function over a key table the app cannot read. |
| Q7 | Does a transaction-local identity leak to the next transaction? | **No** — GUC empty after `COMMIT`, next read returns 0 rows | Identity is set with `set_config(..., true)` inside an explicit transaction. (Session-level `false` leaks across pooled checkouts, silently giving the next request the previous caller's authorization.) |
| Q9 | Does a leaky low-cost function in a `WHERE` clause see denied rows? | **No** — only `a-one`, `a-two` leaked; never `b-one`, with *or* without `security_barrier` | Because RLS is enforced at the **base table**, not by the view's `WHERE`. The barrier is kept anyway as defence in depth. |
| Q10 | Do aggregates through the view respect row and column limits? | **Yes** — `count(*)` = 2 not 3; `sum(revenue)` = NULL when masked | Aggregate probing gets the same answer set as row reads. |

## Negative finding, kept

| # | Question | Result | Consequence |
|---|---|---|---|
| Q8 | Does table metadata leak to a role that cannot read the table? | **Yes.** After `ANALYZE`, `pg_class.reltuples` reads **3** — the true total, including the row `agent-x` may not see. `pg_stats` correctly returns 0 rows and `pg_statistic` is `permission denied`. | RLS protects row *contents*, not the *cardinality* of the base relation. A partner who can run arbitrary SQL can learn roughly how many rows exist beyond their grant. `attacks/metadata_cardinality.py` demonstrates this as a **known, accepted** limitation with its mitigation (partners get views, never `pg_class`; the guarded read API is not arbitrary SQL), rather than claiming a bypass count of zero over an attack surface that was never tested. |
