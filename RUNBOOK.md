# RUNBOOK — operating a multi-org data share

For whoever is on call for the sharing portal. Written to be followed under
pressure: every procedure states what to run, what "good" looks like, and what to
do when it isn't.

The governing principle: **the database is the enforcement point.** If you are
about to fix an access problem by changing application code, stop — you are
probably about to move enforcement somewhere weaker.

---

## 0. Ten-second mental model

- A **grant** is provider-org → one *human* in a partner org, scoped to regions,
  a classification ceiling, and column capabilities, with an expiry. It does
  nothing until a human on the provider side approves it.
- A **delegation** lets that human's *agent* act under the grant, always
  narrower and never longer-lived. Sub-delegations narrow again.
- A **credential** is a short-lived signed claim. The database verifies it and
  re-derives everything from live grant/delegation rows on every read. Holding a
  valid credential is not authorization.
- Every read appends one hash-chained audit row, allowed or denied.

---

## 1. Bring the environment up

```bash
scripts/pg_local.sh start        # Postgres 16 into ./pgdata on 127.0.0.1:5435
uv sync --extra dev
uv run portal init               # schema + roles + policies + demo scenario
```

Good: `postgres ready on 127.0.0.1:5435` then `schema ready  (seeded)`.

`portal init` is **destructive** — it drops and recreates the `portal` schema.
Never run it against a live share. For a real deployment, apply `schema.sql`
once and manage grants through the CLI.

Health check:

```bash
uv run portal grant list          # every grant, with a live/dead column
uv run portal audit verify        # chain intact over N events
uv run pytest -q                  # 88 tests, ~15 s
```

### Environment variables

| Variable | Meaning | Note |
|---|---|---|
| `PORTAL_SIGNING_KEY` | HMAC key for credentials **and** the audit chain | Must be stable. Rotating it invalidates live credentials and makes previously-written audit rows fail verification — see §7. |
| `PGHOST`/`PGPORT`/`PGDATABASE`/`PGUSER` | admin connection | Defaults to `127.0.0.1:5435/sharing` as `shareadmin`. |
| `ADMIN_URL` / `APP_URL` | full override | `APP_URL` must point at `portal_app`, never at a privileged role. |

---

## 2. Onboard a partner (the common request)

A partner asks for access. Two steps, deliberately separate: requesting is not
approving.

```bash
# 1. the request — creates an UNAPPROVED grant, which serves nothing
uv run portal grant request g-acme northwind acme ac-jordan \
    --regions EU,UK --max-class internal --cost --days 90

# 2. a human on the PROVIDER side approves
uv run portal grant approve g-acme nw-dana
```

Verify before telling the partner it works:

```bash
uv run portal grant list                       # g-acme shows live = yes
TOK=$(uv run portal token ac-jordan --grant g-acme)
uv run portal whoami "$TOK"                    # confirm the scope the DB derived
uv run portal read "$TOK" --columns all        # confirm the rows and masking
```

**Check the masked columns, not just the row count.** The most common
misconfiguration is a grant that returns the right rows with a sensitive column
unintentionally unlocked.

If approval is refused:

| Message | Cause |
|---|---|
| `approver X must be a human` | You passed an agent id. Agents cannot approve shares. |
| `approver X (org Y) cannot approve a grant over Z data` | The approver is not in the provider org. A consuming org cannot approve its own access. |

---

## 3. Let a partner's agent act (delegated credentials)

The partner's *human* delegates to their agent. Narrow it deliberately — the
agent should hold the least it needs for its stated purpose.

```bash
uv run portal delegation create d-acme-agent g-acme ac-jordan ac-agent-1 \
    --purpose "weekly EU replenishment planning" \
    --regions EU --hours 24
```

`--purpose` is required and lands in the audit trail. A delegated credential
without a stated purpose cannot be reviewed meaningfully six months later.

The database refuses anything that widens scope. These are **correct** refusals,
not bugs to work around:

```
delegation regions {EU,UK,APAC} exceed grant scope {EU,UK}
delegation cannot widen the column scope of grant g-acme
delegation cannot outlive grant g-acme (expires ...)
sub-delegation regions {...} exceed parent {...}
delegator X does not hold grant g-acme (held by Y)
delegatee X must be an agent, is human
```

If a partner needs more than their grant allows, the answer is a **new grant
request and a new provider approval** — not a wider delegation.

---

## 4. Incident: "a partner saw something they shouldn't have"

Work from the audit trail. Do not start by reading application logs.

```bash
AT=$(uv run portal audit-token nw-dana northwind)      # provider-side credential

# 1. What has this partner's identities actually done?
uv run portal audit trail "$AT" --side provider --limit 100

# 2. Reconstruct the specific access in full, including the authority chain
uv run portal audit reconstruct <seq>
```

`audit reconstruct` gives you: the agent, the human it acted for, the grant, the
delegation, the exact row ids served, the exact columns withheld, the verbatim
request, and the chain back to the provider human who approved the share.

Then confirm the trail has not been altered:

```bash
uv run portal audit verify        # must say: chain intact over N events
```

**If the chain is broken**, treat it as an integrity incident. `audit_verify()`
names the first divergent `seq`; everything from that row onward is suspect.
Rows are append-only by trigger, so a break means either the trigger was
disabled (a privileged insider) or the signing key changed (§7).

Reconciliation query — did the portal ever serve a row outside its grant's scope?
This is the check that would catch a policy bug rather than a credential misuse:

```bash
uv run python -m attacks.audit_reconstruction    # section 7 runs it; expects 0 and 0
```

### Deciding what actually happened

| Finding | Interpretation |
|---|---|
| `decision=allow`, rows inside the grant's scope | Working as configured. The grant was too broad — a **policy** problem, fix in §5. |
| `decision=deny`, `subject=NULL` | Someone presented an unverifiable credential. `request.claimed_sub` shows who it claimed to be. Not a breach; an attempt. |
| `decision=allow` but reconciliation flags the row | A genuine enforcement bug. Contain per §5, then treat the RLS policy as suspect. |

---

## 5. Contain: revoke

Revocation is checked on every read, so it takes effect on the **next request**.

```bash
# stop one agent, leave the human's access intact
uv run portal delegation revoke d-acme-agent nw-dana "incident 4821"

# stop the entire share
uv run portal grant revoke g-acme nw-dana "incident 4821"
```

Revoking a delegation also kills every credential *below* it in the chain,
because authorization walks to the root on every read.

**What revocation does not do:** stop a read that is already executing. That
request finishes on its pre-revocation snapshot — measured at one request's worth
of rows. Expect up to one more response after you revoke; verify with the audit
trail rather than assuming.

Confirm containment:

```bash
TOK=$(uv run portal token ac-agent-1 --grant g-acme --delegation d-acme-agent)
uv run portal read "$TOK"        # must exit non-zero: denied
uv run portal audit trail "$AT" --side provider --limit 5   # the denial is recorded
```

To offboard a person entirely, disable the principal. This kills every delegation
rooted at them in one step — you do not need to hunt down their agents:

```bash
uv run portal disable-principal ac-jordan
uv run portal whoami "$TOK"        # their agent: "no live authorization"
```

Reversible if you disabled the wrong person: `--enable` restores them.

```bash
uv run portal disable-principal ac-jordan --enable
```

---

## 6. Routine review

**Weekly** — what is live, and does anything look over-broad?

```bash
uv run portal grant list
uv run portal delegation list
```

Look for: grants with `allow_contact=yes` that don't need personal data;
delegations whose `expires` is far out; delegations whose purpose no longer
matches what the partner is doing.

**Monthly** — prove the controls still hold. This is the difference between a
governed share and one that merely was governed once:

```bash
uv run pytest                                  # 88 tests
uv run python -m attacks.run_suite --both      # 30 attacks; RLS arm must be 0 bypasses
uv run python -m attacks.bench_revocation      # revocation bounds still hold
scripts/mutation_check.sh                      # the suite can still detect a break
uv run portal audit verify
```

Any RLS-arm bypass, or any positive-control failure, is a stop-ship. A positive
control failing means the portal is refusing legitimate requests — an outage,
even though nothing leaked.

---

## 7. Signing-key rotation (read before you do it)

`PORTAL_SIGNING_KEY` signs **two different things**: live credentials and the
audit chain. Rotating it:

- invalidates every outstanding credential immediately (partners must re-mint —
  that is acceptable and, in a compromise, desirable);
- makes `audit_verify()` fail for every row written under the old key, because
  their HMACs no longer recompute.

So a rotation is not a routine operation. Before rotating:

1. Run `uv run portal audit verify` and record that the chain was intact.
2. Export the existing trail for archival:
   `scripts/pg_local.sh psql -c "\copy portal.audit_event TO 'audit-pre-rotation.csv' CSV HEADER"`
3. Rotate, then re-verify. Expect the chain to report a break at the first row
   written after rotation. Document the rotation timestamp alongside the archive
   so a future auditor can verify each segment against the key that signed it.

A production deployment should carry a `kid` per key and keep old keys for
verification — the schema already stores `kid` per row in `signing_key` and the
credential carries it, so this is a configuration change rather than a redesign.

---

## 8. Troubleshooting

| Symptom | Likely cause | Check |
|---|---|---|
| `no live authorization` for a credential that "should work" | The grant is unapproved, expired or revoked; or a delegation hop is dead; or a principal in the chain is disabled | `uv run portal whoami "$TOK"`, then `portal grant list` and `portal delegation list` |
| Partner sees 0 rows but is authorized | Their scope legitimately matches nothing (e.g. region scope with no rows), or the classification ceiling excludes everything | `portal whoami` shows the derived scope; compare against the data |
| A column the partner expects is NULL | The grant lacks that capability, or a delegation narrowed it away. Remember the *intersection* of grant and every hop applies | `portal whoami` shows `allow_cost` / `allow_contact` |
| `permission denied for table shipment` | Something is trying to read the base table as `portal_app`. This is the protection working — find the code path that bypassed the view | it should never come from `portal.py`'s RLS arm |
| `new row violates row-level security policy` on load | You are loading provider data through a non-privileged role. Data loading is an admin operation outside the portal | run it as the bootstrap superuser |
| `function hmac(...) does not exist` | The `ext` schema is missing or `USAGE` was not granted | re-run `portal init`; see the note at the top of `schema.sql` |
| Audit chain broken with no known incident | Signing key changed (§7), or a trigger was disabled | compare the first bad `seq` against your deployment timeline |

---

## 9. What this system does not protect against

State these when someone asks "is the data safe?", because a confident yes over
an untested surface is worse than a scoped one. The full list is in
`attacks/framework.py` and prints with every suite run.

- **Base-table cardinality.** `pg_class.reltuples` reveals the true row count to
  any role that can read the catalog, including one with no privilege on the
  table. Demonstrated by `uv run python -m attacks.metadata_cardinality`.
  Mitigated only by the fact that partners receive an API, never a database
  connection. **If you are ever asked to give a partner direct SQL access, this
  is the first thing to raise.**
- **Timing.** Response latency varies with rows scanned; not measured, not
  mitigated.
- **Denial of service.** An authorized partner can issue expensive queries.
- **Physical, backup and replica access.** Out of scope; the audit chain detects
  tampering with the trail, not exfiltration of a filesystem snapshot.
- **A compromised signing key.** Whoever holds it can mint any credential and
  forge a consistent audit chain. It is the one secret that matters; treat its
  storage as the security boundary of the whole system.
