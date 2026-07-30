#!/usr/bin/env bash
# Does the adversarial suite actually detect a broken control?
#
# A suite of 30 attacks that all pass proves nothing unless it can fail. This
# script breaks one control at a time in schema.sql, runs the tests, and reports
# which attack caught it. Every mutant MUST be caught.
#
# Usage: scripts/mutation_check.sh            (writes results/mutation_check.md)
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
SCHEMA=src/sharing/schema.sql
BACKUP=$(mktemp)
OUT=results/mutation_check.md
PY=${PY:-.venv/bin/python}

cp "$SCHEMA" "$BACKUP"
restore() { cp "$BACKUP" "$SCHEMA"; }
trap restore EXIT

# Preflight: prove the interpreter can actually run the suite BEFORE mutating.
# Without this, a wrong $PY makes every mutant look like a coverage gap — which
# is the most misleading possible failure, since it reports the security suite
# as toothless when nothing is wrong with it.
if ! $PY -c 'import pytest' 2>/dev/null; then
  echo "ERROR: '$PY' cannot import pytest, so no mutant would be evaluated." >&2
  echo "Pass an interpreter that has the dev extras installed, e.g.:" >&2
  echo "  PY=.venv/bin/python scripts/mutation_check.sh" >&2
  echo "  PY=\$(uv run python -c 'import sys; print(sys.executable)') scripts/mutation_check.sh" >&2
  exit 1
fi
if ! $PY -m pytest -q >/dev/null 2>&1; then
  echo "ERROR: the suite is not green before any mutation is applied." >&2
  echo "Fix that first — mutation results are meaningless from a red baseline." >&2
  $PY -m pytest -q 2>&1 | tail -n 15 >&2
  exit 1
fi
echo "preflight: '$PY' runs the suite and it is green"

mkdir -p results
{
  echo "# Mutation check: can the adversarial suite fail?"
  echo
  echo "Each row breaks exactly one control in \`src/sharing/schema.sql\`, runs the"
  echo "full test suite, and records which attack caught it. Regenerate with"
  echo "\`scripts/mutation_check.sh\`."
  echo
  echo "| # | control removed | caught | first failing tests |"
  echo "|---|---|---|---|"
} > "$OUT"

mutate () {
  local n="$1" desc="$2" pysnippet="$3"
  restore
  # A mutation whose search string does not match leaves the file unchanged and
  # then "passes", which reads identically to a genuine coverage gap. So the
  # snippet must prove it changed something, and a no-op is a hard error rather
  # than a quiet clean run. (This bit once: a `%`-formatting precedence bug built
  # a search string that never matched, and mutant 9 reported NOT CAUGHT.)
  if ! $PY - <<PYEOF
import pathlib, sys
p = pathlib.Path("$SCHEMA"); s = p.read_text(); before = s
$pysnippet
if s == before:
    sys.exit("mutation $n did not match anything in the schema")
p.write_text(s)
PYEOF
  then
    echo "| $n | $desc | **ERROR** | \`mutation did not apply — search string is stale\` |" >> "$OUT"
    echo "  [$n] $desc -> ERROR: mutation did not apply"
    return 1
  fi

  # Capture pytest's OUTPUT and its EXIT CODE separately.
  #
  # Grepping for FAILED alone cannot distinguish "the suite ran and passed"
  # (exit 0 — a real coverage gap) from "the suite never ran" (exit 4/5, e.g.
  # pytest not importable). Both produce no FAILED lines. That ambiguity turned
  # a broken interpreter path in CI into twelve reported coverage gaps.
  local out rc failures
  out=$($PY -m pytest -q 2>&1); rc=$?
  # pytest: 0 = all passed, 1 = tests failed. Anything else (2 collection error,
  # 3 internal error, 4 usage error, 5 no tests) means the suite did not run.
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
    echo "| $n | $desc | **ERROR** | \`pytest did not run (exit $rc)\` |" >> "$OUT"
    echo "  [$n] $desc -> ERROR: pytest did not run (exit $rc)"
    echo "$out" | tail -n 5 >&2
    return 1
  fi

  failures=$(printf '%s\n' "$out" | grep -E '^FAILED' | head -3 \
             | sed -E 's/FAILED tests\///; s/ - .*//' | paste -sd '; ' -)
  local caught="**yes**"
  if [ "$rc" -eq 0 ]; then
    # Exit 0 with the mutation applied: the suite genuinely did not notice.
    caught="**NO — GAP**"
    failures=""
  fi
  echo "| $n | $desc | $caught | \`${failures:-none}\` |" >> "$OUT"
  echo "  [$n] $desc -> ${failures:-NOT CAUGHT}"
}

echo "running mutation check (each mutant runs the full suite)..."

mutate 1 "RLS policy: partner-org restriction" \
  's=s.replace("       AND (shipment.partner_org IS NULL OR shipment.partner_org = a.grantee_org)","       AND (true)")'

mutate 2 "RLS policy: classification ceiling" \
  's=s.replace("AND portal.class_rank(shipment.classification) <= portal.class_rank(a.max_classification)","AND true")'

mutate 3 "RLS policy: region scope" \
  's=s.replace("AND shipment.region    = ANY (a.region_scope)","AND true")'

mutate 4 "view: cost column masking" \
  's=s.replace("CASE WHEN a.allow_cost    THEN s.unit_cost_usd END AS unit_cost_usd","s.unit_cost_usd AS unit_cost_usd")'

mutate 5 "view: contact column masking" \
  's=s.replace("CASE WHEN a.allow_contact THEN s.contact_email END AS contact_email","s.contact_email AS contact_email")'

mutate 6 "current_auth: delegation revocation/expiry check" \
  's=s.replace("IF d.revoked_at IS NOT NULL OR d.expires_at <= now() THEN RETURN; END IF;","IF false THEN RETURN; END IF;")'

mutate 7 "current_auth: delegation chain walk to root" \
  's=s.replace("IF hop.revoked_at IS NOT NULL OR hop.expires_at <= now() THEN RETURN; END IF;\n    IF hop.grant_id <> g.grant_id THEN RETURN; END IF;","IF false THEN RETURN; END IF;")'

mutate 8 "current_auth: grant liveness (approved/unrevoked/unexpired)" \
  's=s.replace("IF NOT FOUND OR NOT portal.grant_is_live(g, now()) THEN RETURN; END IF;","IF NOT FOUND THEN RETURN; END IF;")'

mutate 9 "current_auth: credential subject must match the delegatee" \
  '''s=s.replace("""IF d.delegatee IS DISTINCT FROM c->>\x27sub\x27 THEN RETURN; END IF;""","IF false THEN RETURN; END IF;")'''

mutate 10 "verify_credential: signature comparison" \
  's=s.replace("IF expect IS DISTINCT FROM parts[2] THEN RETURN NULL; END IF;","IF false THEN RETURN NULL; END IF;")'

mutate 11 "verify_credential: expiry check" \
  's=s.replace("OR to_timestamp((claims->>%s)::double precision) <= now() THEN" % (chr(39)+"exp"+chr(39)),"OR false THEN")'

mutate 12 "delegation trigger: narrowing enforcement" \
  's=s.replace("IF NOT (NEW.region_scope <@ g.region_scope) THEN","IF false THEN")'

restore
echo
echo "verifying the suite is green again after restore..."
if final_out=$($PY -m pytest -q 2>&1); then
  n_passed=$(printf '%s\n' "$final_out" | grep -oE '[0-9]+ passed' | tail -1)
  echo "restored: suite green (${n_passed:-all passed})"
  echo >> "$OUT"
  echo "After restoring the original schema the suite is green again" \
       "(${n_passed:-all passed})." >> "$OUT"
else
  echo "WARNING: suite is not green after restore" >&2
  exit 1
fi

echo
cat "$OUT"
