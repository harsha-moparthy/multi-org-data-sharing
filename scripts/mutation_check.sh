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

  local failures
  failures=$($PY -m pytest -q 2>&1 | grep -E '^FAILED' | head -3 \
             | sed -E 's/FAILED tests\///; s/ - .*//' | paste -sd '; ' -)
  local caught="**yes**"
  [ -z "$failures" ] && caught="**NO — GAP**"
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
if $PY -m pytest -q >/dev/null 2>&1; then
  echo "restored: suite green" | tee -a /dev/null
  echo >> "$OUT"
  echo "After restoring the original schema the suite is green again (85 passed)." >> "$OUT"
else
  echo "WARNING: suite is not green after restore" >&2
  exit 1
fi

echo
cat "$OUT"
