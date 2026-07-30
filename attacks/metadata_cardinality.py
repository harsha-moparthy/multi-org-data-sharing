"""The one channel that is NOT closed, demonstrated rather than hidden.

RLS controls which *rows* a role may read. It does not conceal how many rows the
relation has. `pg_class.reltuples` is planner metadata, readable by anyone who
can read the catalog, and it reports the true total.

This is included as a runnable demonstration because a security result that
counts only the attacks you thought to run is worth less than one that says
plainly where the boundary is. The suite's "zero bypasses" figure is scoped to
the read API; this file is why that scope is stated explicitly.

    python -m attacks.metadata_cardinality
"""

from __future__ import annotations

import psycopg
from psycopg.rows import dict_row

from sharing import credentials
from sharing.db import admin_conn, app_url
from sharing.portal import Portal


def main() -> int:
    # What the partner's agent may legitimately see through the portal.
    tok = credentials.mint(
        subject="mr-agent-1", grant_id="g-main", delegation_id="d-agent1"
    )
    served = Portal("rls").read_shipments(tok)
    print(f"rows the portal serves this agent:      {len(served.row_ids)}")

    with admin_conn() as conn:
        conn.execute("ANALYZE portal.shipment")
        true_total = conn.execute(
            "SELECT count(*) AS n FROM portal.shipment"
        ).fetchone()["n"]
    print(f"rows that actually exist in the table:  {true_total}")

    # Now the leak, as the application role, which has NO privilege on the table.
    with psycopg.connect(app_url(), autocommit=True, row_factory=dict_row) as c:
        try:
            c.execute("SELECT count(*) FROM portal.shipment")
            print("UNEXPECTED: portal_app read the base table")
            return 1
        except psycopg.errors.InsufficientPrivilege:
            print("portal_app SELECT on the base table:    permission denied  (as designed)")

        est = c.execute(
            "SELECT reltuples::bigint AS n FROM pg_class WHERE oid='portal.shipment'::regclass"
        ).fetchone()["n"]
        print(f"portal_app pg_class.reltuples:          {est}  <-- LEAKS the true total")

        stats = c.execute(
            "SELECT count(*) AS n FROM pg_stats "
            "WHERE schemaname='portal' AND tablename='shipment'"
        ).fetchone()["n"]
        print(f"portal_app pg_stats column stats rows:  {stats}  (correctly hidden)")

    print()
    print("Finding: RLS hides row CONTENTS, not relation CARDINALITY. A partner")
    print("who can reach the catalog learns that 24 rows exist while being served")
    print("5. Column-level statistics (histograms, MCVs) are correctly withheld,")
    print("so the values themselves do not leak this way — only the count.")
    print()
    print("Mitigation actually in place: partners never receive a database")
    print("connection. They call the read API, which exposes no catalog surface.")
    print("The leak requires SQL access that the deployment does not grant, which")
    print("is why it is listed as an accepted limitation rather than a fixed bug.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
