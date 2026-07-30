"""The sharing portal: two enforcement arms over identical data and grants.

``arm="rls"``       — the database enforces. The app reads
                     ``portal.shared_shipment`` as ``portal_app`` (no base-table
                     privileges) and adds no filtering of its own.

``arm="appfilter"`` — the application enforces. It reads the base table through
                     a privileged connection and applies the grant's row and
                     column limits in Python.

The second arm is the control, and it is written to be *fair*: it implements
every rule the RLS policy implements — region scope, classification ceiling,
partner-org restriction, column masking, grant liveness, delegation expiry — in
straightforward, competent Python. It is not a strawman with a rule left out.
The point of the comparison is that the two arms diverge anyway, on request
shapes whose filtering the application never sees, because "filter the rows we
return" and "the database will not serve these rows" are different guarantees.

A handicapped baseline would make the result worth less, not more.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Literal

from psycopg import sql

from sharing import credentials
from sharing.db import admin_url, app_pool, authorized

Arm = Literal["rls", "appfilter"]

# The columns a caller can ask for. Split by the capability that unlocks them.
BASE_COLUMNS = [
    "shipment_id",
    "owner_org",
    "region",
    "classification",
    "partner_org",
    "carrier",
    "status",
    "units",
    "updated_at",
]
COST_COLUMNS = ["unit_cost_usd", "margin_pct"]
CONTACT_COLUMNS = ["contact_email", "contact_phone"]
ALL_COLUMNS = BASE_COLUMNS + COST_COLUMNS + CONTACT_COLUMNS


@dataclass
class Result:
    """The outcome of one request, in a shape both arms produce identically."""

    decision: str  # allow | deny
    rows: list[dict[str, Any]] = field(default_factory=list)
    deny_reason: str | None = None
    columns_served: list[str] = field(default_factory=list)
    columns_masked: list[str] = field(default_factory=list)
    audit_seq: int | None = None
    elapsed_ms: float = 0.0

    @property
    def row_ids(self) -> list[int]:
        return sorted(r["shipment_id"] for r in self.rows)

    def visible_values(self) -> set[tuple[int, str, Any]]:
        """Every (row, column, value) actually handed to the caller.

        Comparing arms on this — rather than on row counts — is what catches a
        masked column that leaked its value while the row count looked right.
        """
        out = set()
        for r in self.rows:
            for k, v in r.items():
                if v is not None:
                    out.add((r["shipment_id"], k, str(v)))
        return out


class Portal:
    """Serves data requests under a delegated credential."""

    def __init__(self, arm: Arm = "rls"):
        self.arm = arm

    # -- the public API -----------------------------------------------------
    def read_shipments(
        self,
        credential: str,
        *,
        columns: list[str] | None = None,
        where: str | None = None,
        params: tuple | None = None,
        order_by: str | None = None,
        limit: int | None = None,
        aggregate: str | None = None,
    ) -> Result:
        """Read shared shipment rows.

        ``where``/``aggregate`` are the interesting part of the threat model: a
        partner's query is not limited to "give me my rows". It can carry
        predicates, joins and aggregates, which is where application-level
        filtering starts to differ from database enforcement.
        """
        t0 = time.perf_counter()
        cols = columns or BASE_COLUMNS
        bad = [c for c in cols if c not in ALL_COLUMNS]
        if bad:
            return self._deny(credential, f"unknown columns: {bad}", cols, t0)

        if self.arm == "rls":
            res = self._read_rls(credential, cols, where, params, order_by, limit, aggregate)
        else:
            res = self._read_appfilter(
                credential, cols, where, params, order_by, limit, aggregate
            )
        res.elapsed_ms = (time.perf_counter() - t0) * 1000
        return res

    # -- arm 1: the database enforces ---------------------------------------
    def _read_rls(
        self, credential, cols, where, params, order_by, limit, aggregate
    ) -> Result:
        # Note what is absent: no region check, no classification check, no
        # partner check, no column masking, no grant-liveness check. All of it
        # is in the database. The app's job is to pass the credential through.
        with authorized(credential) as conn:
            auth = conn.execute("SELECT * FROM portal.current_auth()").fetchone()
            if auth is None:
                return self._audit_deny(
                    conn, credential, "no_live_authorization", cols
                )

            select_list = sql.SQL(", ").join(sql.Identifier(c) for c in cols)
            if aggregate:
                select_list = sql.SQL(aggregate)  # trusted shape, see cli/tests
            q = sql.SQL("SELECT {} FROM portal.shared_shipment").format(select_list)
            if where:
                q = q + sql.SQL(" WHERE ") + sql.SQL(where)
            if order_by:
                q = q + sql.SQL(" ORDER BY ") + sql.SQL(order_by)
            if limit:
                q = q + sql.SQL(" LIMIT {}").format(sql.Literal(limit))
            rows = conn.execute(q, params).fetchall()

            served, masked = self._column_split(cols, auth)
            seq = self._audit(
                conn,
                auth=auth,
                credential=credential,
                request={
                    "columns": cols,
                    "where": where,
                    "params": list(params or ()),
                    "aggregate": aggregate,
                    "limit": limit,
                },
                decision="allow",
                rows=rows,
                served=served,
                masked=masked,
            )
            return Result(
                decision="allow",
                rows=rows,
                columns_served=served,
                columns_masked=masked,
                audit_seq=seq,
            )

    # -- arm 2: the application enforces (the control) ----------------------
    def _read_appfilter(
        self, credential, cols, where, params, order_by, limit, aggregate
    ) -> Result:
        """Competent application-level enforcement over a privileged connection.

        This is what a careful engineer writes when RLS is not available: read
        the base table, then apply every rule from the grant in code.
        """
        import psycopg
        from psycopg.rows import dict_row

        # A privileged connection: this arm cannot use portal_app, because
        # portal_app has no access to the base table. That is itself the point —
        # the control arm structurally requires broader database privileges.
        with psycopg.connect(admin_url(), autocommit=True, row_factory=dict_row) as conn:
            auth = self._auth_appside(conn, credential)
            if auth is None:
                return self._audit_deny(conn, credential, "no_live_authorization", cols)

            # The application's filter: every rule the RLS policy has.
            clauses = [
                "owner_org = %(provider)s",
                "region = ANY(%(regions)s)",
                "portal.class_rank(classification) <= portal.class_rank(%(maxclass)s)",
                "(partner_org IS NULL OR partner_org = %(grantee)s)",
            ]
            p: dict[str, Any] = {
                "provider": auth["provider_org"],
                "regions": list(auth["region_scope"]),
                "maxclass": auth["max_classification"],
                "grantee": auth["grantee_org"],
            }
            select_list = ", ".join(f'"{c}"' for c in cols)
            if aggregate:
                select_list = aggregate
            q = f"SELECT {select_list} FROM portal.shipment WHERE " + " AND ".join(clauses)
            if where:
                # The caller's predicate, appended to ours. Positional params for
                # the caller's part, named for ours — psycopg allows only one
                # style per query, so the caller's params are inlined by the
                # caller-side helper in the same way the RLS arm passes them.
                q += f" AND ({where})"
            if order_by:
                q += f" ORDER BY {order_by}"
            if limit:
                q += f" LIMIT {int(limit)}"

            merged: Any = p
            if params:
                # Merge positional caller params into the named dict by rewriting
                # the caller's %s into named placeholders, preserving order.
                for i, v in enumerate(params):
                    key = f"cp{i}"
                    q = q.replace("%s", f"%({key})s", 1)
                    p[key] = v
            rows = conn.execute(q, merged).fetchall()

            served, masked = self._column_split(cols, auth)
            # Application-side column masking.
            for r in rows:
                for c in masked:
                    if c in r:
                        r[c] = None

            seq = self._audit(
                conn,
                auth=auth,
                credential=credential,
                request={
                    "columns": cols,
                    "where": where,
                    "params": list(params or ()),
                    "aggregate": aggregate,
                    "limit": limit,
                },
                decision="allow",
                rows=rows,
                served=served,
                masked=masked,
            )
            return Result(
                decision="allow",
                rows=rows,
                columns_served=served,
                columns_masked=masked,
                audit_seq=seq,
            )

    def _auth_appside(self, conn, credential) -> dict | None:
        """Resolve authorization for the control arm.

        Uses the same ``current_auth()`` resolution as the RLS arm, so the two
        arms cannot differ merely because one has a weaker idea of who the caller
        is. The difference under test is *where the row/column limits are
        applied*, not whose credential logic is better.
        """
        with conn.transaction():
            conn.execute("SELECT set_config('portal.credential', %s, true)", (credential,))
            return conn.execute("SELECT * FROM portal.current_auth()").fetchone()

    # -- shared helpers ----------------------------------------------------
    @staticmethod
    def _column_split(cols, auth) -> tuple[list[str], list[str]]:
        """Split requested columns into served and masked.

        Spelled out per capability rather than as one boolean expression: this
        function decides what a partner is allowed to see, so it should be
        readable without working out `and`/`or` precedence.
        """
        capability_for = {
            **{c: "allow_cost" for c in COST_COLUMNS},
            **{c: "allow_contact" for c in CONTACT_COLUMNS},
        }
        served, masked = [], []
        for c in cols:
            cap = capability_for.get(c)
            if cap is not None and not auth[cap]:
                masked.append(c)
            else:
                served.append(c)
        return served, masked

    def _audit(
        self, conn, *, auth, credential, request, decision, rows, served, masked
    ) -> int | None:
        claims = credentials.decode_unverified(credential) or {}
        row_ids = [r["shipment_id"] for r in rows if "shipment_id" in r]
        # Via the definer function: portal_app holds no privilege on audit_event.
        rec = conn.execute(
            "SELECT portal.audit_append(%s,%s,%s,%s,%s,%s,%s,'read','shipment',"
            "%s,%s,NULL,%s,%s,%s,%s) AS seq",
            (
                auth["subject"],
                auth["acting_for"],
                auth["grant_id"],
                auth["delegation_id"],
                json.dumps(claims.get("chain", [])),
                auth["provider_org"],
                auth["grantee_org"],
                json.dumps({**request, "arm": self.arm}),
                decision,
                len(rows),
                row_ids,
                served,
                masked,
            ),
        ).fetchone()
        return rec["seq"] if rec else None

    def _audit_deny(self, conn, credential, reason, cols) -> Result:
        """Record a denial.

        A denial is audited with whatever the credential *claimed*, since by
        definition there is no verified authorization to attribute it to. This
        is why ``subject`` is nullable: an unattributable access attempt must
        still leave a trace, and it must be visibly unattributed rather than
        borrowing a plausible identity.
        """
        claims = credentials.decode_unverified(credential) or {}
        # subject is NULL: the request had no verifiable identity, so the row is
        # visibly unattributed rather than borrowing whatever the token claimed.
        # The claimed subject is preserved inside `request` for the investigation.
        rec = conn.execute(
            "SELECT portal.audit_append(NULL,NULL,%s,%s,%s,NULL,NULL,'read',"
            "'shipment',%s,'deny',%s,0,NULL,NULL,NULL) AS seq",
            (
                claims.get("grant_id"),
                claims.get("delegation_id"),
                json.dumps(claims.get("chain", [])),
                json.dumps({"columns": cols, "claimed_sub": claims.get("sub"),
                            "arm": self.arm}),
                reason,
            ),
        ).fetchone()
        return Result(
            decision="deny", deny_reason=reason, audit_seq=rec["seq"] if rec else None
        )

    def _deny(self, credential, reason, cols, t0) -> Result:
        with app_pool().connection() as conn, conn.transaction():
            res = self._audit_deny(conn, credential, reason, cols)
        res.elapsed_ms = (time.perf_counter() - t0) * 1000
        return res
