"""Every sensitive column in the shared view must be guarded by a CASE.

The RLS arm's immunity to the three side channels in
``results/side_channel_analysis.md`` is a property of masking *in the view's
target list*. A column added later without its guard would silently reopen all
three, and no attack in the suite would notice, because the suite probes the
specific columns that exist today.

So this test reads the view definition and asserts the invariant structurally.
"""

from __future__ import annotations

from sharing.db import admin_conn
from sharing.portal import CONTACT_COLUMNS, COST_COLUMNS


def _view_def() -> str:
    with admin_conn() as conn:
        return conn.execute(
            "SELECT pg_get_viewdef('portal.shared_shipment'::regclass, true) AS d"
        ).fetchone()["d"]


def test_every_sensitive_column_is_masked_by_a_case():
    d = _view_def()
    for col in (*COST_COLUMNS, *CONTACT_COLUMNS):
        assert col in d, f"{col} is missing from the shared view entirely"
        # The column must appear inside a CASE guarded by the matching capability.
        cap = "allow_cost" if col in COST_COLUMNS else "allow_contact"
        # Find the fragment of the definition that projects this column.
        idx = d.index(f"AS {col}") if f"AS {col}" in d else d.index(col)
        window = d[max(0, idx - 260) : idx + 40]
        assert "CASE" in window, f"{col} is projected without a CASE guard: {window!r}"
        assert cap in window, (
            f"{col} is not guarded by {cap}; a caller without that capability "
            f"would receive the real value. Fragment: {window!r}"
        )


def test_sensitive_columns_are_not_in_the_views_where_clause():
    """A sensitive column used in the view's own WHERE would defeat masking."""
    d = _view_def().lower()
    where = d.split("where", 1)[1] if "where" in d else ""
    for col in (*COST_COLUMNS, *CONTACT_COLUMNS):
        assert col not in where, f"{col} appears in the view's WHERE clause"


def test_view_reads_current_auth_not_a_bare_guc():
    """Authorization must come from the verified credential, not an assertable GUC."""
    d = _view_def()
    assert "current_auth()" in d, "the view no longer derives authorization from current_auth()"
    assert "portal.credential" not in d, (
        "the view reads the credential GUC directly instead of going through "
        "verify_credential(); an app-set GUC is forgeable"
    )


def test_policy_exists_and_is_for_select_only():
    with admin_conn() as conn:
        rows = conn.execute(
            "SELECT polname, polcmd FROM pg_policy "
            "WHERE polrelid='portal.shipment'::regclass"
        ).fetchall()
    assert rows, "the shipment RLS policy is gone"
    # 'r' = SELECT. No write policy should exist: the portal is a read path.
    assert {r["polcmd"] for r in rows} == {"r"}, (
        f"unexpected policy commands {[r['polcmd'] for r in rows]}; a write policy "
        "would let the read path mutate provider data"
    )
