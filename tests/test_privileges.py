"""The structural claims about database privileges.

These are the tests that make the README's central sentence checkable rather than
aspirational: "the application role holds no privileges on any base table". If
someone later adds a convenient GRANT, this fails.
"""

from __future__ import annotations

import psycopg
import pytest
from psycopg.rows import dict_row

from sharing.db import admin_conn, app_url

BASE_TABLES = [
    "shipment",
    "data_grant",
    "delegation",
    "principal",
    "org",
    "signing_key",
    "audit_event",
]

PRIVS = ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]


def test_app_role_has_no_privilege_on_any_base_table():
    with admin_conn() as conn:
        rows = conn.execute(
            """
            SELECT table_name, privilege_type
              FROM information_schema.role_table_grants
             WHERE grantee = 'portal_app' AND table_schema = 'portal'
               AND table_name = ANY(%s)
            """,
            (BASE_TABLES,),
        ).fetchall()
    assert rows == [], f"portal_app holds privileges it must not: {rows}"


def test_app_role_cannot_read_base_tables_in_practice():
    """Belt and braces: actually try, as the app role."""
    with psycopg.connect(app_url(), autocommit=True, row_factory=dict_row) as c:
        for t in BASE_TABLES:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute(f"SELECT * FROM portal.{t} LIMIT 1")


def test_app_role_cannot_read_the_signing_key():
    """The key is what makes credential verification meaningful."""
    with psycopg.connect(app_url(), autocommit=True, row_factory=dict_row) as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT secret FROM portal.signing_key")


def test_app_role_can_read_exactly_the_guarded_views():
    with admin_conn() as conn:
        rows = conn.execute(
            """
            SELECT table_name FROM information_schema.role_table_grants
             WHERE grantee='portal_app' AND table_schema='portal'
             ORDER BY table_name
            """
        ).fetchall()
    names = sorted({r["table_name"] for r in rows})
    assert names == [
        "audit_consumer_view",
        "audit_provider_view",
        "shared_shipment",
    ], f"unexpected grant set: {names}"


def test_app_role_is_not_superuser_and_cannot_bypass_rls():
    with admin_conn() as conn:
        r = conn.execute(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname='portal_app'"
        ).fetchone()
    assert r["rolsuper"] is False
    assert r["rolbypassrls"] is False


def test_owner_is_also_bound_by_rls():
    """FORCE ROW LEVEL SECURITY: the table owner gets no free pass."""
    with admin_conn() as conn:
        r = conn.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
            "WHERE oid='portal.shipment'::regclass"
        ).fetchone()
    assert r["relrowsecurity"] is True, "RLS is not enabled on shipment"
    assert r["relforcerowsecurity"] is True, "RLS is not FORCEd, so the owner bypasses it"


def test_shared_view_is_a_security_barrier():
    with admin_conn() as conn:
        r = conn.execute(
            "SELECT reloptions FROM pg_class WHERE oid='portal.shared_shipment'::regclass"
        ).fetchone()
    assert r["reloptions"] and any(
        "security_barrier=true" in o for o in r["reloptions"]
    ), f"shared_shipment lost its security_barrier: {r['reloptions']}"


def test_audit_append_is_the_only_write_path_for_the_app():
    """The app can append audit rows only through the definer function."""
    with psycopg.connect(app_url(), autocommit=True, row_factory=dict_row) as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(
                "INSERT INTO portal.audit_event (action, resource, request, decision) "
                "VALUES ('read','shipment','{}','allow')"
            )
        # but the function works
        r = c.execute(
            "SELECT portal.audit_append(NULL,NULL,NULL,NULL,NULL,NULL,NULL,"
            "'read','shipment','{}'::jsonb,'deny','test',0,NULL,NULL,NULL) AS seq"
        ).fetchone()
        assert r["seq"] > 0
