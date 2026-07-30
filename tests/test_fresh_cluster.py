"""The schema must apply to a cluster that has never seen it.

This exists because of a real escape. `GRANT USAGE ON SCHEMA ext TO
portal_owner` sat above the block that CREATEs portal_owner. Every local run
passed, because the roles already existed from a previous run; CI failed on the
first genuinely fresh Postgres with `role "portal_owner" does not exist`.

"Works on my machine" was literally true and completely useless. So the property
under test is idempotency-from-nothing: drop the roles and everything they own,
then apply the schema and confirm it succeeds.
"""

from __future__ import annotations

import psycopg
import pytest
from psycopg.rows import dict_row

from sharing.db import admin_url, close_pool, init_schema

ROLES = ["portal_app", "portal_owner"]


@pytest.fixture
def dropped_roles():
    """Remove the portal roles entirely, then restore the world afterwards."""
    with psycopg.connect(admin_url(), autocommit=True, row_factory=dict_row) as c:
        # The pool may hold portal_app sessions; they block DROP ROLE.
        close_pool()
        c.execute("DROP SCHEMA IF EXISTS portal CASCADE")
        for role in ROLES:
            exists = c.execute(
                "SELECT 1 FROM pg_roles WHERE rolname=%s", (role,)
            ).fetchone()
            if exists:
                c.execute(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE usename = %s AND pid <> pg_backend_pid()",
                    (role,),
                )
                c.execute(f"DROP OWNED BY {role} CASCADE")
                c.execute(f"DROP ROLE {role}")
    yield
    # Leave a working database behind for whatever runs next.
    init_schema()


def _roles_present() -> set[str]:
    with psycopg.connect(admin_url(), autocommit=True, row_factory=dict_row) as c:
        rows = c.execute(
            "SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)", (ROLES,)
        ).fetchall()
    return {r["rolname"] for r in rows}


def test_schema_applies_with_no_preexisting_roles(dropped_roles):
    """The exact condition CI hit and every local run had already papered over."""
    assert _roles_present() == set(), "the fixture did not actually drop the roles"

    init_schema()  # must not raise

    assert _roles_present() == set(ROLES)


def test_schema_is_reappliable_over_itself(dropped_roles):
    """And it must still be safe to run twice, which is the normal case."""
    init_schema()
    init_schema()
    assert _roles_present() == set(ROLES)

    # the seeded scenario is intact, not doubled
    with psycopg.connect(admin_url(), autocommit=True, row_factory=dict_row) as c:
        n = c.execute("SELECT count(*) AS n FROM portal.shipment").fetchone()["n"]
    assert n == 24, f"reapplying the schema left {n} shipment rows, expected 24"


def test_every_grant_names_a_role_that_already_exists():
    """Structural guard: no GRANT may precede the roles it references.

    Cheaper than provisioning a cluster, and it fails on the *next* such mistake
    rather than only on this one.
    """
    import pathlib
    import re

    sql = pathlib.Path("src/sharing/schema.sql").read_text()
    role_creation = sql.find("CREATE ROLE portal_owner")
    assert role_creation > 0, "could not locate role creation in schema.sql"

    for m in re.finditer(r"^\s*GRANT\b.*?;", sql, re.M | re.S):
        if "portal_owner" in m.group(0) or "portal_app" in m.group(0):
            assert m.start() > role_creation, (
                "a GRANT to portal_owner/portal_app appears at offset "
                f"{m.start()}, before the roles are created at {role_creation}. "
                "This passes on any cluster where a previous run created the "
                "roles and fails only on a fresh one:\n" + m.group(0).strip()
            )
