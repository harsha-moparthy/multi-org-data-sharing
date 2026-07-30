"""Database access.

Two connection identities, deliberately separated:

* ``admin_conn`` — the bootstrap superuser. Used only by ``portal init`` to
  create the schema and by test fixtures to plant scenarios. Never used to
  serve a data request.
* ``app_pool`` — connects as ``portal_app``, which holds **no privileges on any
  base table**. This is what serves every read. If a query escapes the guarded
  views, it fails at Postgres.

The distinction is the project's core claim, so it is structural here rather
than a convention someone has to remember.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

REPO_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = "5435"
DEFAULT_DB = "sharing"
DEFAULT_ADMIN_USER = "shareadmin"
DEFAULT_APP_USER = "portal_app"


def _url(user: str) -> str:
    host = os.environ.get("PGHOST", DEFAULT_HOST)
    port = os.environ.get("PGPORT", DEFAULT_PORT)
    db = os.environ.get("PGDATABASE", DEFAULT_DB)
    return f"postgresql://{user}@{host}:{port}/{db}"


def admin_url() -> str:
    return os.environ.get("ADMIN_URL") or _url(
        os.environ.get("PGUSER", DEFAULT_ADMIN_USER)
    )


def app_url() -> str:
    return os.environ.get("APP_URL") or _url(DEFAULT_APP_USER)


@contextmanager
def admin_conn() -> Iterator[psycopg.Connection]:
    """A superuser connection. Schema management and test setup only."""
    with psycopg.connect(admin_url(), autocommit=True, row_factory=dict_row) as conn:
        yield conn


_pool: ConnectionPool | None = None


def app_pool() -> ConnectionPool:
    """Pooled ``portal_app`` connections — the only identity that serves reads."""
    global _pool
    if _pool is None:
        _pool = ConnectionPool(
            app_url(),
            min_size=1,
            max_size=4,
            kwargs={"autocommit": True, "row_factory": dict_row},
            open=True,
        )
    return _pool


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None


@contextmanager
def authorized(credential: str | None, *, audit_credential: str | None = None):
    """Run a block with a credential bound to *this transaction only*.

    The ``true`` third argument to ``set_config`` is load-bearing. A
    session-level setting survives ``pool.connection()`` returning the
    connection and leaks to whoever checks it out next — with an identity GUC
    that means the next caller inherits the previous caller's authorization.
    Under ``autocommit=True`` a transaction-local setting needs an explicit
    transaction to be local to, hence the ``conn.transaction()`` block; without
    it the setting silently behaves as session-level.
    """
    pool = app_pool()
    with pool.connection() as conn, conn.transaction():
        if credential is not None:
            conn.execute("SELECT set_config('portal.credential', %s, true)", (credential,))
        if audit_credential is not None:
            conn.execute(
                "SELECT set_config('portal.audit_credential', %s, true)", (audit_credential,)
            )
        yield conn


def init_schema(*, seed: bool = True) -> None:
    """Create the schema (and optionally the seeded scenario) from scratch."""
    here = Path(__file__).resolve().parent
    with admin_conn() as conn:
        conn.execute((here / "schema.sql").read_text())
        # The signing key is planted separately: it must not live in a file that
        # gets committed, and in CI it comes from the environment.
        from sharing.credentials import plant_signing_key

        plant_signing_key(conn)
        if seed:
            conn.execute((here / "seed.sql").read_text())
