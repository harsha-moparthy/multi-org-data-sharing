from __future__ import annotations

import pytest

from sharing.db import close_pool, init_schema


@pytest.fixture(scope="session", autouse=True)
def schema():
    """Build the schema and seed once per session.

    Tests that mutate governance state (revoking, expiring, disabling) restore it
    themselves; the ones that cannot are marked and reseed.
    """
    init_schema()
    yield
    close_pool()


@pytest.fixture
def fresh():
    """For tests that need a pristine fixture."""
    init_schema()
    yield
