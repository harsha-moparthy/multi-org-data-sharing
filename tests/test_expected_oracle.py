"""Tests for the oracle itself.

The oracle is what makes every other assertion meaningful, so it gets its own
tests. If it silently returned "no rows expected" for everything, the positive
controls would pass vacuously.
"""

from __future__ import annotations

from sharing.db import admin_conn
from sharing.expected import expect_for
from sharing.portal import ALL_COLUMNS


def _exp(**kw):
    with admin_conn() as conn:
        return expect_for(conn, requested_columns=ALL_COLUMNS, **kw)


def test_oracle_returns_a_specific_non_empty_answer():
    e = _exp(subject="mr-priya", grant_id="g-main", delegation_id=None)
    assert e is not None
    assert e.row_ids == [1001, 1002, 1003, 1005, 1006, 1010, 1011, 1013]
    assert e.masked_columns == {"contact_email", "contact_phone"}


def test_oracle_excludes_the_specific_rows_it_should():
    e = _exp(subject="mr-priya", grant_id="g-main", delegation_id=None)
    # restricted classification
    assert 1004 not in e.row_ids and 1012 not in e.row_ids
    # another partner's rows
    for r in (1007, 1008, 1009, 1014):
        assert r not in e.row_ids
    # out of region
    for r in (1015, 1016, 1017, 1018, 1019):
        assert r not in e.row_ids
    # another provider's data
    for r in (2001, 2002, 3001, 3002, 3003):
        assert r not in e.row_ids


def test_oracle_narrows_for_a_delegated_agent():
    human = _exp(subject="mr-priya", grant_id="g-main", delegation_id=None)
    agent = _exp(subject="mr-agent-1", grant_id="g-main", delegation_id="d-agent1")
    assert set(agent.row_ids) < set(human.row_ids), "the agent should see strictly less"
    assert agent.masked_columns > human.masked_columns


def test_oracle_denies_the_cases_that_must_be_denied():
    # unapproved grant
    assert _exp(subject="mr-priya", grant_id="g-unapproved", delegation_id=None) is None
    # agent claiming a grant directly
    assert _exp(subject="mr-agent-1", grant_id="g-main", delegation_id=None) is None
    # wrong subject for the delegation
    assert _exp(subject="mr-agent-x", grant_id="g-main", delegation_id="d-agent1") is None
    # nonexistent grant
    assert _exp(subject="mr-priya", grant_id="nope", delegation_id=None) is None


def test_oracle_is_independent_of_the_views():
    """It must not consult the guarded view or current_auth().

    Otherwise it would agree with the system by construction and could never
    catch a policy bug.
    """
    import ast
    import pathlib

    src = pathlib.Path("src/sharing/expected.py").read_text()
    # Check executable code only. The module docstring names these very objects
    # in order to explain that it does not use them, so a plain substring search
    # over the file matches its own documentation.
    tree = ast.parse(src)
    # Delete every docstring node in place, then unparse what remains: whatever
    # survives is code the interpreter actually runs.
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(body, list) and body:
            first = body[0]
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                body.pop(0)
    haystack = ast.unparse(tree)

    for forbidden in ("shared_shipment", "current_auth", "portal.credential"):
        assert forbidden not in haystack, (
            f"the oracle references {forbidden} in executable code; it is no "
            "longer independent of the system it checks"
        )
    # It must read the base tables directly — that is what independence means.
    assert "portal.shipment" in haystack
    assert "portal.data_grant" in haystack
