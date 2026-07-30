"""Credential verification, including the failure modes that must fail closed."""

from __future__ import annotations

import time

from sharing import credentials
from sharing.db import admin_conn


def _verify(tok):
    with admin_conn() as conn:
        return conn.execute(
            "SELECT portal.verify_credential(%s) AS c", (tok,)
        ).fetchone()["c"]


def test_valid_credential_verifies():
    tok = credentials.mint(subject="mr-priya", grant_id="g-main")
    claims = _verify(tok)
    assert claims is not None
    assert claims["sub"] == "mr-priya"


def test_python_and_postgres_agree_on_the_signature():
    """The two implementations must produce byte-identical HMACs.

    They use different code paths (hmac.new vs pgcrypto's hmac over convert_to),
    so this is a real compatibility check, not a tautology.
    """
    tok = credentials.mint(subject="mr-priya", grant_id="g-main")
    payload, sig = tok.split(".")
    with admin_conn() as conn:
        conn.execute("SET ROLE portal_owner")
        pg_sig = conn.execute(
            "SELECT encode(ext.hmac(convert_to(%s,'utf8'), secret, 'sha256'),'hex') AS s "
            "FROM portal.signing_key WHERE kid='default'",
            (payload,),
        ).fetchone()["s"]
        conn.execute("RESET ROLE")
    assert pg_sig == sig


def test_tampered_claims_fail_closed_returning_null():
    """Not an error — NULL, so a forged token is indistinguishable from none."""
    tok = credentials.mint(subject="mr-agent-1", grant_id="g-main",
                           delegation_id="d-agent1")
    forged = credentials.tamper(tok, sub="mr-priya")
    assert _verify(forged) is None


def test_expired_credential_rejected():
    tok = credentials.mint(subject="mr-priya", grant_id="g-main",
                           exp=time.time() - 1)
    assert _verify(tok) is None


def test_wrong_key_rejected():
    tok = credentials.forge_with_wrong_key(
        b"not-the-real-key", subject="mr-priya", grant_id="g-main"
    )
    assert _verify(tok) is None


def test_malformed_inputs_all_return_null():
    for bad in ["", "no-dot", "a.b.c", "!!!.###", "eyJhIjoxfQ==.deadbeef",
                "....", "null.null"]:
        assert _verify(bad) is None, f"{bad!r} should not verify"


def test_none_credential_returns_null():
    assert _verify(None) is None


def test_unknown_key_id_rejected():
    tok = credentials.mint(subject="mr-priya", grant_id="g-main", kid="no-such-key")
    assert _verify(tok) is None


def test_credential_is_transaction_local_and_does_not_leak(monkeypatch):
    """A session-level identity GUC would leak across pooled checkouts.

    Asserted directly rather than assumed: after the authorized block exits, a
    read on the same pool must see nothing.
    """
    from sharing.db import app_pool, authorized

    tok = credentials.mint(subject="mr-priya", grant_id="g-main")
    with authorized(tok) as conn:
        n = conn.execute("SELECT count(*) AS n FROM portal.shared_shipment").fetchone()["n"]
    assert n == 8

    # Same pool, no credential: must be empty, and the GUC must be gone.
    with app_pool().connection() as conn, conn.transaction():
        leaked = conn.execute(
            "SELECT coalesce(current_setting('portal.credential', true),'') AS c"
        ).fetchone()["c"]
        n2 = conn.execute(
            "SELECT count(*) AS n FROM portal.shared_shipment"
        ).fetchone()["n"]
    assert leaked == "", f"the credential leaked to the next checkout: {leaked!r}"
    assert n2 == 0, "a connection with no credential served rows"


def test_audit_credential_cannot_be_forged_to_another_org():
    """viewer_org() must come from a signed claim, not an assertable GUC."""
    from sharing.db import authorized

    real = credentials.mint_audit(subject="mr-priya", org="meridian")
    forged = credentials.tamper(real, audit_org="northwind")
    with authorized(None, audit_credential=forged) as conn:
        n = conn.execute(
            "SELECT count(*) AS n FROM portal.audit_provider_view"
        ).fetchone()["n"]
        org = conn.execute("SELECT portal.viewer_org() AS o").fetchone()["o"]
    assert org is None
    assert n == 0


def test_audit_credential_subject_must_be_a_human_in_that_org():
    """A validly-signed credential naming the wrong org for its subject fails."""
    from sharing.db import authorized

    # co-lena is in contoso, not meridian: signed correctly but inconsistent.
    tok = credentials.mint_audit(subject="co-lena", org="meridian")
    with authorized(None, audit_credential=tok) as conn:
        org = conn.execute("SELECT portal.viewer_org() AS o").fetchone()["o"]
    assert org is None
