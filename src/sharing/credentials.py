"""Delegated credentials: short-lived, scoped, signed, carrying the chain.

A credential is ``base64(json_claims).hex(hmac_sha256(base64_claims, key))``.

Three properties matter, and each is a deliberate choice:

1. **The database verifies it, not the application.** ``portal.verify_credential``
   is a ``SECURITY DEFINER`` function reading a key table ``portal_app`` cannot
   select from. So the service that serves requests can *present* credentials
   but cannot mint one (probe Q6), and an application bug cannot promote a
   caller.
2. **Expiry is inside the signed payload.** A holder cannot extend its own
   credential's life, because doing so invalidates the signature.
3. **The chain travels with the credential.** ``chain`` lists every hop from the
   grant's human grantee down to the acting agent. It is *not* trusted for
   authorization — ``current_auth()`` re-walks the chain against live database
   rows every time — but it makes the audit trail self-describing, so an
   auditor can see the claimed chain and the verified one side by side.

The minting functions live here rather than in the database because minting is
the *issuer's* job (an identity provider), while verification is the *resource
owner's*. Keeping them apart is why the app role can hold tokens safely.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid

DEFAULT_KID = "default"
# Short by default and short on purpose: the offline-revocation bound measured in
# `bench_revocation.py` *is* the credential lifetime, so a shorter TTL is the
# only thing that tightens it.
DEFAULT_TTL_SECONDS = 300


def signing_secret() -> bytes:
    """The HMAC key. From the environment so it is never committed."""
    return os.environ.get(
        "PORTAL_SIGNING_KEY", "dev-signing-key-not-a-real-secret"
    ).encode()


def plant_signing_key(conn) -> None:
    """Install the signing key into the (app-unreadable) key table."""
    conn.execute("SET ROLE portal_owner")
    conn.execute(
        """
        INSERT INTO portal.signing_key (kid, secret) VALUES (%s, %s)
        ON CONFLICT (kid) DO UPDATE SET secret = EXCLUDED.secret
        """,
        (DEFAULT_KID, signing_secret()),
    )
    conn.execute("RESET ROLE")


def _sign(payload_b64: str) -> str:
    return hmac.new(signing_secret(), payload_b64.encode(), hashlib.sha256).hexdigest()


def _encode(claims: dict) -> str:
    raw = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode()
    # Postgres `decode(..., 'base64')` accepts standard base64; keep the padding.
    return base64.b64encode(raw).decode()


def mint(
    *,
    subject: str,
    grant_id: str,
    delegation_id: str | None = None,
    chain: list[dict] | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    kid: str = DEFAULT_KID,
    audit_org: str | None = None,
    exp: float | None = None,
) -> str:
    """Mint a credential. ``exp`` is exposed so tests can create expired ones."""
    claims = {
        "sub": subject,
        "grant_id": grant_id,
        "delegation_id": delegation_id,
        "chain": chain or [],
        "jti": uuid.uuid4().hex,
        "kid": kid,
        "exp": exp if exp is not None else time.time() + ttl_seconds,
    }
    if audit_org is not None:
        claims["audit_org"] = audit_org
    payload = _encode(claims)
    return f"{payload}.{_sign(payload)}"


def mint_audit(*, subject: str, org: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> str:
    """A credential for reading one org's side of the audit trail."""
    return mint(
        subject=subject, grant_id="-", audit_org=org, ttl_seconds=ttl_seconds
    )


def decode_unverified(token: str) -> dict | None:
    """Read the claims WITHOUT checking the signature.

    Only for display and for attack construction. Named to make misuse obvious.
    """
    try:
        payload = token.split(".")[0]
        return json.loads(base64.b64decode(payload))
    except Exception:
        return None


def tamper(token: str, **claim_overrides) -> str:
    """Rewrite claims and keep the ORIGINAL signature — a forged credential.

    Used by the attack suite. The result must always be rejected: the signature
    no longer matches the payload.
    """
    claims = decode_unverified(token) or {}
    claims.update(claim_overrides)
    original_sig = token.split(".")[1] if "." in token else "deadbeef"
    return f"{_encode(claims)}.{original_sig}"


def forge_with_wrong_key(key: bytes, **kwargs) -> str:
    """Mint a well-formed credential with the WRONG key: must be rejected."""
    real = signing_secret()
    os.environ["PORTAL_SIGNING_KEY"] = key.decode()
    try:
        return mint(**kwargs)
    finally:
        os.environ["PORTAL_SIGNING_KEY"] = real.decode()
