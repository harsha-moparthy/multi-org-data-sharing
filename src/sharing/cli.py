"""`portal` — the operator's interface to the sharing portal.

Enough surface to run an engagement: initialize, request/approve/revoke grants,
delegate to an agent, read as any principal, and inspect the audit trail from
either side of the share.
"""

from __future__ import annotations

import json
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from sharing import credentials
from sharing.db import admin_conn, authorized, close_pool, init_schema
from sharing.portal import ALL_COLUMNS, BASE_COLUMNS, Portal

app = typer.Typer(add_completion=False, help=__doc__)
console = Console()

grant_app = typer.Typer(help="Grant lifecycle: request, approve, revoke, list.")
deleg_app = typer.Typer(help="Delegated agent credentials.")
audit_app = typer.Typer(help="Audit trail, from either org's perspective.")
app.add_typer(grant_app, name="grant")
app.add_typer(deleg_app, name="delegation")
app.add_typer(audit_app, name="audit")


@app.command()
def init(
    seed: Annotated[bool, typer.Option(help="Load the two-org demo scenario")] = True,
):
    """Create the schema, roles, policies and (optionally) the demo data."""
    init_schema(seed=seed)
    console.print("[green]schema ready[/green]" + ("  (seeded)" if seed else ""))
    close_pool()


@app.command()
def whoami(credential: str):
    """Show the effective authorization a credential resolves to.

    This is what the database concludes, not what the token claims — the useful
    view when debugging why a partner sees fewer rows than they expect.
    """
    with authorized(credential) as conn:
        auth = conn.execute("SELECT * FROM portal.current_auth()").fetchone()
    if auth is None:
        console.print("[red]no live authorization[/red] — forged, expired, revoked, "
                      "or the chain is broken")
        raise typer.Exit(1)
    t = Table(show_header=False, box=None)
    for k, v in auth.items():
        t.add_row(f"[dim]{k}[/dim]", str(v))
    console.print(t)
    close_pool()


@app.command()
def read(
    credential: str,
    columns: Annotated[str, typer.Option(help="Comma-separated, or 'all'")] = "base",
    where: Annotated[str | None, typer.Option(help="Extra SQL predicate")] = None,
    arm: Annotated[str, typer.Option(help="rls | appfilter")] = "rls",
):
    """Read shared data under a credential."""
    cols = (
        ALL_COLUMNS if columns == "all"
        else BASE_COLUMNS if columns == "base"
        else [c.strip() for c in columns.split(",")]
    )
    portal = Portal(arm)  # type: ignore[arg-type]
    res = portal.read_shipments(credential, columns=cols, where=where)
    if res.decision == "deny":
        console.print(f"[red]denied[/red]: {res.deny_reason}  (audit seq {res.audit_seq})")
        raise typer.Exit(1)
    if not res.rows:
        console.print("[yellow]0 rows[/yellow] (authorized, but nothing matched)")
        return
    t = Table()
    for c in res.rows[0]:
        t.add_column(c)
    for r in res.rows:
        t.add_row(*["[dim]—[/dim]" if v is None else str(v) for v in r.values()])
    console.print(t)
    console.print(
        f"[dim]{len(res.rows)} rows · masked: "
        f"{', '.join(res.columns_masked) or 'none'} · audit seq {res.audit_seq} · "
        f"{res.elapsed_ms:.1f}ms[/dim]"
    )
    close_pool()


@app.command("token")
def mint_token(
    subject: str,
    grant: Annotated[str, typer.Option()] = "g-main",
    delegation: Annotated[str | None, typer.Option()] = None,
    ttl: Annotated[int, typer.Option(help="Seconds")] = 300,
):
    """Mint a credential (the identity-provider side of the system)."""
    print(credentials.mint(
        subject=subject, grant_id=grant, delegation_id=delegation, ttl_seconds=ttl
    ))


@app.command("audit-token")
def mint_audit_token(subject: str, org: str):
    """Mint a credential for reading one org's slice of the audit trail."""
    print(credentials.mint_audit(subject=subject, org=org))


# -- grants ----------------------------------------------------------------
@grant_app.command("list")
def grant_list():
    """All grants with their live/dead status."""
    with admin_conn() as conn:
        rows = conn.execute(
            "SELECT grant_id, provider_org, grantee_org, grantee_principal, "
            "region_scope, max_classification, allow_cost, allow_contact, "
            "approved_by, expires_at, revoked_at, "
            "portal.grant_is_live(d.*, now()) AS live "
            "FROM portal.data_grant d ORDER BY grant_id"
        ).fetchall()
    t = Table()
    for c in ("grant", "provider", "grantee", "principal", "regions", "max class",
              "cost", "contact", "approved by", "expires", "live"):
        t.add_column(c)
    for r in rows:
        t.add_row(
            r["grant_id"], r["provider_org"], r["grantee_org"], r["grantee_principal"],
            ",".join(r["region_scope"]), r["max_classification"],
            "yes" if r["allow_cost"] else "no", "yes" if r["allow_contact"] else "no",
            r["approved_by"] or "[red]unapproved[/red]",
            f"{r['expires_at']:%Y-%m-%d}",
            "[green]yes[/green]" if r["live"] else "[red]no[/red]",
        )
    console.print(t)


@grant_app.command("request")
def grant_request(
    grant_id: str,
    provider: str,
    grantee_org: str,
    grantee: str,
    regions: Annotated[str, typer.Option(help="Comma-separated")],
    max_class: Annotated[str, typer.Option()] = "internal",
    cost: Annotated[bool, typer.Option()] = False,
    contact: Annotated[bool, typer.Option()] = False,
    days: Annotated[int, typer.Option()] = 30,
):
    """Request a share. It is NOT usable until a provider human approves it."""
    with admin_conn() as conn:
        conn.execute(
            """
            INSERT INTO portal.data_grant
              (grant_id, provider_org, grantee_org, grantee_principal, region_scope,
               max_classification, allow_cost, allow_contact, expires_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s, now() + (%s || ' days')::interval)
            """,
            (grant_id, provider, grantee_org, grantee,
             [r.strip() for r in regions.split(",")], max_class, cost, contact, days),
        )
    console.print(f"[yellow]requested[/yellow] {grant_id} — awaiting provider approval")


@grant_app.command("approve")
def grant_approve(grant_id: str, approver: str):
    """Approve a share (must be a human in the provider org)."""
    with admin_conn() as conn:
        conn.execute("SELECT portal.approve_grant(%s,%s)", (grant_id, approver))
    console.print(f"[green]approved[/green] {grant_id} by {approver}")


@grant_app.command("revoke")
def grant_revoke(grant_id: str, actor: str, reason: str = "operator request"):
    """Revoke a share. Takes effect on the next request under it."""
    with admin_conn() as conn:
        conn.execute("SELECT portal.revoke_grant(%s,%s,%s)", (grant_id, actor, reason))
    console.print(f"[red]revoked[/red] {grant_id}: {reason}")


# -- delegations -----------------------------------------------------------
@deleg_app.command("list")
def deleg_list():
    with admin_conn() as conn:
        rows = conn.execute(
            "SELECT delegation_id, grant_id, delegator, delegatee, depth, "
            "parent_delegation, region_scope, allow_cost, allow_contact, purpose, "
            "expires_at, revoked_at FROM portal.delegation ORDER BY grant_id, depth"
        ).fetchall()
    t = Table()
    for c in ("delegation", "grant", "delegator", "delegatee", "depth", "parent",
              "regions", "cost", "purpose", "expires", "revoked"):
        t.add_column(c)
    for r in rows:
        t.add_row(
            r["delegation_id"], r["grant_id"], r["delegator"], r["delegatee"],
            str(r["depth"]), r["parent_delegation"] or "—",
            ",".join(r["region_scope"]), "yes" if r["allow_cost"] else "no",
            r["purpose"][:28], f"{r['expires_at']:%m-%d %H:%M}",
            "[red]yes[/red]" if r["revoked_at"] else "no",
        )
    console.print(t)


@deleg_app.command("create")
def deleg_create(
    delegation_id: str,
    grant_id: str,
    delegator: str,
    delegatee: str,
    purpose: Annotated[str, typer.Option()],
    regions: Annotated[str, typer.Option()],
    depth: Annotated[int, typer.Option()] = 1,
    parent: Annotated[str | None, typer.Option()] = None,
    cost: Annotated[bool, typer.Option()] = False,
    contact: Annotated[bool, typer.Option()] = False,
    hours: Annotated[int, typer.Option()] = 24,
):
    """Delegate to an agent. The database refuses anything that widens scope."""
    try:
        with admin_conn() as conn:
            conn.execute(
                """
                INSERT INTO portal.delegation
                  (delegation_id, grant_id, delegator, delegatee, depth,
                   parent_delegation, region_scope, allow_cost, allow_contact,
                   purpose, expires_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, now() + (%s || ' hours')::interval)
                """,
                (delegation_id, grant_id, delegator, delegatee, depth, parent,
                 [r.strip() for r in regions.split(",")], cost, contact, purpose, hours),
            )
    except Exception as exc:
        console.print(f"[red]refused by the database[/red]: {str(exc).splitlines()[0]}")
        raise typer.Exit(1) from exc
    console.print(f"[green]delegated[/green] {delegation_id}: {delegator} -> {delegatee}")


@deleg_app.command("revoke")
def deleg_revoke(delegation_id: str, actor: str, reason: str = "operator request"):
    """Revoke a delegation. Kills every credential below it in the chain too."""
    with admin_conn() as conn:
        conn.execute(
            "SELECT portal.revoke_delegation(%s,%s,%s)", (delegation_id, actor, reason)
        )
    console.print(f"[red]revoked[/red] {delegation_id}: {reason}")


@app.command("disable-principal")
def disable_principal(principal_id: str, enable: bool = False):
    """Offboard a person or agent: kills every delegation rooted at them.

    One command rather than a hand-written UPDATE, because offboarding is the
    procedure most likely to be run under time pressure by someone who is not
    the author.
    """
    with admin_conn() as conn:
        r = conn.execute(
            "UPDATE portal.principal SET disabled_at = %s WHERE principal_id = %s "
            "RETURNING principal_id, kind, disabled_at",
            (None if enable else "now()", principal_id),
        ).fetchone()
    if r is None:
        console.print(f"[red]no such principal[/red] {principal_id}")
        raise typer.Exit(1)
    if enable:
        console.print(f"[green]re-enabled[/green] {principal_id} ({r['kind']})")
    else:
        console.print(
            f"[red]disabled[/red] {principal_id} ({r['kind']}) — every credential "
            "in a chain through them now fails on its next request"
        )


# -- audit -----------------------------------------------------------------
@audit_app.command("trail")
def audit_trail(
    audit_credential: Annotated[str, typer.Argument(help="From `portal audit-token`")],
    side: Annotated[str, typer.Option(help="provider | consumer")] = "provider",
    limit: int = 30,
):
    """Show one org's slice of the audit trail."""
    view = "audit_provider_view" if side == "provider" else "audit_consumer_view"
    with authorized(None, audit_credential=audit_credential) as conn:
        org = conn.execute("SELECT portal.viewer_org() AS o").fetchone()["o"]
        if org is None:
            console.print("[red]invalid audit credential[/red]")
            raise typer.Exit(1)
        rows = conn.execute(
            f"SELECT seq, at, subject, acting_for, delegation_id, counterparty_org, "
            f"action, decision, deny_reason, row_count, columns_masked "
            f"FROM portal.{view} ORDER BY seq DESC LIMIT {int(limit)}"
        ).fetchall()
    console.print(f"[bold]{org}[/bold] — {side} view, {len(rows)} most recent events")
    t = Table()
    for c in ("seq", "at", "subject", "acting for", "delegation", "party",
              "action", "decision", "rows", "masked"):
        t.add_column(c)
    for r in reversed(rows):
        t.add_row(
            str(r["seq"]), f"{r['at']:%H:%M:%S}",
            r["subject"] or "[red]<unattributed>[/red]",
            r["acting_for"] or "—", r["delegation_id"] or "—",
            r["counterparty_org"] or "—", r["action"],
            "[green]allow[/green]" if r["decision"] == "allow"
            else f"[red]deny[/red] {r['deny_reason'] or ''}",
            str(r["row_count"] if r["row_count"] is not None else "—"),
            ",".join(r["columns_masked"] or []) or "—",
        )
    console.print(t)
    close_pool()


@audit_app.command("verify")
def audit_verify():
    """Verify the hash chain over the whole trail."""
    with admin_conn() as conn:
        r = conn.execute("SELECT * FROM portal.audit_verify()").fetchone()
    if r["first_bad_seq"] is None:
        console.print(f"[green]chain intact[/green] over {r['checked']} events")
    else:
        console.print(
            f"[red]chain broken[/red] at seq {r['first_bad_seq']} "
            f"(of {r['checked']} events)"
        )
        raise typer.Exit(1)


@audit_app.command("reconstruct")
def audit_reconstruct(seq: int):
    """Reconstruct one access in full: who, for whom, under what authority."""
    with admin_conn() as conn:
        e = conn.execute(
            "SELECT * FROM portal.audit_event WHERE seq=%s", (seq,)
        ).fetchone()
        if e is None:
            console.print(f"[red]no event {seq}[/red]")
            raise typer.Exit(1)
        chain = None
        if e["delegation_id"]:
            chain = conn.execute(
                "SELECT g.approved_by, g.grantee_principal, g.expires_at, "
                "d.delegator, d.delegatee, d.purpose, d.depth, d.expires_at AS d_exp "
                "FROM portal.data_grant g JOIN portal.delegation d "
                "ON d.grant_id=g.grant_id WHERE d.delegation_id=%s",
                (e["delegation_id"],),
            ).fetchone()

    t = Table(show_header=False, box=None)
    t.add_row("[dim]when[/dim]", str(e["at"]))
    t.add_row("[dim]subject[/dim]", e["subject"] or "[red]unattributed[/red]")
    t.add_row("[dim]acting for[/dim]", e["acting_for"] or "—")
    t.add_row("[dim]grant[/dim]", e["grant_id"] or "—")
    t.add_row("[dim]delegation[/dim]", e["delegation_id"] or "—")
    why = f" ({e['deny_reason']})" if e["deny_reason"] else ""
    t.add_row("[dim]decision[/dim]", e["decision"] + why)
    t.add_row("[dim]rows served[/dim]", str(e["row_ids"] or []))
    t.add_row("[dim]columns served[/dim]", ", ".join(e["columns_served"] or []) or "—")
    t.add_row("[dim]columns withheld[/dim]", ", ".join(e["columns_masked"] or []) or "—")
    t.add_row("[dim]request[/dim]", json.dumps(e["request"]))
    console.print(t)
    if chain:
        console.print("\n[bold]authority chain[/bold]")
        console.print(f"  {chain['approved_by']} (provider) approved the share")
        console.print(f"   └─ granted to {chain['grantee_principal']}, "
                      f"expires {chain['expires_at']:%Y-%m-%d}")
        console.print(f"      └─ {chain['delegator']} delegated to "
                      f"{chain['delegatee']} (depth {chain['depth']})")
        console.print(f"         purpose: {chain['purpose']!r}, "
                      f"expires {chain['d_exp']:%Y-%m-%d %H:%M}")


if __name__ == "__main__":
    app()
