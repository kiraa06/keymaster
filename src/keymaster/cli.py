"""`km` — the human front-end for Keymaster."""

from __future__ import annotations

import csv
import getpass
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table

from . import __version__, approval, clipboard, generator, totp
from .config import DEFAULTS, POLICIES
from .core import HUMAN, UNSET, Actor, Keymaster, ensure_ready
from .errors import KeymasterError, ValidationError
from .models import TYPE_HELP, TYPES, Credential
from .runner import credential_env
from .vault import Vault, export_document, import_document, read_document

console = Console()
err = Console(stderr=True)
app = typer.Typer(
    name="km",
    help='🔑 Keymaster — local encrypted credential vault + MCP server.  "I am the Keymaster."',
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=True,
    pretty_exceptions_enable=False,
)
config_app = typer.Typer(help="View / change settings.", no_args_is_help=True)
touchid_app = typer.Typer(help="Touch ID approvals.", no_args_is_help=True)
backups_app = typer.Typer(help="Encrypted automatic snapshots.", no_args_is_help=True)
app.add_typer(config_app, name="config")
app.add_typer(touchid_app, name="touchid")
app.add_typer(backups_app, name="backups")

BANNER = r"""[bold yellow]
      .--.
     /.-. '----------.
     \'-' .--"--""-"-'   [/][bold]K E Y M A S T E R[/][bold yellow]
      '--'[/]              [dim]"Are you the Keymaster?"[/]
"""

QUOTES = [
    "I am the Keymaster.",
    "There is no Dana, only Zuul.",
    "Who you gonna call?",
    "Are you the Gatekeeper?",
    "We came, we saw, we kicked its ass.",
]

POLICY_STYLE = {"open": "green", "confirm": "yellow", "sealed": "magenta", "strict": "red"}


def _actor() -> Actor:
    # The agent can shell out to `km` too; without a real terminal we treat the caller like
    # the agent so policies can't be bypassed by piping through the CLI.
    if sys.stdin.isatty() and sys.stdout.isatty():
        return HUMAN
    return Actor("agent", "a non-interactive process (km without a terminal)")


def _km(actor: Actor | None = None) -> Keymaster:
    return Keymaster(Vault(), actor=actor or _actor())


def _ready(actor: Actor | None = None) -> Keymaster:
    k = _km(actor)
    ensure_ready(k)
    return k


def _fail(msg: str, code: int = 1) -> None:
    err.print(f"[bold red]✗[/] {msg}")
    raise typer.Exit(code)


def _ask_secret(label: str, confirm: bool = False) -> str:
    v = getpass.getpass(f"{label}: ")
    if confirm and getpass.getpass(f"{label} (again): ") != v:
        _fail("Values did not match.")
    return v


def _kv(pairs: list[str] | None) -> dict[str, str]:
    out = {}
    for p in pairs or []:
        if "=" not in p:
            _fail(f"Expected key=value, got {p!r}")
        k, v = p.split("=", 1)
        out[k.strip().lower()] = v
    return out


def _policy_txt(p: str) -> str:
    return f"[{POLICY_STYLE.get(p, 'white')}]{p}[/]"


def _cred_table(items: list[dict], title: str | None = None, scores: bool = False) -> Table:
    t = Table(box=box.ROUNDED, title=title, header_style="bold cyan", expand=False)
    if scores:
        t.add_column("score", justify="right", no_wrap=True)
    t.add_column("name", overflow="fold", min_width=12)
    t.add_column("type", no_wrap=True)
    t.add_column("username", overflow="fold")
    t.add_column("urls / aliases", overflow="fold", min_width=22)
    t.add_column("tags", overflow="fold")
    t.add_column("policy", no_wrap=True)
    t.add_column("used", justify="right", no_wrap=True)
    for c in items:
        where = "\n".join(c.get("urls", [])[:2])
        if c.get("aliases"):
            where += ("\n" if where else "") + "[dim]aka " + ", ".join(c["aliases"]) + "[/]"
        name = f"[bold]{c['name']}[/]"
        if c.get("has_totp"):
            name += " [blue]⏱[/]"
        if scores:
            name += f"\n[dim]↳ {c['match']}[/]"
        if c.get("warnings"):
            name += "\n[red]⚠ " + "; ".join(c["warnings"]) + "[/]"
        row = [
            name,
            c["type"],
            c.get("username", ""),
            where,
            ", ".join(c.get("tags", [])),
            _policy_txt(c["policy"]),
            str(c.get("use_count", 0)),
        ]
        if scores:
            row.insert(0, str(c["score"]))
        t.add_row(*row)
    return t


def main() -> None:
    try:
        app()
    except KeymasterError as e:
        err.print(f"[bold red]✗[/] {e.__class__.__name__}: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        err.print("\n[dim]interrupted[/]")
        sys.exit(130)


# ============================================================================ lifecycle
@app.command()
def init() -> None:
    """Create a new vault (asks for a master passphrase, prints a recovery code)."""
    v = Vault()
    if v.exists():
        _fail(f"Vault already exists at {v.layout.vault}")
    console.print(BANNER)
    console.print(
        "Choose a [bold]master passphrase[/] (10+ chars). A few random words works well, e.g. "
        f"[green]{generator.passphrase(4)}[/]\n"
    )
    pw = _ask_secret("Master passphrase", confirm=True)
    s = generator.strength(pw)
    if s["rating"] == "weak" and not typer.confirm(
        f"That looks weak (~{s['bits']} bits). Use it anyway?", default=False
    ):
        raise typer.Exit(1)
    with console.status("Deriving keys (Argon2id, 64 MiB)…"):
        code = v.create(pw)
    Keymaster(v, HUMAN).log("init")
    console.print(
        Panel.fit(
            f"[bold]{code}[/]\n\nThis recovery code opens the vault if you forget the passphrase.\n"
            "Write it down / store it offline. It will [bold red]not[/] be shown again.",
            title="🆘 Recovery code",
            border_style="red",
        )
    )
    console.print(f"[green]✓[/] Vault created at [cyan]{v.layout.vault}[/] and unlocked (key held in macOS Keychain).")
    console.print("Next: [bold]km add jenkins --url https://ci.example.com --user me[/]  ·  [bold]km install-mcp[/]")


@app.command()
def status() -> None:
    """Vault status."""
    s = _km().status()
    if not s.get("initialized"):
        _fail("No vault. Run `km init`.")
    lock = "[green]🔓 unlocked[/]" if s["unlocked"] else "[red]🔒 locked[/]"
    t = Table.grid(padding=(0, 2))
    t.add_row("state", lock)
    for key in (
        "vault",
        "credentials",
        "trash",
        "by_type",
        "generation",
        "slots",
        "backups",
        "approval",
        "default_policy",
        "active_grants",
        "auto_lock_in_minutes",
    ):
        if key in s:
            val = s[key]
            if isinstance(val, dict):
                val = ", ".join(f"{k}:{n}" for k, n in val.items())
            elif isinstance(val, list):
                val = ", ".join(val)
            t.add_row(key, str(val))
    console.print(Panel(t, title=f"🔑 Keymaster v{__version__}", border_style="yellow", expand=False))
    if s.get("warning"):
        err.print(f"[bold red]⚠ {s['warning']}[/]")


@app.command()
def unlock(dialog: bool = typer.Option(False, help="Use the macOS secure dialog instead of the terminal.")) -> None:
    """Unlock the vault (master passphrase or recovery code)."""
    k = _km(HUMAN)
    if k.vault.is_unlocked():
        console.print("[green]Already unlocked.[/]")
        return
    secret = (
        approval.dialog_ask_secret("Keymaster", "Master passphrase:")
        if dialog
        else getpass.getpass("Are you the Keymaster? Passphrase: ")
    )
    if not secret:
        _fail("Cancelled.")
    try:
        with console.status("Verifying…"):
            kind = k.vault.unlock(secret)
    except KeymasterError:
        k.log("unlock", ok=False, via="cli")
        raise
    k.log("unlock", via="cli", slot=kind)
    console.print(f"[green]🔓 Unlocked.[/] [dim]{QUOTES[int(time.time()) % len(QUOTES)]}[/]")
    if kind == "recovery":
        console.print(
            "[yellow]You used the recovery code. Run `km passwd` to set a new passphrase "
            "and `km recovery` to mint a fresh code.[/]"
        )


@app.command()
def lock() -> None:
    """Lock the vault (drops the key from the keychain)."""
    k = _km(HUMAN)
    k.vault.lock()
    k.log("lock", via="cli")
    console.print("[red]🔒 Locked.[/]")


@app.command()
def panic() -> None:
    """🚨 Lock everything NOW: revoke approvals, wipe clipboard, drop the key."""
    k = _km(HUMAN)
    n = 0
    try:
        n = k.revoke_grants()
    except KeymasterError:
        pass
    try:
        clipboard.clear()
    except KeymasterError:
        pass
    k.vault.lock()
    k.log("panic")
    approval.notify("Keymaster", "Vault locked (panic).")
    console.print(f"[bold red]🚨 PANIC:[/] vault locked, {n} approval(s) revoked, clipboard wiped.")


# ============================================================================ CRUD
@app.command()
def add(
    name: str = typer.Argument(..., help="Unique name, e.g. jenkins-ci"),
    type: str = typer.Option("password", "--type", "-t", help="|".join(TYPES)),
    user: str | None = typer.Option(None, "--user", "-u", help="Username / login / access key id"),
    url: list[str] = typer.Option([], "--url", help="URL, host or *.wildcard (repeatable)"),
    alias: list[str] = typer.Option([], "--alias", "-a", help="Alias (repeatable)"),
    tag: list[str] = typer.Option([], "--tag", help="Tag (repeatable)"),
    field: list[str] = typer.Option([], "--field", "-f", help="Non-secret key=value (repeatable)"),
    secret_field: list[str] = typer.Option(
        [], "--secret", "-s", help="Extra secret field NAME to prompt for (repeatable)"
    ),
    with_totp: bool = typer.Option(False, "--totp", help="Also prompt for a TOTP seed / otpauth:// URI"),
    gen: bool = typer.Option(False, "--generate", "-g", help="Generate the main secret"),
    length: int = typer.Option(24, help="Generated password length"),
    passphrase_words: int = typer.Option(0, "--words", help="Generate a passphrase with N words instead"),
    from_file: Path | None = typer.Option(None, "--from-file", help="Read main secret from a file (e.g. SSH key)"),
    from_clipboard: bool = typer.Option(
        False, "--from-clipboard", help="Read main secret from clipboard, then clear it"
    ),
    no_secret: bool = typer.Option(False, "--no-secret", help="No main secret"),
    policy: str | None = typer.Option(None, "--policy", "-p", help="|".join(POLICIES)),
    expires: str | None = typer.Option(None, help="Expiry date YYYY-MM-DD"),
    rotate_days: int | None = typer.Option(None, help="Nag to rotate after N days"),
    notes: str = typer.Option("", help="Free-form notes"),
) -> None:
    """Add a credential."""
    k = _ready()
    if type not in TYPES:
        _fail(f"Unknown type. Choose from: {', '.join(TYPES)}")
    main_field = TYPES[type]
    secrets: dict[str, str] = {}
    if gen or passphrase_words:
        secrets[main_field] = generator.passphrase(passphrase_words) if passphrase_words else generator.password(length)
    elif from_file:
        secrets[main_field] = from_file.expanduser().read_text()
    elif from_clipboard:
        secrets[main_field] = clipboard.paste().strip("\n")
        clipboard.clear()
    elif not no_secret:
        if type == "note":
            console.print("Note text (end with Ctrl-D):")
            secrets[main_field] = sys.stdin.read()
        else:
            secrets[main_field] = _ask_secret(main_field.replace("_", " ").capitalize())
    for f in secret_field:
        secrets[f.lower()] = _ask_secret(f)
    if with_totp:
        seed = _ask_secret("TOTP seed or otpauth:// URI")
        totp.parse(seed)
        secrets["totp_secret"] = seed
    c = k.add(
        name,
        type,
        username=user,
        secrets=secrets,
        fields=_kv(field),
        urls=url,
        aliases=alias,
        tags=tag,
        notes=notes,
        policy=policy,
        expires_at=expires,
        rotate_days=rotate_days,
    )
    console.print(f"[green]✓[/] Added [bold]{c.name}[/] ({c.id}) · policy {_policy_txt(c.policy)}")
    if gen or passphrase_words:
        if typer.confirm("Copy the generated secret to clipboard?", default=True):
            clipboard.copy(secrets[main_field], int(k.vault.config.get("clipboard_seconds")))
            console.print(f"[dim]Copied; clears in {k.vault.config.get('clipboard_seconds')}s.[/]")
    main_secret = secrets.get(main_field, "")
    if main_field in ("password",) and main_secret:
        s = generator.strength(main_secret)
        if s["rating"] == "weak":
            console.print(f"[yellow]⚠ weak password (~{s['bits']} bits): {', '.join(s['issues'])}[/]")


@app.command()
def edit(
    ref: str,
    name: str | None = typer.Option(None, help="Rename"),
    user: str | None = typer.Option(None, "--user", "-u"),
    new_secret: bool = typer.Option(False, "--secret", help="Prompt for a new main secret"),
    gen: bool = typer.Option(False, "--generate", "-g", help="Generate a new main secret"),
    length: int = typer.Option(24),
    set_secret: list[str] = typer.Option([], "--set-secret", help="Prompt for secret field NAME (repeatable)"),
    rm_secret: list[str] = typer.Option([], "--rm-secret"),
    field: list[str] = typer.Option([], "--field", "-f", help="key=value (empty value removes)"),
    add_url: list[str] = typer.Option([], "--add-url"),
    rm_url: list[str] = typer.Option([], "--rm-url"),
    add_alias: list[str] = typer.Option([], "--add-alias", "-a"),
    rm_alias: list[str] = typer.Option([], "--rm-alias"),
    add_tag: list[str] = typer.Option([], "--add-tag"),
    rm_tag: list[str] = typer.Option([], "--rm-tag"),
    with_totp: bool = typer.Option(False, "--totp", help="Set/replace TOTP seed"),
    policy: str | None = typer.Option(None, "--policy", "-p"),
    notes: str | None = typer.Option(None),
    expires: str | None = typer.Option(None, help="YYYY-MM-DD ('' clears)"),
    rotate_days: int | None = typer.Option(None, help="0 clears"),
    reason: str = typer.Option("", help="Why (kept in history)"),
) -> None:
    """Modify a credential."""
    k = _ready()
    cur = k.credential(ref)
    secrets: dict[str, str | None] = {}
    if new_secret:
        secrets[cur.primary_field] = _ask_secret(f"New {cur.primary_field}", confirm=True)
    if gen:
        secrets[cur.primary_field] = generator.password(length)
    for f in set_secret:
        secrets[f.lower()] = _ask_secret(f)
    for f in rm_secret:
        secrets[f.lower()] = None
    if with_totp:
        seed = _ask_secret("TOTP seed or otpauth:// URI")
        totp.parse(seed)
        secrets["totp_secret"] = seed
    flds: dict[str, str | None] = {k2: (v or None) for k2, v in _kv(field).items()}
    c, changed = k.update(
        cur.id,
        name=name,
        username=user if user is not None else UNSET,
        secrets=secrets or None,
        fields=flds or None,
        add_urls=add_url,
        remove_urls=rm_url,
        add_aliases=add_alias,
        remove_aliases=rm_alias,
        add_tags=add_tag,
        remove_tags=rm_tag,
        notes=notes,
        policy=policy,
        expires_at=expires if expires is not None else UNSET,
        rotate_days=rotate_days if rotate_days is not None else UNSET,
        reason=reason,
    )
    if not changed:
        console.print("[dim]Nothing changed.[/]")
        return
    console.print(f"[green]✓[/] Updated [bold]{c.name}[/]: {', '.join(changed)}")
    if gen and typer.confirm("Copy the new secret to clipboard?", default=True):
        clipboard.copy(secrets[cur.primary_field] or "", int(k.vault.config.get("clipboard_seconds")))


@app.command("rm")
def remove(ref: str, yes: bool = typer.Option(False, "--yes", "-y")) -> None:
    """Move a credential to the trash."""
    k = _ready()
    c = k.credential(ref)
    if not yes and not typer.confirm(f"Move '{c.name}' to trash?", default=True):
        raise typer.Exit()
    k.delete(c.id)
    console.print(f"[yellow]🗑[/]  '{c.name}' moved to trash ([bold]km restore {c.name}[/] to undo).")


@app.command()
def restore(ref: str) -> None:
    """Restore from trash."""
    c = _ready().restore(ref)
    console.print(f"[green]✓[/] Restored [bold]{c.name}[/]")


@app.command()
def trash() -> None:
    """Show the trash."""
    items = _ready().list(deleted=True)
    if not items:
        console.print("[dim]Trash is empty.[/]")
        return
    console.print(_cred_table(items, title="🗑 Trash"))


@app.command()
def purge(
    ref: str | None = typer.Argument(None), all: bool = typer.Option(False, "--all", help="Empty the whole trash")
) -> None:
    """Permanently destroy trashed credential(s)."""
    k = _ready()
    if all:
        if typer.confirm("Permanently destroy EVERYTHING in the trash?", default=False):
            console.print(f"[red]Purged {k.empty_trash()} credential(s).[/]")
        return
    if not ref:
        _fail("Give a credential or --all")
    c = k.credential(ref, deleted=True)
    if typer.confirm(f"Permanently destroy '{c.name}'? This cannot be undone.", default=False):
        k.purge(c.id)
        console.print(f"[red]Purged '{c.name}'.[/]")


@app.command("ls")
def list_(
    type: str | None = typer.Option(None, "--type", "-t"),
    tag: str | None = typer.Option(None, "--tag"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List credentials."""
    items = _ready().list(type=type, tag=tag)
    if as_json:
        console.print_json(json.dumps(items))
        return
    if not items:
        console.print("[dim]No credentials yet. `km add <name>`[/]")
        return
    console.print(_cred_table(items, title=f"🔑 {len(items)} credential(s)"))


@app.command()
def find(query: str, limit: int = typer.Option(5, "--limit", "-n")) -> None:
    """Find credentials by URL, host, alias or phrase (the same resolver the agent uses)."""
    r = _ready().find(query, limit)
    if not r["matches"]:
        console.print(f"[dim]No match for {query!r}.[/]")
        return
    console.print(_cred_table(r["matches"], title=f"🔎 {query}", scores=True))
    if r.get("ambiguous"):
        console.print("[yellow]Ambiguous — the agent would ask you which one.[/]")


@app.command()
def show(
    ref: str,
    reveal: bool = typer.Option(False, "--reveal", "-r", help="Show secret values"),
    field: list[str] = typer.Option([], "--field", "-f", help="Only these secret fields"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Show a credential (secrets hidden unless --reveal)."""
    k = _ready()
    if reveal:
        c, vals = k.reveal(ref, field or None, purpose="km show --reveal")
        d = c.public(k.vault.config.get("stale_days"))
        d["secrets"] = vals
    else:
        d = k.get(ref)
    if as_json:
        console.print_json(json.dumps(d))
        return
    t = Table.grid(padding=(0, 2))
    for key in (
        "id",
        "type",
        "username",
        "urls",
        "aliases",
        "tags",
        "fields",
        "secrets",
        "policy",
        "expires_at",
        "rotate_days",
        "notes",
        "created_at",
        "updated_at",
        "secret_changed_at",
        "last_used_at",
        "use_count",
        "history",
        "warnings",
    ):
        if key not in d:
            continue
        v = d[key]
        if isinstance(v, dict):
            v = "\n".join(f"[cyan]{a}[/] = {b}" for a, b in v.items())
        elif isinstance(v, list):
            v = ", ".join(map(str, v))
        if key == "policy":
            v = _policy_txt(v)
        if key == "warnings":
            v = f"[red]{v}[/]"
        t.add_row(f"[dim]{key}[/]", str(v))
    console.print(Panel(t, title=f"[bold]{d['name']}[/]", border_style="cyan", expand=False))


@app.command()
def copy(
    ref: str,
    field: str | None = typer.Option(None, "--field", "-f", help="Field (default main secret; 'username', 'totp')"),
    seconds: int | None = typer.Option(None, help="Clear after N seconds"),
) -> None:
    """Copy a secret to the clipboard (auto-clears)."""
    r = _ready().copy(ref, field, "km copy", seconds)
    console.print(f"[green]📋[/] {r['copied']} copied · clears in {r['clears_in_seconds']}s")


@app.command("totp")
def totp_cmd(
    ref: str,
    watch: bool = typer.Option(False, "--watch", "-w", help="Live countdown"),
    copy_: bool = typer.Option(False, "--copy", "-c"),
) -> None:
    """Show the current 2FA code."""
    k = _ready()
    r = k.totp(ref, "km totp")
    if copy_:
        clipboard.copy(r["code"], r["seconds_remaining"] + 2)
    if not watch:
        console.print(
            f"[bold green]{r['code'][:3]} {r['code'][3:]}[/]  [dim]({r['seconds_remaining']}s left, next {r['next_code']})[/]"
        )
        return
    seed = k.credential(ref).secrets["totp_secret"]
    with Progress(
        TextColumn("[bold green]{task.description}"),
        BarColumn(),
        TextColumn("{task.fields[s]}s"),
        console=console,
        transient=True,
    ) as prog:
        task = prog.add_task("", total=r["period"], s=0)
        try:
            while True:
                n = totp.now(seed)
                prog.update(
                    task,
                    description=f"{n['code'][:3]} {n['code'][3:]}",
                    completed=n["seconds_remaining"],
                    s=n["seconds_remaining"],
                )
                time.sleep(0.25)
        except KeyboardInterrupt:
            pass


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def run(ctx: typer.Context, ref: str) -> None:
    """Run a command with the credential in env vars:  km run jenkins -- curl -u "$KM_USERNAME:$KM_TOKEN" …"""
    if not ctx.args:
        _fail("Usage: km run <ref> -- <command…>")
    k = _ready()
    c = k.use(ref, "run", "km run")
    k.log("run", cred=c, command=" ".join(ctx.args)[:300], via="cli")
    with credential_env(c) as env:
        code = subprocess.call(
            ctx.args if len(ctx.args) > 1 else ["/bin/bash", "-c", ctx.args[0]], env={**os.environ, **env}
        )
    raise typer.Exit(code)


@app.command()
def gen(
    length: int = typer.Option(24, "--length", "-l"),
    words: int = typer.Option(0, "--words", "-w", help="Passphrase with N words instead"),
    no_symbols: bool = typer.Option(False, "--no-symbols"),
    count: int = typer.Option(1, "--count", "-n"),
    copy_: bool = typer.Option(False, "--copy", "-c"),
) -> None:
    """Generate passwords / passphrases (no vault needed)."""
    last = ""
    for _ in range(count):
        last = generator.passphrase(words) if words else generator.password(length, symbols=not no_symbols)
        bits = generator.passphrase_bits(words) if words else generator.strength(last)["bits"]
        console.print(f"[bold]{_esc(last)}[/]  [dim]~{bits:.0f} bits[/]", highlight=False)
    if copy_:
        clipboard.copy(last, int(DEFAULTS["clipboard_seconds"]))
        console.print("[dim]Copied (last one); clears in 30s.[/]")


def _esc(s: str) -> str:
    return s.replace("[", r"\[")


@app.command()
def strength() -> None:
    """Rate a password (typed hidden, never stored)."""
    s = generator.strength(getpass.getpass("Password to rate: "))
    color = {"weak": "red", "fair": "yellow", "strong": "green", "excellent": "bold green"}.get(s["rating"], "white")
    console.print(f"[{color}]{s['rating'].upper()}[/] ~{s['bits']} bits  {'; '.join(s['issues'])}")


@app.command()
def history(ref: str) -> None:
    """Version history of a credential's secrets."""
    vs = _ready().history(ref)
    if not vs:
        console.print("[dim]No previous versions.[/]")
        return
    t = Table(box=box.SIMPLE, header_style="bold cyan")
    for col in ("version", "replaced at", "reason", "changed afterwards"):
        t.add_column(col)
    for v in vs:
        t.add_row(str(v["version"]), v["replaced_at"], v["reason"], ", ".join(v["fields_that_changed_after"]))
    console.print(t)


@app.command()
def rollback(ref: str, version: int) -> None:
    """Restore username+secrets from an earlier version."""
    c = _ready().rollback(ref, version)
    console.print(f"[green]✓[/] {c.name} rolled back to v{version}")


@app.command()
def health(pwned: bool = typer.Option(False, "--pwned", help="Also check HaveIBeenPwned (k-anonymity)")) -> None:
    """Security report card for the vault."""
    with console.status("Inspecting…"):
        r = _ready().health(pwned)
    color = {"A": "bold green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}[r["grade"]]
    console.print(
        Panel.fit(
            f"[{color}]{r['grade']}[/]  score {r['score']}/100 · {r['credentials']} credentials",
            title="🩺 Vault health",
            border_style=color.split()[-1],
        )
    )
    if not r["issues"]:
        console.print("[green]No issues. Spotless. 👻[/]")
        return
    t = Table(box=box.SIMPLE, header_style="bold cyan")
    for col in ("sev", "credential", "issue"):
        t.add_column(col)
    sev = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}
    for i in r["issues"]:
        t.add_row(f"[{sev[i['severity']]}]{i['severity']}[/]", i["cred"], i["message"])
    console.print(t)


@app.command()
def audit(
    limit: int = typer.Option(30, "--limit", "-n"),
    ref: str | None = typer.Option(None, "--ref"),
    verify: bool = typer.Option(False, "--verify", help="Verify the tamper-evident hash chain"),
) -> None:
    """Show who accessed what (and verify the log hasn't been tampered with)."""
    k = _ready()
    if verify:
        r = k.audit.verify()
        if r["ok"]:
            console.print(f"[green]✓ Audit chain intact[/] ({r['entries']} entries)")
        else:
            _fail(f"Audit chain BROKEN at line {r.get('broken_at_line')}: {r['reason']}")
        return
    t = Table(box=box.SIMPLE, header_style="bold cyan")
    for col in ("time", "who", "action", "credential", "detail"):
        t.add_column(col, overflow="fold")
    for e in k.audit_tail(limit, ref):
        ts = datetime.fromisoformat(e["ts"]).astimezone().strftime("%m-%d %H:%M:%S")
        who = "🤖" if e["actor"] == "agent" else "🧑"
        act = e["action"] if e["ok"] else f"[red]{e['action']} ✗[/]"
        det = ", ".join(f"{a}={b}" for a, b in (e.get("detail") or {}).items())
        t.add_row(ts, who, act, e.get("cred", ""), det[:120])
    console.print(t)


# ============================================================================ keys
@app.command()
def passwd() -> None:
    """Change the master passphrase."""
    v = Vault()
    cur = getpass.getpass("Current passphrase (or recovery code): ")
    new = _ask_secret("New passphrase", confirm=True)
    with console.status("Re-wrapping key…"):
        v.change_passphrase(cur, new)
    Keymaster(v, HUMAN).log("passwd")
    console.print(
        "[green]✓ Passphrase changed.[/] [dim]Old backups still open with the old passphrase; "
        "`km backups prune` to remove them.[/]"
    )


@app.command()
def recovery() -> None:
    """Mint a new recovery code (the old one stops working)."""
    v = Vault()
    code = v.new_recovery_code(getpass.getpass("Master passphrase: "))
    Keymaster(v, HUMAN).log("recovery_rotated")
    console.print(Panel.fit(f"[bold]{code}[/]", title="🆘 New recovery code", border_style="red"))


@app.command("rotate-key")
def rotate_key() -> None:
    """Re-encrypt the whole vault under a brand-new data key (+ new recovery code)."""
    v = Vault()
    pw = getpass.getpass("Master passphrase: ")
    with console.status("Rotating…"):
        code = v.rotate_dek(pw)
    Keymaster(v, HUMAN).log("rotate_key")
    console.print("[green]✓ Data key rotated.[/]")
    console.print(Panel.fit(f"[bold]{code}[/]", title="🆘 New recovery code", border_style="red"))


# ============================================================================ import / export
@app.command()
def export(path: Path, force: bool = typer.Option(False, "--force")) -> None:
    """Export an encrypted, portable backup protected by its own passphrase."""
    if path.exists() and not force:
        _fail(f"{path} exists (use --force)")
    k = _ready(HUMAN)
    pw = _ask_secret("Passphrase for the export file", confirm=True)
    with k.vault.transaction() as p:
        doc = export_document(p, pw)
        n = len(p["credentials"])
    path.write_text(json.dumps(doc, indent=1))
    os.chmod(path, 0o600)
    k.log("export", count=n, file=str(path))
    console.print(f"[green]✓[/] Exported {n} credential(s) to {path} (encrypted).")


@app.command("import")
def import_(
    path: Path,
    format: str = typer.Option("auto", "--format", help="auto|km|csv|env"),
    on_conflict: str = typer.Option("skip", help="skip|overwrite|rename"),
    name: str | None = typer.Option(None, help="Credential name for --format env"),
    tag: list[str] = typer.Option([], "--tag", help="Tag every imported credential"),
    policy: str | None = typer.Option(None, "--policy"),
) -> None:
    """Import from a Keymaster export, a password-manager CSV (Chrome/Bitwarden/1Password/…) or a .env file."""
    k = _ready(HUMAN)
    fmt = format
    if fmt == "auto":
        fmt = (
            "csv"
            if path.suffix.lower() == ".csv"
            else "env"
            if path.name.startswith(".env") or path.suffix == ".env"
            else "km"
        )
    incoming: list[Credential] = []
    if fmt == "km":
        payload = import_document(path, getpass.getpass("Export file passphrase: "))
        incoming = [Credential.from_dict(d) for d in payload["credentials"].values() if not d.get("deleted_at")]
    elif fmt == "csv":
        incoming = _from_csv(path)
    elif fmt == "env":
        secrets = {}
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.removeprefix("export ").split("=", 1)
            secrets[key.strip().lower()] = val.strip().strip("'\"")
        incoming = [Credential(id="", name=name or path.stem.lstrip(".") or "env", type="custom", secrets=secrets)]
    else:
        _fail("format must be auto|km|csv|env")
    existing = {c["name"].lower(): c for c in k.list()}
    added = skipped = replaced = 0
    for c in incoming:
        c.tags = list({*c.tags, *tag})
        if policy:
            c.policy = policy
        if c.name.lower() in existing:
            if on_conflict == "skip":
                skipped += 1
                continue
            if on_conflict == "overwrite":
                k.update(
                    existing[c.name.lower()]["id"],
                    username=c.username,
                    secrets=c.secrets,
                    add_urls=c.urls,
                    add_tags=c.tags,
                    reason=f"import from {path.name}",
                )
                replaced += 1
                continue
            base, i = c.name, 2
            while f"{base}-{i}".lower() in existing:
                i += 1
            c.name = f"{base}-{i}"
        try:
            k.add(
                c.name,
                c.type,
                username=c.username,
                secrets=c.secrets,
                fields=c.fields,
                urls=c.urls,
                aliases=[a for a in c.aliases if a not in existing],
                tags=c.tags,
                notes=c.notes,
                policy=c.policy if fmt == "km" or policy else None,
                expires_at=c.expires_at,
                rotate_days=c.rotate_days,
            )
            existing[c.name.lower()] = {"id": c.name}
            added += 1
        except ValidationError as e:
            err.print(f"[yellow]skip {c.name}: {e}[/]")
            skipped += 1
    k.log("import", file=str(path), added=added, replaced=replaced, skipped=skipped)
    console.print(f"[green]✓[/] Imported: {added} added, {replaced} overwritten, {skipped} skipped.")
    if fmt == "csv":
        console.print(f"[yellow]Now securely delete the plaintext CSV:[/] rm -P {path}")


def _from_csv(path: Path) -> list[Credential]:
    out = []
    with path.open(newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            r = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}

            def pick(*keys: str, r: dict = r) -> str:
                return next((r[x] for x in keys if r.get(x)), "")

            name = pick("name", "title")
            url = pick("url", "login_uri", "website", "urls")
            pw = pick("password", "login_password")
            if not (name or url) or not pw:
                continue
            secrets = {"password": pw}
            otp = pick("totp", "login_totp", "otpauth", "one-time password")
            if otp:
                secrets["totp_secret"] = otp
            host = url.split("//")[-1].split("/")[0] if url else ""
            cname = (
                "".join(ch if ch.isalnum() or ch in "@.+/:_- " else "-" for ch in (name or host))[:80].strip()
                or "imported"
            )
            out.append(
                Credential(
                    id="",
                    name=cname,
                    type="password",
                    username=pick("username", "login_username", "login") or None,
                    secrets=secrets,
                    urls=[url] if url else [],
                    notes=pick("note", "notes", "extra"),
                    tags=["imported"],
                )
            )
    return out


# ============================================================================ backups
@backups_app.command("ls")
def backups_ls() -> None:
    """List automatic snapshots (taken before every change)."""
    v = Vault()
    t = Table(box=box.SIMPLE, header_style="bold cyan")
    for col in ("file", "generation", "size"):
        t.add_column(col)
    for b in v.backups():
        try:
            gen = str(read_document(b)["generation"])
        except KeymasterError:
            gen = "?"
        t.add_row(b.name, gen, f"{b.stat().st_size // 1024} KB")
    console.print(t)


@backups_app.command("restore")
def backups_restore(name: str) -> None:
    """Replace the vault with a snapshot (current vault is snapshotted first)."""
    v = Vault()
    src = v.layout.backups / name
    if not src.exists():
        _fail(f"No backup {name}")
    doc = read_document(src)
    secret = getpass.getpass("Passphrase for that snapshot: ")
    from .vault import open_document, unwrap_with

    dek, _ = unwrap_with(doc, secret)
    open_document(doc, dek)
    if not typer.confirm(f"Replace current vault with {name} (generation {doc['generation']})?", default=False):
        raise typer.Exit()
    v._backup()
    shutil.copy2(src, v.layout.vault)
    v.keystore.set(f"dek:{doc['vault_id']}", dek)
    st = v.state.load()
    st["last_generation"] = doc["generation"]
    v.state.save(st)
    Keymaster(v, HUMAN).log("backup_restore", file=name)
    console.print(f"[green]✓[/] Restored {name}.")


@backups_app.command("prune")
def backups_prune(keep: int = typer.Option(0, help="How many recent snapshots to keep")) -> None:
    """Delete old snapshots (e.g. after a passphrase change)."""
    v = Vault()
    snaps = v.backups()
    for b in snaps[keep:]:
        b.unlink()
    console.print(f"Removed {max(0, len(snaps) - keep)} snapshot(s).")


# ============================================================================ config / touchid
@config_app.command("list")
def config_list() -> None:
    """Show all settings."""
    cfg = Vault().config.all()
    t = Table(box=box.SIMPLE, header_style="bold cyan")
    t.add_column("key")
    t.add_column("value")
    t.add_column("default", style="dim")
    for key, val in cfg.items():
        t.add_row(key, str(val), str(DEFAULTS[key]))
    console.print(t)


@config_app.command("get")
def config_get(key: str) -> None:
    console.print(Vault().config.get(key))


@config_app.command("set")
def config_set(key: str, value: str) -> None:
    """e.g. km config set approval touchid · km config set auto_lock_hours 12"""
    if _actor() is not HUMAN:
        _fail("Config changes need an interactive terminal.")
    v = Vault()
    val = v.config.set(key, value)
    if v.exists():
        Keymaster(v, HUMAN).log("config", key=key, value=str(val))
    console.print(f"[green]✓[/] {key} = {val}")


@touchid_app.command("setup")
def touchid_setup() -> None:
    """Compile the Touch ID helper and switch approvals to Touch ID."""
    v = Vault()
    with console.status("Compiling Touch ID helper (swiftc)…"):
        path = approval.build_touchid(v.layout.bin)
    r = subprocess.run([str(path), "--check"], capture_output=True, text=True)
    if r.returncode != 0:
        _fail(f"Touch ID not available on this Mac: {r.stderr.strip()}")
    v.config.set("approval", "touchid")
    console.print(f"[green]✓[/] Touch ID ready ({path}). Approvals now use your fingerprint 👆")


@touchid_app.command("test")
def touchid_test() -> None:
    """Trigger a test Touch ID prompt."""
    v = Vault()
    d = approval.TouchIDApprover(v.layout.bin).approve(approval.Request("Keymaster", "test Keymaster Touch ID"))
    console.print("[green]✓ approved[/]" if d.allowed else f"[red]✗ {d.note}[/]")


# ============================================================================ integration
@app.command("install-mcp")
def install_mcp(scope: str = typer.Option("user", help="Claude Code scope: user|project|local")) -> None:
    """Register the Keymaster MCP server with Claude Code."""
    exe = shutil.which("keymaster-mcp") or str(Path(sys.executable).parent / "keymaster-mcp")
    claude = shutil.which("claude")
    if not claude:
        console.print(f"Claude CLI not found. Add manually:\n  claude mcp add --scope {scope} keymaster -- {exe}")
        return
    subprocess.run([claude, "mcp", "remove", "--scope", scope, "keymaster"], capture_output=True)
    r = subprocess.run([claude, "mcp", "add", "--scope", scope, "keymaster", "--", exe], capture_output=True, text=True)
    if r.returncode != 0:
        _fail(r.stderr or r.stdout)
    console.print(f"[green]✓[/] Registered with Claude Code ({scope} scope) → {exe}")
    console.print("For other MCP clients (Claude Desktop, Cursor…):")
    console.print_json(json.dumps({"mcpServers": {"keymaster": {"command": exe}}}))


@app.command("git-credential", hidden=True)
def git_credential(operation: str) -> None:
    """git credential helper:  git config --global credential.helper '!km git-credential'"""
    if operation != "get":
        sys.stdin.read()
        return  # store/erase: Keymaster is the source of truth; ignore git's writes
    req = dict(line.split("=", 1) for line in sys.stdin.read().splitlines() if "=" in line)
    host = req.get("host")
    if not host:
        return
    url = f"{req.get('protocol', 'https')}://{host}/{req.get('path', '')}"
    try:
        k = _ready(Actor("agent", "git (credential helper)"))
        r = k.find(url, limit=2, type=None)
        m = [x for x in r["matches"] if x["type"] in ("password", "token") and x["score"] >= 75]
        if not m or r.get("ambiguous"):
            return
        c = k.use(m[0]["id"], "git-credential", f"git {req.get('protocol')}://{host}")
        k.log("git-credential", cred=c, host=host)
        sys.stdout.write(f"username={c.username or 'x-access-token'}\npassword={c.primary_secret}\n")
    except KeymasterError:
        return  # fall through to git's next helper / prompt


@app.command()
def doctor() -> None:
    """Check everything: permissions, keychain, audit chain, backups, integration."""
    v = Vault()
    ok_all = True

    def row(ok: bool | None, what: str, hint: str = "") -> None:
        nonlocal ok_all
        icon = "[green]✓[/]" if ok else "[yellow]•[/]" if ok is None else "[red]✗[/]"
        if ok is False:
            ok_all = False
        console.print(f" {icon} {what}" + (f"  [dim]{hint}[/]" if hint and ok is not True else ""))

    console.print("[bold]🩺 km doctor[/]")
    row(sys.version_info >= (3, 11), f"Python {sys.version.split()[0]}")
    row(v.exists(), f"vault at {v.layout.vault}", "" if v.exists() else "run `km init`")
    if v.exists():
        mode = oct(v.layout.root.stat().st_mode & 0o777)
        row(mode == "0o700", f"home dir permissions {mode}", "chmod 700 ~/.keymaster")
        fmode = oct(v.layout.vault.stat().st_mode & 0o777)
        row(fmode == "0o600", f"vault file permissions {fmode}", "chmod 600")
        try:
            unlocked = v.is_unlocked()
            row(True, "keychain reachable")
            row(unlocked or None, "unlocked" if unlocked else "locked", "" if unlocked else "`km unlock`")
        except KeymasterError as e:
            row(False, f"keychain: {e}")
            unlocked = False
        if unlocked:
            with v.transaction():
                pass
            row(v.rollback_warning is None, "no rollback detected", v.rollback_warning or "")
            r = Keymaster(v, HUMAN).audit.verify()
            row(r["ok"], f"audit chain ({r.get('entries', 0)} entries)", r.get("reason", ""))
        row(len(v.backups()) > 0 or None, f"{len(v.backups())} snapshot(s)")
        doc = v.document()
        kinds = [s["kind"] for s in doc["slots"]]
        row("recovery" in kinds or None, f"key slots: {', '.join(kinds)}")
    method = v.config.get("approval")
    if method == "touchid":
        row(approval.touchid_binary(v.layout.bin).exists(), "Touch ID helper", "`km touchid setup`")
    else:
        row(None, f"approvals via {method}", "try `km touchid setup` 👆")
    row(bool(shutil.which("keymaster-mcp")), "keymaster-mcp on PATH", "uv tool install -e ~/keymaster")
    if shutil.which("claude"):
        r = subprocess.run(["claude", "mcp", "get", "keymaster"], capture_output=True, text=True, timeout=60)
        row(r.returncode == 0, "registered with Claude Code", "" if r.returncode == 0 else "`km install-mcp`")
    console.print("[green]All good. 👻[/]" if ok_all else "[yellow]Some checks need attention.[/]")


@app.command()
def version() -> None:
    console.print(f"keymaster {__version__}")


@app.command("types")
def types_() -> None:
    """Credential types and their main secret field."""
    t = Table(box=box.SIMPLE, header_style="bold cyan")
    for col in ("type", "main secret", "for"):
        t.add_column(col)
    for ty, f in TYPES.items():
        t.add_row(ty, f, TYPE_HELP[ty])
    console.print(t)
    console.print("Policies: " + " · ".join(f"{_policy_txt(p)}" for p in POLICIES))
    console.print(
        "[dim]open: agent reveals freely · confirm: reveal needs your OK (can grant for hours) · "
        "sealed: never revealed, use-only · strict: every use needs your OK[/]"
    )


if __name__ == "__main__":
    main()
