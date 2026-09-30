"""Keymaster MCP server (stdio)."""

import functools
import os
from pathlib import Path
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from . import __version__, clipboard, generator
from .core import AGENT, UNSET, Keymaster, ensure_ready, generate
from .errors import KeymasterError, PolicyDenied, ValidationError
from .models import TYPE_HELP, TYPES
from .vault import Vault

INSTRUCTIONS = """\
Keymaster is the user's personal, locally-encrypted credential vault. It is the source of truth
for their logins, tokens, API keys, SSH keys, AWS keys, DB passwords and 2FA seeds.

WHEN TO USE: any time a task needs to authenticate to something — Jenkins/CI, a web UI, an API,
AWS, a database, a git host, a VPN, a server — call `find_credentials` FIRST with whatever you
have (the URL, hostname, service name or a phrase like "jenkins prod"). Do NOT ask the user where
the password is, and do not search the filesystem or env for secrets. The user expects you to
just know.

HOW TO USE, in order of preference (least exposure first):
  1. `http_request`       — call an API with auth injected; the secret never enters the chat.
  2. `run_with_credential` — run a shell command with the secret in env vars ($KM_USERNAME,
                             $KM_PASSWORD, $KM_TOKEN, $KM_SECRET, AWS_*, PG*, $KM_KEY_FILE…);
                             output is scrubbed of the secret.
  3. `get_totp`           — current 2FA code when a login asks for one.
  4. `copy_to_clipboard`  — when the human will paste it themselves.
  5. `get_credential(reveal=true)` — only when you must type the value yourself (e.g. a
                             browser login form). Never repeat a revealed secret in your reply,
                             in files, commits or logs.

Some credentials need the human to approve (a macOS dialog / Touch ID pops up; the call waits).
If access is denied, do not retry — ask the user. If a match is ambiguous, ask which one.
If nothing matches, offer to store it with `add_credential(secret_source="prompt")`, which makes
the user type the secret into a secure dialog so it never passes through the conversation.
When the user gives you a new URL/alias for an existing credential, save it with
`update_credential(add_urls=[...])` so next time lookup is instant.
If the vault is locked, call `unlock_vault` (the user types the passphrase in a dialog).
"""

mcp = MCPServer(name="keymaster", instructions=INSTRUCTIONS, version=__version__, log_level="WARNING")

RO = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False)
WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False)
DESTRUCTIVE = ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False)
WORLD = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=True)

_vault_root = os.environ.get("KEYMASTER_HOME")


def km() -> Keymaster:
    return Keymaster(Vault(Path(_vault_root) if _vault_root else None), actor=AGENT)


def tool(annotations: ToolAnnotations, needs_unlock: bool = True):
    """Register a tool; map domain errors to clean MCP tool errors (no tracebacks, no secrets)."""

    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                k = km()
                if needs_unlock:
                    ensure_ready(k)
                return fn(k, *args, **kwargs)
            except KeymasterError as e:
                raise ToolError(f"{e.__class__.__name__}: {e}") from None
            except Exception as e:  # pragma: no cover - last-resort guard
                raise ToolError(f"Internal error ({e.__class__.__name__}). See `km doctor`.") from None

        # MCPServer introspects the signature; hide our injected `k` parameter.
        import inspect

        sig = inspect.signature(fn)
        wrapper.__signature__ = sig.replace(parameters=list(sig.parameters.values())[1:])  # type: ignore[attr-defined]
        wrapper.__annotations__ = {k: v for k, v in fn.__annotations__.items() if k != "k"}
        return mcp.tool(annotations=annotations)(wrapper)

    return deco


CredType = Literal[
    "password", "token", "api_key", "ssh_key", "aws", "database", "certificate", "totp", "note", "custom"
]
Policy = Literal["open", "confirm", "sealed", "strict"]
SecretSource = Literal["value", "prompt", "clipboard", "file", "generate", "none"]


# ============================================================================ discovery
@tool(RO, needs_unlock=False)
def vault_status(k: Keymaster) -> dict:
    """Is the vault initialised/unlocked, how many credentials, approval mode, etc."""
    return k.status()


@tool(RO)
def find_credentials(
    k: Keymaster, query: str, limit: int = 5, type: CredType | None = None, tag: str | None = None
) -> dict:
    """Find the credential(s) for a URL, hostname, name, alias or free-text phrase
    (e.g. "https://ci.example.com/job/x", "jenkins", "prod db", "aws sg").
    Returns ranked matches with metadata only (secrets hidden), plus `ambiguous` when unsure."""
    return k.find(query, limit=max(1, min(limit, 20)), type=type, tag=tag)


@tool(RO)
def list_credentials(k: Keymaster, type: CredType | None = None, tag: str | None = None) -> dict:
    """List all credentials (metadata only), optionally filtered by type or tag."""
    items = k.list(type=type, tag=tag)
    return {"count": len(items), "credentials": items}


@tool(RO)
def get_credential(
    k: Keymaster, ref: str, reveal: bool = False, fields: list[str] | None = None, purpose: str = ""
) -> dict:
    """Get one credential by id, name, alias or URL. With reveal=true the raw secret values are
    returned (subject to its policy — may pop an approval dialog for the user). Always give a
    short `purpose` when revealing. Prefer http_request/run_with_credential over revealing."""
    if not reveal:
        return k.get(ref)
    c, values = k.reveal(ref, fields, purpose)
    out = c.public(k.vault.config.get("stale_days"))
    out["secrets"] = values
    out["_notice"] = (
        "Secret revealed. Use it only for the immediate step; never echo it back to the user or write it anywhere."
    )
    return out


# ============================================================================ create / modify
def _obtain_secret(
    k: Keymaster, source: str, name: str, field: str, value: str | None, file: str | None, length: int, kind: str
) -> tuple[str | None, str]:
    if source == "none":
        return None, "none"
    if source == "value":
        if not value:
            raise ValidationError("secret_source='value' needs `secret`. Or use secret_source='prompt'.")
        return value, "provided"
    if source == "prompt":
        return k.secret_from_human(name, field), "typed by user in secure dialog"
    if source == "clipboard":
        v = clipboard.paste()
        if not v.strip():
            raise ValidationError("Clipboard is empty — ask the user to copy the secret first.")
        clipboard.clear()
        return v.strip("\n"), "read from clipboard (clipboard cleared)"
    if source == "file":
        if not file:
            raise ValidationError("secret_source='file' needs `secret_file`")
        p = Path(file).expanduser()
        if not p.is_file() or p.stat().st_size > 256_000:
            raise ValidationError(f"{p} is not a readable file under 256KB")
        return p.read_text(), f"read from {p}"
    if source == "generate":
        return generate(kind, length=length), f"generated ({kind})"
    raise ValidationError(f"Unknown secret_source {source!r}")


@tool(WRITE)
def add_credential(
    k: Keymaster,
    name: str,
    type: CredType = "password",
    username: str | None = None,
    urls: list[str] | None = None,
    aliases: list[str] | None = None,
    tags: list[str] | None = None,
    secret_source: SecretSource = "prompt",
    secret: str | None = None,
    secret_field: str | None = None,
    secret_file: str | None = None,
    extra_secrets: dict[str, str] | None = None,
    fields: dict[str, str] | None = None,
    notes: str = "",
    policy: Policy | None = None,
    expires_at: str | None = None,
    rotate_days: int | None = None,
    generate_length: int = 24,
    generate_kind: Literal["password", "passphrase"] = "password",
) -> dict:
    """Store a new credential. Keys the agent can later look it up by: `name`, `aliases`, `urls`
    (full URLs, bare hosts, or wildcards like *.corp.com), and `tags`.

    secret_source (how the main secret is obtained — prefer ones that keep it out of the chat):
      prompt    (default) user types it into a secure macOS dialog
      clipboard read from clipboard, then clear it (user copies it first)
      file      read from `secret_file` (great for SSH keys / service-account JSON)
      generate  create a strong random password/passphrase
      value     use `secret` as given (only if the user already pasted it in chat)
      none      no main secret (e.g. only extra_secrets / notes)
    `secret_field` overrides the field name (default depends on type: password/token/key/...).
    `extra_secrets` e.g. {"totp_secret": "JBSW..."} or {"api_secret": "..."}.
    `fields` = non-secret extras, e.g. {"host": "db.internal", "port": "5432", "region": "ap-south-1"}.
    policy: open | confirm | sealed | strict (default from config)."""
    field = (secret_field or TYPES.get(type, "secret")).lower()
    value, how = _obtain_secret(k, secret_source, name, field, secret, secret_file, generate_length, generate_kind)
    secrets = dict(extra_secrets or {})
    if value is not None:
        secrets[field] = value
    c = k.add(
        name,
        type,
        username=username,
        secrets=secrets,
        fields=fields,
        urls=urls,
        aliases=aliases,
        tags=tags,
        notes=notes,
        policy=policy,
        expires_at=expires_at,
        rotate_days=rotate_days,
    )
    out = {"added": c.public(), "secret": how}
    if secret_source == "generate":
        out["strength"] = generator.strength(value or "")
    return out


@tool(WRITE)
def update_credential(
    k: Keymaster,
    ref: str,
    name: str | None = None,
    username: str | None = None,
    secret_source: SecretSource = "none",
    secret: str | None = None,
    secret_field: str | None = None,
    secret_file: str | None = None,
    set_secrets: dict[str, str] | None = None,
    remove_secrets: list[str] | None = None,
    fields: dict[str, str] | None = None,
    remove_fields: list[str] | None = None,
    add_urls: list[str] | None = None,
    remove_urls: list[str] | None = None,
    add_aliases: list[str] | None = None,
    remove_aliases: list[str] | None = None,
    add_tags: list[str] | None = None,
    remove_tags: list[str] | None = None,
    notes: str | None = None,
    policy: Policy | None = None,
    expires_at: str | None = None,
    rotate_days: int | None = None,
    reason: str = "",
    generate_length: int = 24,
    generate_kind: Literal["password", "passphrase"] = "password",
) -> dict:
    """Modify a credential. Only the arguments you pass change. To change the main secret use
    secret_source (prompt / clipboard / file / generate / value) — the previous value is kept in
    version history for rollback. Loosening the policy requires the user's approval.
    Use add_urls/add_aliases whenever you learn a new way the user refers to this credential."""
    with k.vault.transaction() as p:
        cur = k._resolve(p, ref)
    secrets: dict[str, str | None] = dict(set_secrets or {})
    for f in remove_secrets or []:
        secrets[f] = None
    field = (secret_field or cur.primary_field).lower()
    value, how = _obtain_secret(k, secret_source, cur.name, field, secret, secret_file, generate_length, generate_kind)
    if value is not None:
        secrets[field] = value
    flds: dict[str, str | None] = dict(fields or {})
    for f in remove_fields or []:
        flds[f] = None
    c, changed = k.update(
        cur.id,
        name=name,
        username=username if username is not None else UNSET,
        secrets=secrets or None,
        fields=flds or None,
        add_urls=add_urls,
        remove_urls=remove_urls,
        add_aliases=add_aliases,
        remove_aliases=remove_aliases,
        add_tags=add_tags,
        remove_tags=remove_tags,
        notes=notes,
        policy=policy,
        expires_at=expires_at if expires_at is not None else UNSET,
        rotate_days=rotate_days if rotate_days is not None else UNSET,
        reason=reason,
    )
    return {"updated": c.public(), "changed": changed or "nothing", "secret": how}


@tool(DESTRUCTIVE)
def delete_credential(k: Keymaster, ref: str) -> dict:
    """Move a credential to the trash (recoverable with restore_credential)."""
    c = k.delete(ref)
    return {"deleted": c.name, "id": c.id, "note": "In trash. restore_credential to undo."}


@tool(WRITE)
def restore_credential(k: Keymaster, ref: str) -> dict:
    """Restore a credential from the trash."""
    c = k.restore(ref)
    return {"restored": c.public()}


@tool(RO)
def list_trash(k: Keymaster) -> dict:
    """List soft-deleted credentials."""
    return {"trash": k.list(deleted=True)}


@tool(DESTRUCTIVE)
def purge_credential(k: Keymaster, ref: str) -> dict:
    """Permanently destroy a trashed credential. Always requires the user's approval."""
    c = k.purge(ref)
    return {"purged": c.name}


@tool(RO)
def credential_history(k: Keymaster, ref: str) -> dict:
    """Previous versions of a credential's secrets (values hidden) for auditing / rollback."""
    return {"versions": k.history(ref)}


@tool(WRITE)
def rollback_credential(k: Keymaster, ref: str, version: int) -> dict:
    """Restore a credential's username+secrets to an earlier version (current one is kept in history)."""
    c = k.rollback(ref, version)
    return {"rolled_back": c.name, "to_version": version}


# ============================================================================ use without revealing
@tool(WORLD)
def http_request(
    k: Keymaster,
    ref: str,
    url: str,
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    json: Any = None,
    auth: str = "auto",
    timeout: float = 30,
    follow_redirects: bool = False,
    allow_any_host: bool = False,
    purpose: str = "",
) -> dict:
    """Make an HTTP request authenticated with a stored credential, without exposing the secret.
    auth: auto (basic for user+password/user+token e.g. Jenkins; bearer for bare tokens),
    basic, bearer, none, header:<Name>, query:<param>. Placeholders {{km.password}},
    {{km.username}}, {{km.token}}, {{km.<field>}} are substituted in url/headers/body.
    Only hosts registered on the credential are allowed (anti-exfiltration guard).
    Response body is scrubbed of the secret."""
    return k.http(
        ref,
        method,
        url,
        purpose,
        headers=headers,
        body=body,
        json_body=json,
        auth=auth,
        timeout=timeout,
        follow_redirects=follow_redirects,
        allow_any_host=allow_any_host,
    )


@tool(WORLD)
def run_with_credential(
    k: Keymaster,
    ref: str,
    command: str,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    timeout: int = 120,
    stdin: str | None = None,
    purpose: str = "",
) -> dict:
    """Run a bash command with the credential injected as environment variables; stdout/stderr
    are scrubbed of the secret (and its base64/url/hex encodings).
    Always set: KM_NAME, KM_USERNAME, KM_SECRET (main secret), KM_<FIELD> for every secret and
    field (KM_PASSWORD, KM_TOKEN, KM_KEY, KM_HOST...), KM_URL, KM_BASIC_AUTH.
    Type extras — aws: AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY/AWS_SESSION_TOKEN/AWS_REGION;
    database: PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE/MYSQL_PWD;
    ssh_key: KM_KEY_FILE (temp 0600 file, shredded after) + GIT_SSH_COMMAND.
    `env` maps extra var names to fields, e.g. {"JENKINS_TOKEN": "token"} or templates
    {"CREDS": "{{km.username}}:{{km.password}}"}. `stdin` also supports {{km.*}} placeholders.
    Example: curl -su "$KM_USERNAME:$KM_TOKEN" https://ci.example.com/api/json"""
    return k.run(ref, command, purpose, env_map=env, cwd=cwd, timeout=max(1, min(timeout, 1800)), stdin=stdin)


@tool(RO)
def get_totp(k: Keymaster, ref: str, purpose: str = "") -> dict:
    """Current 2FA/TOTP code for a credential that has a totp_secret (plus seconds remaining)."""
    return k.totp(ref, purpose)


@tool(WRITE)
def copy_to_clipboard(
    k: Keymaster, ref: str, field: str | None = None, purpose: str = "", seconds: int | None = None
) -> dict:
    """Copy a secret (default: main secret; or 'username', 'totp', any field) to the macOS
    clipboard for the human to paste. Auto-clears after N seconds. The agent never sees it."""
    return k.copy(ref, field, purpose, seconds)


# ============================================================================ utilities
@tool(RO, needs_unlock=False)
def generate_secret(
    k: Keymaster,
    kind: Literal["password", "passphrase"] = "password",
    length: int = 24,
    words: int = 5,
    symbols: bool = True,
    store_in: str | None = None,
    store_field: str | None = None,
    reason: str = "",
) -> dict:
    """Generate a strong password or diceware-style passphrase. With `store_in` (a credential ref)
    it is written straight into that credential (old value kept in history) and NOT returned —
    use this for rotation so the new secret never enters the chat."""
    value = generator.passphrase(words) if kind == "passphrase" else generator.password(length, symbols=symbols)
    info = generator.strength(value)
    if kind == "passphrase":
        info["bits"] = round(generator.passphrase_bits(words), 1)
    if store_in:
        ensure_ready(k)
        with k.vault.transaction() as p:
            cur = k._resolve(p, store_in)
        f = (store_field or cur.primary_field).lower()
        c, _ = k.update(cur.id, secrets={f: value}, reason=reason or "rotated via generate_secret")
        return {
            "stored_in": f"{c.name}.{f}",
            "strength": info,
            "hint": f"Use {{{{km.{f}}}}} in http_request or $KM_{f.upper()} in run_with_credential "
            "to set it on the service.",
        }
    return {"value": value, "strength": info}


@tool(RO)
def health_report(k: Keymaster, check_pwned: bool = False) -> dict:
    """Audit the vault: weak, reused, expired/expiring, stale, unused and (optionally) breached
    passwords via HaveIBeenPwned k-anonymity (only 5 hash chars leave the machine). Graded A–F."""
    return k.health(check_pwned)


@tool(RO)
def audit_log(k: Keymaster, limit: int = 30, ref: str | None = None) -> dict:
    """Recent vault activity (who revealed/used/changed what, when). Optionally for one credential."""
    return {"entries": k.audit_tail(max(1, min(limit, 500)), ref), "chain": k.audit.verify()}


@tool(WRITE, needs_unlock=False)
def lock_vault(k: Keymaster) -> dict:
    """Lock the vault now (removes the key from the keychain). Unlocking needs the user."""
    k.vault.lock()
    k.log("lock")
    return {"locked": True}


@tool(WRITE, needs_unlock=False)
def unlock_vault(k: Keymaster) -> dict:
    """Unlock the vault by asking the user for the master passphrase in a secure dialog
    (the passphrase never passes through the agent)."""
    if not k.vault.exists():
        raise KeymasterError("No vault yet — the user must run `km init` in a terminal.")
    if k.vault.is_unlocked():
        return {"unlocked": True, "note": "already unlocked"}
    secret = k.approver.ask_secret("Keymaster — unlock", "Are you the Keymaster?\n\nEnter the master passphrase:")
    if not secret:
        raise PolicyDenied("User cancelled the unlock dialog.")
    try:
        kind = k.vault.unlock(secret)
    except KeymasterError:
        k.log("unlock", ok=False, via="dialog")
        raise
    k.log("unlock", via="dialog", slot=kind)
    return {"unlocked": True}


@tool(WRITE)
def revoke_approvals(k: Keymaster) -> dict:
    """Cancel every time-boxed 'Allow for …' approval, so the next reveal asks again."""
    return {"revoked": k.revoke_grants()}


@tool(RO, needs_unlock=False)
def credential_types(k: Keymaster) -> dict:
    """The supported credential types and the main secret field of each."""
    return {t: {"main_secret_field": f, "description": TYPE_HELP[t]} for t, f in TYPES.items()}


def main() -> None:
    mcp.run("stdio")


if __name__ == "__main__":
    main()
