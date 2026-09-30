"""Use a credential without revealing it: env-injected commands and authenticated HTTP."""

from __future__ import annotations

import base64
import os
import re
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from urllib.parse import urlsplit

import httpx

from .errors import PolicyDenied, ValidationError
from .models import Credential
from .redact import Redactor
from .resolver import host_allowed

MAX_OUTPUT = 60_000
ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]*$")
PLACEHOLDER = re.compile(r"\{\{\s*km\.([a-z][a-z0-9_]*)\s*\}\}")


def _value(cred: Credential, key: str) -> str | None:
    if key == "username":
        return cred.username
    if key in ("secret", "primary"):
        return cred.primary_secret
    if key == "basic_auth":
        return base64.b64encode(f"{cred.username or ''}:{cred.primary_secret or ''}".encode()).decode()
    if key == "url":
        return cred.urls[0] if cred.urls else None
    return cred.secrets.get(key) or cred.fields.get(key)


def fill_placeholders(text: str, cred: Credential) -> str:
    """Replace {{km.password}}, {{km.username}}, {{km.<field>}} — inside our process only."""

    def sub(m: re.Match) -> str:
        v = _value(cred, m.group(1))
        if v is None:
            raise ValidationError(f"Credential '{cred.name}' has no field '{m.group(1)}'")
        return v

    return PLACEHOLDER.sub(sub, text)


def _truncate(s: str) -> str:
    return s if len(s) <= MAX_OUTPUT else s[:MAX_OUTPUT] + f"\n…[truncated {len(s) - MAX_OUTPUT} chars]"


@contextmanager
def credential_env(cred: Credential, mapping: dict[str, str] | None = None) -> Iterator[dict[str, str]]:
    env: dict[str, str] = {"KM_NAME": cred.name}
    tmpfiles: list[str] = []
    if cred.username:
        env["KM_USERNAME"] = cred.username
    if cred.primary_secret:
        env["KM_SECRET"] = cred.primary_secret
    for k, v in {**cred.fields, **cred.secrets}.items():
        env[f"KM_{k.upper()}"] = v
    if cred.urls:
        env["KM_URL"] = cred.urls[0]
    if cred.username and cred.primary_secret:
        env["KM_BASIC_AUTH"] = _value(cred, "basic_auth")  # type: ignore[assignment]

    if cred.type == "aws":
        env["AWS_ACCESS_KEY_ID"] = cred.username or cred.secrets.get("access_key_id", "")
        env["AWS_SECRET_ACCESS_KEY"] = cred.secrets.get("secret_access_key", "")
        if "session_token" in cred.secrets:
            env["AWS_SESSION_TOKEN"] = cred.secrets["session_token"]
        if "region" in cred.fields:
            env["AWS_REGION"] = env["AWS_DEFAULT_REGION"] = cred.fields["region"]
    elif cred.type == "database":
        pw = cred.secrets.get("password", "")
        env.update(PGPASSWORD=pw, MYSQL_PWD=pw)
        if cred.username:
            env["PGUSER"] = cred.username
        for f, var in (("host", "PGHOST"), ("port", "PGPORT"), ("database", "PGDATABASE")):
            if f in cred.fields:
                env[var] = cred.fields[f]
    elif cred.type in ("ssh_key", "certificate") and "private_key" in cred.secrets:
        fd, path = tempfile.mkstemp(prefix="km-key-", dir=os.environ.get("TMPDIR"))
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as fh:
            key = cred.secrets["private_key"]
            fh.write(key if key.endswith("\n") else key + "\n")
        tmpfiles.append(path)
        env["KM_KEY_FILE"] = path
        if cred.type == "ssh_key":
            env["GIT_SSH_COMMAND"] = f"ssh -i {path} -o IdentitiesOnly=yes"

    for var, key in (mapping or {}).items():
        if not ENV_NAME.match(var):
            raise ValidationError(f"Invalid env var name {var!r}")
        v = fill_placeholders(key, cred) if "{{" in key else _value(cred, key)
        if v is None:
            raise ValidationError(f"Credential '{cred.name}' has no field '{key}' for ${var}")
        env[var] = v
    try:
        yield env
    finally:
        for p in tmpfiles:
            try:
                with open(p, "r+b") as fh:  # overwrite before unlinking
                    fh.write(b"\0" * os.path.getsize(p))
                os.unlink(p)
            except OSError:
                pass


def run_command(
    cred: Credential,
    command: str,
    *,
    env_map: dict[str, str] | None = None,
    cwd: str | None = None,
    timeout: int = 120,
    stdin: str | None = None,
) -> dict:
    red = Redactor([cred])
    if stdin:
        stdin = fill_placeholders(stdin, cred)
    with credential_env(cred, env_map) as injected:
        try:
            p = subprocess.run(
                ["/bin/bash", "-c", command],
                env={**os.environ, **injected},
                cwd=os.path.expanduser(cwd) if cwd else None,
                capture_output=True,
                text=True,
                input=stdin,
                timeout=timeout,
            )
            code, out, err = p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired as e:
            code = -1
            out = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
            err = (
                e.stderr.decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
            ) + f"\n[timed out after {timeout}s]"
    return {
        "exit_code": code,
        "stdout": _truncate(red(out)),
        "stderr": _truncate(red(err)),
        "injected_env": sorted(injected),
    }


def _auth_style(cred: Credential, requested: str) -> str:
    if requested != "auto":
        return requested
    if cred.fields.get("auth_style"):
        return cred.fields["auth_style"]
    if cred.type in ("password", "database"):
        return "basic"
    if cred.type == "token":
        return "basic" if cred.username else "bearer"  # e.g. Jenkins user:api-token
    if cred.type == "api_key":
        return "header:X-API-Key"
    return "bearer"


def http_request(
    cred: Credential,
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: str | None = None,
    json_body: object | None = None,
    auth: str = "auto",
    timeout: float = 30,
    allow_any_host: bool = False,
    allow_insecure: bool = False,
    follow_redirects: bool = False,
    verify_tls: bool = True,
) -> dict:
    target = fill_placeholders(url, cred)
    parts = urlsplit(target)
    if parts.scheme not in ("http", "https"):
        raise ValidationError("URL must be http(s)")
    local = parts.hostname in ("localhost", "127.0.0.1", "::1")
    if parts.scheme == "http" and not (local or allow_insecure):
        raise PolicyDenied("Refusing to send credentials over plain http. Use https (or enable allow_insecure_http).")
    if not allow_any_host and not host_allowed(cred, target):
        registered = ", ".join(cred.urls) or "none"
        raise PolicyDenied(
            f"Host '{parts.hostname}' is not registered for credential '{cred.name}' (registered: {registered}). "
            "This guard stops credentials leaking to the wrong server. Add the URL to the credential "
            "(update_credential add_urls=[...]) if it really belongs there."
        )
    hdrs = {k: fill_placeholders(v, cred) for k, v in (headers or {}).items()}
    style = _auth_style(cred, auth)
    secret = cred.primary_secret or ""
    basic = None
    if style == "basic":
        basic = httpx.BasicAuth(cred.username or "", secret)
    elif style == "bearer":
        hdrs.setdefault("Authorization", f"Bearer {secret}")
    elif style.startswith("header:"):
        hdrs.setdefault(style.split(":", 1)[1], secret)
    elif style.startswith("query:"):
        param = style.split(":", 1)[1]
        target += ("&" if parts.query else "?") + httpx.QueryParams({param: secret}).__str__()
    elif style != "none":
        raise ValidationError("auth must be auto, basic, bearer, none, header:<Name> or query:<param>")
    content = fill_placeholders(body, cred) if body is not None else None
    red = Redactor([cred])
    with httpx.Client(timeout=timeout, follow_redirects=False, verify=verify_tls) as client:
        resp = client.request(method.upper(), target, headers=hdrs, content=content, json=json_body, auth=basic)
        hops = 0
        # Only follow redirects that stay on a registered host — never forward auth elsewhere.
        while follow_redirects and resp.is_redirect and hops < 5:
            nxt = str(resp.next_request.url) if resp.next_request else None
            if not nxt or not (allow_any_host or host_allowed(cred, nxt)):
                break
            resp = client.send(resp.next_request)
            hops += 1
    keep = ("content-type", "location", "x-jenkins", "x-ratelimit-remaining", "www-authenticate", "retry-after")
    return {
        "status": resp.status_code,
        "reason": resp.reason_phrase,
        "url": red(str(resp.url)),
        "auth_style": style,
        "headers": {k: red(v) for k, v in resp.headers.items() if k.lower() in keep},
        "body": _truncate(red(resp.text)),
    }
