"""Claude Code `UserPromptSubmit` hook: nudge the agent to check Keymaster first.

MCP server instructions are easy to miss: with many servers configured, Claude Code defers MCP
tools (only their names are visible) and truncates long instructions. This hook runs on every
prompt and, when the prompt smells like it needs credentials, injects a short, specific
reminder — including which stored credentials match, if the vault is unlocked.

It must be fast and must never break a prompt: every failure path exits 0 silently.
Only credential *names* are ever printed — never secrets.
"""

from __future__ import annotations

import json
import re
import sys

INTENT = re.compile(
    r"\b("
    r"creds?|credentials?|passwords?|passwd|passphrases?|log ?in|sign ?in|logon|auth(?:enticate|entication|orize)?|"
    r"tokens?|api[ _-]?keys?|secrets?|ssh[ _-]?keys?|private[ _-]?keys?|access[ _-]?keys?|keys? for|"
    r"2fa|mfa|otp|totp|one[ -]time code|verification code|"
    r"keychain|vault|keymaster|basic auth|bearer|pat|personal access token|service account"
    r")\b",
    re.IGNORECASE,
)
URL = re.compile(r"\bhttps?://[^\s)>\]\"']+", re.IGNORECASE)
HOSTISH = re.compile(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\.[a-z]{2,}\b", re.IGNORECASE)
WORD = re.compile(r"[a-z0-9][a-z0-9._-]{2,}", re.IGNORECASE)

REMINDER = (
    "[keymaster] This request may need credentials. The user's credential vault is Keymaster — "
    "check it FIRST, before env vars, dotfiles, ~/.aws, `gh auth`, the OS keychain or the repo: "
    "call `mcp__keymaster__find_credentials` with the URL/host/service name "
    '(or `mcp__keymaster__list_credentials` for "what creds do you have"). '
    'If those tools aren\'t loaded yet, load them with ToolSearch query "keymaster". '
    "Prefer `http_request` / `run_with_credential` over revealing secrets. "
    'If Keymaster has no match, say so and offer `add_credential(secret_source="prompt")`.'
)


def _labels(vault=None) -> list[tuple[str, list[str]]]:
    """(name, match-terms) for every live credential — only if the vault is already unlocked."""
    try:
        from .models import Credential
        from .resolver import parse_target
        from .vault import Vault

        v = vault or Vault()
        if not v.exists() or not v.is_unlocked():
            return []
        out = []
        with v.transaction() as p:
            for d in p["credentials"].values():
                if d.get("deleted_at"):
                    continue
                c = Credential.from_dict(d)
                terms = [c.name.lower(), *c.aliases]
                for u in c.urls:
                    t = parse_target(u)
                    if t and "*" not in t.host:
                        terms.append(t.host)
                if c.fields.get("host"):
                    terms.append(c.fields["host"].lower())
                out.append((c.name, [t for t in terms if len(t) >= 3]))
        return out
    except Exception:
        return []


def matching_credentials(prompt: str, labels: list[tuple[str, list[str]]]) -> list[str]:
    low = prompt.lower()
    words = set(WORD.findall(low))
    hits = []
    for name, terms in labels:
        for t in terms:
            multiword = " " in t or "." in t
            if (multiword and t in low) or t in words:
                hits.append(name)
                break
    return hits[:5]


def build_context(prompt: str, vault=None) -> str | None:
    intent = bool(INTENT.search(prompt))
    urls = URL.findall(prompt) or HOSTISH.findall(prompt)
    hits = matching_credentials(prompt, _labels(vault)) if (intent or urls or len(prompt) < 2000) else []
    if not (intent or hits):
        return None  # a URL alone (e.g. "summarise this docs page") isn't a credential signal
    msg = REMINDER
    if hits:
        msg += " Stored credentials that look relevant: " + ", ".join(hits) + "."
    return msg


def main() -> None:
    try:
        data = json.load(sys.stdin)
        prompt = data.get("prompt") or ""
        if not prompt.strip():
            return
        ctx = build_context(prompt)
        if ctx:
            json.dump(
                {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": ctx}}, sys.stdout
            )
    except Exception:
        return


if __name__ == "__main__":
    main()
