"""Wire Keymaster into Claude Code so the agent reliably checks it first.

Three layers, installed by `km install-mcp` and removed by `km uninstall-mcp`:

1. the MCP server itself (`claude mcp add`)
2. a `UserPromptSubmit` hook in ~/.claude/settings.json (see hook.py)
3. a short rule block in ~/.claude/CLAUDE.md, between markers so it can be removed cleanly
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from .config import atomic_write

START = "<!-- keymaster:start -->"
END = "<!-- keymaster:end -->"

CLAUDE_MD_BLOCK = f"""{START}
# Credentials — check Keymaster first

Keymaster (MCP server `keymaster`) is my credential vault and the source of truth for my
passwords, tokens, API keys, SSH/AWS keys, database logins and 2FA seeds.

- Whenever a task needs credentials — I ask what creds exist, a login, an API call, a CLI or DB
  that needs auth, a 2FA code — call `mcp__keymaster__find_credentials` (or
  `list_credentials`) BEFORE anything else. If its tools are deferred, load them with
  ToolSearch "keymaster".
- Don't hunt for secrets in env vars, dotfiles, `~/.aws`, `gh auth`, the OS keychain or the repo
  unless Keymaster has no match — then tell me, and offer `add_credential(secret_source="prompt")`.
- Prefer `http_request` / `run_with_credential` over revealing a secret; never echo a revealed one.
{END}"""


def claude_dir() -> Path:
    return Path.home() / ".claude"


# ---------------------------------------------------------------- CLAUDE.md
def install_claude_md(path: Path) -> str:
    text = path.read_text() if path.exists() else ""
    if START in text and END in text:
        before, rest = text.split(START, 1)
        _, after = rest.split(END, 1)
        new = before + CLAUDE_MD_BLOCK + after
        status = "updated" if new != text else "unchanged"
    else:
        if text and not text.endswith("\n"):
            text += "\n"
        new = text + ("\n" if text else "") + CLAUDE_MD_BLOCK + "\n"
        status = "added"
    if new != text:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(path, new.encode(), mode=0o644)
    return status


def remove_claude_md(path: Path) -> bool:
    if not path.exists():
        return False
    text = path.read_text()
    if START not in text or END not in text:
        return False
    before, rest = text.split(START, 1)
    _, after = rest.split(END, 1)
    new = before.rstrip("\n") + ("\n" if before.strip() else "") + after.lstrip("\n")
    atomic_write(path, new.encode(), mode=0o644)
    return True


# ---------------------------------------------------------------- settings.json hook
def _is_ours(hook: dict) -> bool:
    return "keymaster-hook" in str(hook.get("command", ""))


def install_hook(settings: Path, command: str) -> str:
    data = json.loads(settings.read_text()) if settings.exists() else {}
    groups = data.setdefault("hooks", {}).setdefault("UserPromptSubmit", [])
    for g in groups:
        for h in g.get("hooks", []):
            if _is_ours(h):
                if h.get("command") == command:
                    return "unchanged"
                h["command"] = command
                _save(settings, data)
                return "updated"
    groups.append({"hooks": [{"type": "command", "command": command, "timeout": 5}]})
    _save(settings, data)
    return "added"


def remove_hook(settings: Path) -> bool:
    if not settings.exists():
        return False
    data = json.loads(settings.read_text())
    groups = data.get("hooks", {}).get("UserPromptSubmit", [])
    changed = False
    for g in groups:
        before = len(g.get("hooks", []))
        g["hooks"] = [h for h in g.get("hooks", []) if not _is_ours(h)]
        changed |= len(g["hooks"]) != before
    data["hooks"]["UserPromptSubmit"] = [g for g in groups if g.get("hooks")] if groups else groups
    if not data["hooks"]["UserPromptSubmit"]:
        data["hooks"].pop("UserPromptSubmit")
    if not data["hooks"]:
        data.pop("hooks")
    if changed:
        _save(settings, data)
    return changed


def _save(settings: Path, data: dict) -> None:
    if settings.exists():
        shutil.copy2(settings, settings.with_name(settings.name + ".keymaster.bak"))
    atomic_write(settings, (json.dumps(data, indent=2) + "\n").encode(), mode=0o644)
