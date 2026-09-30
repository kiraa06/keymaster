"""User configuration (~/.keymaster/config.json) and non-secret runtime state (state.json)."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .errors import ValidationError

POLICIES = ("open", "confirm", "sealed", "strict")

DEFAULTS: dict[str, Any] = {
    # Policy for new credentials unless specified. See `km help policies`.
    "default_policy": "confirm",
    # How long an "Allow for a while" approval lasts.
    "grant_minutes": 480,
    # dialog | touchid | deny  (deny = never approve; for headless machines)
    "approval": "dialog",
    # Auto-lock the vault N hours after unlock (0 = stay unlocked until `km lock`).
    "auto_lock_hours": 0,
    # Seconds before a clipboard copy is wiped.
    "clipboard_seconds": 30,
    # Versions of each credential kept for rollback.
    "history_depth": 10,
    # Encrypted snapshots kept in ~/.keymaster/backups.
    "backup_count": 20,
    # Warn when a secret is older than this many days (unless rotate_days is set on it).
    "stale_days": 180,
    # Allow http_request to plain-http URLs (non-localhost).
    "allow_insecure_http": False,
}

_TYPES = {k: type(v) for k, v in DEFAULTS.items()}


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


class JsonFile:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> dict:
        try:
            return json.loads(self.path.read_text())
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError:
            return {}

    def save(self, data: dict) -> None:
        atomic_write(self.path, json.dumps(data, indent=2, sort_keys=True).encode())


class Config(JsonFile):
    def get(self, key: str) -> Any:
        if key not in DEFAULTS:
            raise ValidationError(f"Unknown config key {key!r}. Keys: {', '.join(DEFAULTS)}")
        return self.load().get(key, DEFAULTS[key])

    def all(self) -> dict:
        return {**DEFAULTS, **{k: v for k, v in self.load().items() if k in DEFAULTS}}

    def set(self, key: str, raw: str | Any) -> Any:
        if key not in DEFAULTS:
            raise ValidationError(f"Unknown config key {key!r}. Keys: {', '.join(DEFAULTS)}")
        value = coerce(key, raw)
        data = self.load()
        data[key] = value
        self.save(data)
        return value


def coerce(key: str, raw: Any) -> Any:
    t = _TYPES[key]
    if isinstance(raw, t) and not (t is int and isinstance(raw, bool)):
        value = raw
    elif t is bool:
        value = str(raw).lower() in ("1", "true", "yes", "on")
    elif t is int:
        try:
            value = int(raw)
        except ValueError as e:
            raise ValidationError(f"{key} must be an integer") from e
        if value < 0:
            raise ValidationError(f"{key} must be >= 0")
    else:
        value = str(raw)
    if key == "default_policy" and value not in POLICIES:
        raise ValidationError(f"default_policy must be one of {POLICIES}")
    if key == "approval" and value not in ("dialog", "touchid", "deny"):
        raise ValidationError("approval must be dialog, touchid or deny")
    return value
