"""Credential model."""

from __future__ import annotations

import re
import secrets
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime
from typing import Any

from .config import POLICIES
from .errors import ValidationError

# type -> primary secret field
TYPES: dict[str, str] = {
    "password": "password",  # user + password (web logins, Jenkins, VPN...)
    "token": "token",  # bearer / personal access tokens
    "api_key": "key",  # API keys (optionally with api_secret)
    "ssh_key": "private_key",  # SSH private key (+ optional passphrase)
    "aws": "secret_access_key",  # username = access key id
    "database": "password",  # fields: host, port, database
    "certificate": "private_key",
    "totp": "totp_secret",  # standalone 2FA seed
    "note": "note",  # secure note
    "custom": "secret",
}

TYPE_HELP = {
    "password": "username + password (web logins, Jenkins, VPN)",
    "token": "bearer / personal access token",
    "api_key": "API key (optionally api_secret)",
    "ssh_key": "SSH private key (+ passphrase)",
    "aws": "AWS access key id (username) + secret_access_key (+ session_token)",
    "database": "DB login; fields host/port/database",
    "certificate": "TLS cert/private key",
    "totp": "standalone 2FA seed",
    "note": "secure note",
    "custom": "anything else",
}

NAME_RE = re.compile(r"^[\w@.+/:-][\w @.+/:-]{0,79}$")
FIELD_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def new_id() -> str:
    return "km_" + secrets.token_hex(4)


def _clean_list(values: list[str] | None, lower: bool = False) -> list[str]:
    out: list[str] = []
    for v in values or []:
        v = v.strip()
        if lower:
            v = v.lower()
        if v and v not in out:
            out.append(v)
    return out


@dataclass
class Credential:
    id: str
    name: str
    type: str
    username: str | None = None
    secrets: dict[str, str] = field(default_factory=dict)
    fields: dict[str, str] = field(default_factory=dict)
    urls: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    notes: str = ""
    policy: str = "confirm"
    expires_at: str | None = None
    rotate_days: int | None = None
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)
    secret_changed_at: str = field(default_factory=now_iso)
    last_used_at: str | None = None
    use_count: int = 0
    deleted_at: str | None = None
    history: list[dict[str, Any]] = field(default_factory=list)

    # ------------------------------------------------------------------ serde
    @classmethod
    def from_dict(cls, d: dict) -> Credential:
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})

    def to_dict(self) -> dict:
        return asdict(self)

    # ------------------------------------------------------------------ helpers
    @property
    def primary_field(self) -> str:
        return TYPES.get(self.type, "secret")

    @property
    def primary_secret(self) -> str | None:
        return self.secrets.get(self.primary_field) or next(iter(self.secrets.values()), None)

    @property
    def deleted(self) -> bool:
        return self.deleted_at is not None

    def labels(self) -> list[str]:
        return [self.name, *self.aliases]

    def validate(self) -> None:
        if self.type not in TYPES:
            raise ValidationError(f"Unknown type {self.type!r}. Types: {', '.join(TYPES)}")
        if not NAME_RE.match(self.name):
            raise ValidationError(f"Invalid name {self.name!r}: 1-80 chars of letters, digits, space, @ . + / : _ -")
        for a in self.aliases:
            if not NAME_RE.match(a):
                raise ValidationError(f"Invalid alias {a!r}")
        for k in [*self.secrets, *self.fields]:
            if not FIELD_RE.match(k):
                raise ValidationError(f"Invalid field name {k!r} (lower_snake_case, max 40)")
        overlap = set(self.secrets) & set(self.fields)
        if overlap:
            raise ValidationError(f"{sorted(overlap)} cannot be both a secret and a plain field")
        if self.policy not in POLICIES:
            raise ValidationError(f"policy must be one of {POLICIES}")
        for u in self.urls:
            if any(c.isspace() for c in u):
                raise ValidationError(f"URL pattern {u!r} contains whitespace")
        if self.expires_at:
            try:
                date.fromisoformat(self.expires_at[:10])
            except ValueError as e:
                raise ValidationError("expires_at must be YYYY-MM-DD") from e
        if self.rotate_days is not None and self.rotate_days <= 0:
            raise ValidationError("rotate_days must be positive")
        if not self.secrets and self.type != "note":
            raise ValidationError("A credential needs at least one secret value.")

    def normalize(self) -> None:
        self.name = self.name.strip()
        self.aliases = [a for a in _clean_list(self.aliases, lower=True) if a != self.name.lower()]
        self.tags = _clean_list(self.tags, lower=True)
        self.urls = _clean_list(self.urls)
        self.secrets = {k.strip().lower(): v for k, v in self.secrets.items() if v not in (None, "")}
        self.fields = {k.strip().lower(): str(v) for k, v in self.fields.items() if v not in (None, "")}
        if self.username is not None:
            self.username = self.username.strip() or None

    # ------------------------------------------------------------------ status
    def warnings(self, stale_days: int = 180) -> list[str]:
        out = []
        today = date.today()
        if self.expires_at:
            exp = date.fromisoformat(self.expires_at[:10])
            days = (exp - today).days
            if days < 0:
                out.append(f"EXPIRED {-days} day(s) ago")
            elif days <= 14:
                out.append(f"expires in {days} day(s)")
        changed = datetime.fromisoformat(self.secret_changed_at).date()
        age = (today - changed).days
        limit = self.rotate_days or stale_days
        if limit and age > limit:
            out.append(f"secret is {age} days old (rotate every {limit})")
        return out

    def public(self, stale_days: int = 180) -> dict:
        """Everything the agent may see without a reveal: secrets are replaced by shape info."""
        d = self.to_dict()
        d["secrets"] = {k: f"<hidden: {len(v)} chars>" for k, v in self.secrets.items()}
        d["history"] = len(self.history)
        d["has_totp"] = "totp_secret" in self.secrets
        w = self.warnings(stale_days)
        if w:
            d["warnings"] = w
        return {k: v for k, v in d.items() if v not in (None, [], {}, "")}

    def snapshot(self, reason: str) -> dict:
        return {
            "version": len(self.history) + 1,
            "at": now_iso(),
            "reason": reason,
            "username": self.username,
            "secrets": dict(self.secrets),
            "fields": dict(self.fields),
        }
