"""Scrub secret values (and their common encodings) out of text before the agent sees it."""

from __future__ import annotations

import base64
from urllib.parse import quote

from .models import Credential

MIN_LEN = 4


def variants(value: str) -> set[str]:
    out = {value}
    raw = value.encode()
    out.add(base64.b64encode(raw).decode())
    out.add(base64.b64encode(raw).decode().rstrip("="))
    out.add(base64.urlsafe_b64encode(raw).decode().rstrip("="))
    out.add(quote(value, safe=""))
    out.add(raw.hex())
    out.add(value.replace("\n", "\\n"))  # JSON-escaped multi-line keys
    return {v for v in out if len(v) >= MIN_LEN}


class Redactor:
    def __init__(self, creds: list[Credential] | None = None) -> None:
        self._map: dict[str, str] = {}
        for c in creds or []:
            self.add(c)

    def add(self, cred: Credential) -> None:
        for fieldname, value in cred.secrets.items():
            label = f"«redacted:{cred.name}.{fieldname}»"
            for v in variants(value):
                self._map.setdefault(v, label)
            for line in value.splitlines():  # PEM bodies, multi-line notes
                if len(line) >= 16:
                    self._map.setdefault(line, label)
        if cred.username and cred.secrets.get(cred.primary_field):
            basic = f"{cred.username}:{cred.secrets[cred.primary_field]}"
            for v in variants(basic):
                self._map.setdefault(v, f"«redacted:{cred.name}.basic-auth»")

    def __call__(self, text: str) -> str:
        if not text:
            return text
        for needle in sorted(self._map, key=len, reverse=True):
            if needle in text:
                text = text.replace(needle, self._map[needle])
        return text
