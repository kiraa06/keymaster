"""Tamper-evident audit log.

Each JSONL entry carries `mac = HMAC(audit_key, prev_mac || canonical(entry))`, forming a hash
chain: editing, deleting or re-ordering any line breaks verification from that point on.
The log never contains secret values — only who touched which credential, when, and why.
"""

from __future__ import annotations

import fcntl
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import crypto

GENESIS = "0" * 64


def _canonical(entry: dict) -> bytes:
    body = {k: v for k, v in entry.items() if k != "mac"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


class AuditLog:
    def __init__(self, path: Path, key_provider) -> None:
        self.path = path
        self._key = key_provider

    def append(self, action: str, *, actor: str, ok: bool = True, cred=None, **detail: Any) -> None:
        key = self._key()
        entry: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "actor": actor,
            "action": action,
            "ok": ok,
        }
        if cred is not None:
            entry["cred_id"], entry["cred"] = cred.id, cred.name
        if detail:
            entry["detail"] = {k: v for k, v in detail.items() if v not in (None, "")}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "r+b") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                last = _last_line(fh)
                prev = json.loads(last) if last else None
                entry["seq"] = (prev["seq"] + 1) if prev else 1
                entry["prev"] = (prev.get("mac") or GENESIS) if prev else GENESIS
                entry["mac"] = crypto.mac(key, entry["prev"].encode() + _canonical(entry)) if key else None
                fh.seek(0, os.SEEK_END)
                fh.write((json.dumps(entry, separators=(",", ":")) + "\n").encode())
                fh.flush()
                os.fsync(fh.fileno())
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    def entries(self) -> list[dict]:
        try:
            lines = self.path.read_text().splitlines()
        except FileNotFoundError:
            return []
        out = []
        for ln in lines:
            try:
                out.append(json.loads(ln))
            except json.JSONDecodeError:
                out.append({"corrupt": ln[:80]})
        return out

    def tail(self, limit: int = 50, cred_id: str | None = None, action: str | None = None) -> list[dict]:
        es = [e for e in self.entries() if "corrupt" not in e]
        if cred_id:
            es = [e for e in es if e.get("cred_id") == cred_id]
        if action:
            es = [e for e in es if e.get("action") == action]
        return es[-limit:]

    def verify(self) -> dict:
        key = self._key()
        if key is None:
            return {"ok": False, "reason": "audit key unavailable (vault never unlocked on this machine?)"}
        prev, count = GENESIS, 0
        for i, e in enumerate(self.entries(), 1):
            if "corrupt" in e:
                return {"ok": False, "entries": count, "broken_at_line": i, "reason": "unparseable line"}
            if e.get("prev") != prev:
                return {
                    "ok": False,
                    "entries": count,
                    "broken_at_line": i,
                    "reason": "chain link mismatch (line removed or reordered)",
                }
            if e.get("mac") is None or not crypto.mac_ok(key, prev.encode() + _canonical(e), e["mac"]):
                return {"ok": False, "entries": count, "broken_at_line": i, "reason": "MAC mismatch (line edited)"}
            prev, count = e["mac"], count + 1
        return {"ok": True, "entries": count}


def _last_line(fh) -> str | None:
    fh.seek(0, os.SEEK_END)
    size = fh.tell()
    if size == 0:
        return None
    block = min(size, 8192)
    while True:
        fh.seek(size - block)
        chunk = fh.read(block)
        lines = chunk.rstrip(b"\n").split(b"\n")
        if len(lines) > 1 or block == size:
            return lines[-1].decode() or None
        block = min(size, block * 2)
