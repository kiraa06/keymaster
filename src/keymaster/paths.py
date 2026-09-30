"""Filesystem layout. Everything lives under ~/.keymaster (override with KEYMASTER_HOME)."""

from __future__ import annotations

import os
from pathlib import Path


def home() -> Path:
    return Path(os.environ.get("KEYMASTER_HOME") or Path.home() / ".keymaster").expanduser()


class Layout:
    def __init__(self, root: Path | None = None) -> None:
        self.root = Path(root) if root else home()

    @property
    def vault(self) -> Path:
        return self.root / "vault.km"

    @property
    def lock(self) -> Path:
        return self.root / ".vault.lock"

    @property
    def audit(self) -> Path:
        return self.root / "audit.jsonl"

    @property
    def state(self) -> Path:
        return self.root / "state.json"

    @property
    def config(self) -> Path:
        return self.root / "config.json"

    @property
    def backups(self) -> Path:
        return self.root / "backups"

    @property
    def bin(self) -> Path:
        return self.root / "bin"

    def ensure(self) -> None:
        for d in (self.root, self.backups, self.bin):
            d.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(d, 0o700)
