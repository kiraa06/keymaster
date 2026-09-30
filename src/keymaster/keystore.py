"""Where the unwrapped DEK lives while the vault is unlocked.

Default: the macOS Keychain (via `keyring`, which calls Security.framework directly, so the key
never appears on a command line). "Unlocked" means the DEK is in the keychain; `km lock`
removes it, after which only the master passphrase or recovery code can re-open the vault.

A second item, the audit key, stays in the keychain even while locked so failed unlock
attempts can still be written to the tamper-evident audit log.
"""

from __future__ import annotations

from typing import Protocol

from .crypto import b64d, b64e
from .errors import KeymasterError

SERVICE = "keymaster"
_HINT = " — on Linux, Keymaster needs a Secret Service provider (GNOME Keyring or KWallet) running in your session."


class KeyStore(Protocol):
    def get(self, name: str) -> bytes | None: ...
    def set(self, name: str, value: bytes) -> None: ...
    def delete(self, name: str) -> None: ...


class KeyringKeyStore:
    def __init__(self) -> None:
        try:
            import keyring
            from keyring.errors import PasswordDeleteError
        except ImportError as e:  # pragma: no cover
            raise KeymasterError("The `keyring` package is required.") from e
        self._kr = keyring
        self._del_err = PasswordDeleteError

    def get(self, name: str) -> bytes | None:
        try:
            v = self._kr.get_password(SERVICE, name)
        except Exception as e:  # keychain denied / no backend
            raise KeymasterError(f"Keychain unavailable: {e}{_HINT}") from e
        return b64d(v) if v else None

    def set(self, name: str, value: bytes) -> None:
        try:
            self._kr.set_password(SERVICE, name, b64e(value))
        except Exception as e:
            raise KeymasterError(f"Could not write to keychain: {e}{_HINT}") from e

    def delete(self, name: str) -> None:
        try:
            self._kr.delete_password(SERVICE, name)
        except self._del_err:
            pass


class MemoryKeyStore:
    """For tests only."""

    def __init__(self) -> None:
        self.items: dict[str, bytes] = {}

    def get(self, name: str) -> bytes | None:
        return self.items.get(name)

    def set(self, name: str, value: bytes) -> None:
        self.items[name] = value

    def delete(self, name: str) -> None:
        self.items.pop(name, None)


def dek_name(vault_id: str) -> str:
    return f"dek:{vault_id}"


def audit_key_name(vault_id: str) -> str:
    return f"audit:{vault_id}"
