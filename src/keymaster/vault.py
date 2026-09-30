"""On-disk vault: envelope-encrypted, atomically written, file-locked, backed up.

File format (JSON, so it is inspectable with `jq` — only ciphertext is sensitive):

    {
      "format": "keymaster-vault", "version": 1, "vault_id": "...", "generation": 42,
      "slots":   [{"kind": "passphrase", "kdf": {...}, "wrapped": {"nonce","ct"}},
                  {"kind": "recovery",   "kdf": {...}, "wrapped": {...}}],
      "payload": {"nonce": "...", "ct": "..."}          # AES-256-GCM(DEK, payload-json)
    }

`generation` increments on every write and is bound into the payload AAD, so an attacker
cannot splice an old payload under a new header; `state.json` remembers the highest
generation seen so restoring an old vault file (rollback) is detected and reported.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import shutil
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import crypto
from .config import Config, JsonFile, atomic_write
from .errors import (
    BadPassphrase,
    KeymasterError,
    LockedOut,
    VaultCorrupted,
    VaultLocked,
    VaultNotInitialized,
)
from .keystore import KeyringKeyStore, KeyStore, audit_key_name, dek_name
from .paths import Layout

FORMAT = "keymaster-vault"
VERSION = 1
SCHEMA = 1
FREE_ATTEMPTS = 5


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _slot_aad(vault_id: str, kind: str) -> bytes:
    return f"keymaster-slot:v{VERSION}:{vault_id}:{kind}".encode()


def _payload_aad(vault_id: str, generation: int) -> bytes:
    return f"keymaster-payload:v{VERSION}:{vault_id}:{generation}".encode()


def empty_payload() -> dict:
    return {"schema": SCHEMA, "credentials": {}, "grants": {}, "meta": {"created_at": now_iso()}}


def make_slot(vault_id: str, kind: str, secret: str, dek: bytes, kdf_params: dict | None) -> dict:
    kdf = crypto.new_kdf(kdf_params)
    kek = crypto.derive_kek(secret, kdf)
    return {
        "kind": kind,
        "kdf": kdf,
        "wrapped": crypto.seal(kek, dek, _slot_aad(vault_id, kind)),
        "created_at": now_iso(),
    }


def seal_document(doc: dict, payload: dict, dek: bytes) -> dict:
    payload = {**payload, "generation": doc["generation"]}
    blob = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    doc["payload"] = crypto.seal(dek, blob, _payload_aad(doc["vault_id"], doc["generation"]))
    return doc


def open_document(doc: dict, dek: bytes) -> dict:
    try:
        raw = crypto.unseal(dek, doc["payload"], _payload_aad(doc["vault_id"], doc["generation"]))
    except BadPassphrase as e:
        raise VaultCorrupted("Vault payload failed authentication — the file was modified or the key is wrong.") from e
    payload = json.loads(raw)
    if payload.get("generation") != doc["generation"]:
        raise VaultCorrupted("Generation mismatch between header and payload.")
    return payload


def unwrap_with(doc: dict, secret: str) -> tuple[bytes, str]:
    """Try every slot that could plausibly match `secret`. Returns (dek, slot_kind)."""
    slots = doc.get("slots", [])
    candidates = [s for s in slots if s["kind"] == "passphrase"]
    if crypto.looks_like_recovery_code(secret):
        secret_rc = crypto.normalize_recovery_code(secret)
        candidates = [s for s in slots if s["kind"] == "recovery"] + candidates
    for slot in candidates:
        attempt = secret_rc if slot["kind"] == "recovery" else secret
        try:
            kek = crypto.derive_kek(attempt, slot["kdf"])
            dek = crypto.unseal(kek, slot["wrapped"], _slot_aad(doc["vault_id"], slot["kind"]))
            return dek, slot["kind"]
        except BadPassphrase:
            continue
    raise BadPassphrase("Wrong passphrase or recovery code.")


def read_document(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text())
    except FileNotFoundError:
        raise VaultNotInitialized() from None
    except json.JSONDecodeError as e:
        raise VaultCorrupted(f"{path} is not valid JSON: {e}") from e
    if doc.get("format") != FORMAT:
        raise VaultCorrupted(f"{path} is not a Keymaster vault.")
    if doc.get("version") != VERSION:
        raise VaultCorrupted(f"Unsupported vault version {doc.get('version')}.")
    return doc


class Vault:
    def __init__(self, root: Path | None = None, keystore: KeyStore | None = None) -> None:
        self.layout = Layout(root)
        self._keystore = keystore
        self.config = Config(self.layout.config)
        self.state = JsonFile(self.layout.state)
        self.rollback_warning: str | None = None
        self._kdf_params: dict | None = None  # tests inject cheap params

    # ---------------------------------------------------------------- plumbing
    @property
    def keystore(self) -> KeyStore:
        if self._keystore is None:
            self._keystore = KeyringKeyStore()
        return self._keystore

    def exists(self) -> bool:
        return self.layout.vault.exists()

    def document(self) -> dict:
        return read_document(self.layout.vault)

    @property
    def vault_id(self) -> str:
        return self.document()["vault_id"]

    @contextlib.contextmanager
    def _flock(self, exclusive: bool) -> Iterator[None]:
        self.layout.ensure()
        with open(self.layout.lock, "a+") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    def _update_state(self, **changes: Any) -> None:
        st = self.state.load()
        st.update(changes)
        self.state.save(st)

    # ---------------------------------------------------------------- lifecycle
    def create(self, passphrase: str) -> str:
        """Create a new vault. Returns the one-time recovery code."""
        if self.exists():
            raise KeymasterError(f"A vault already exists at {self.layout.vault}.")
        if len(passphrase) < 10:
            raise KeymasterError("Master passphrase must be at least 10 characters.")
        self.layout.ensure()
        vault_id = uuid.uuid4().hex
        dek, audit_key = crypto.random_key(), crypto.random_key()
        recovery = crypto.new_recovery_code()
        doc = {
            "format": FORMAT,
            "version": VERSION,
            "vault_id": vault_id,
            "created_at": now_iso(),
            "generation": 1,
            "slots": [
                make_slot(vault_id, "passphrase", passphrase, dek, self._kdf_params),
                make_slot(vault_id, "recovery", recovery, dek, self._kdf_params),
            ],
        }
        payload = empty_payload()
        payload["meta"]["audit_key"] = crypto.b64e(audit_key)
        with self._flock(exclusive=True):
            atomic_write(self.layout.vault, json.dumps(seal_document(doc, payload, dek), indent=1).encode())
        self.keystore.set(dek_name(vault_id), dek)
        self.keystore.set(audit_key_name(vault_id), audit_key)
        self.state.save({"unlocked_at": time.time(), "last_generation": 1, "failed_attempts": 0})
        return recovery

    def _check_lockout(self) -> None:
        until = self.state.load().get("lockout_until", 0)
        if until > time.time():
            raise LockedOut(f"Too many failed attempts. Try again in {int(until - time.time()) + 1}s.")

    def _record_failure(self) -> str:
        st = self.state.load()
        fails = int(st.get("failed_attempts", 0)) + 1
        st["failed_attempts"] = fails
        st["last_failed_at"] = time.time()
        msg = f"Wrong passphrase or recovery code ({fails} consecutive failures)."
        if fails >= FREE_ATTEMPTS:
            delay = min(30 * 2 ** (fails - FREE_ATTEMPTS), 3600)
            st["lockout_until"] = time.time() + delay
            msg += f" Locked out for {delay}s."
        self.state.save(st)
        return msg

    def verify_secret(self, secret: str) -> tuple[bytes, str]:
        """Check a passphrase/recovery code, with brute-force backoff. Returns (dek, slot)."""
        self._check_lockout()
        doc = self.document()
        try:
            dek, kind = unwrap_with(doc, secret)
        except BadPassphrase:
            raise BadPassphrase(self._record_failure()) from None
        open_document(doc, dek)  # prove the DEK actually opens the payload
        self._update_state(failed_attempts=0, lockout_until=0)
        return dek, kind

    def unlock(self, secret: str) -> str:
        dek, kind = self.verify_secret(secret)
        doc = self.document()
        payload = open_document(doc, dek)
        vid = doc["vault_id"]
        self.keystore.set(dek_name(vid), dek)
        ak = payload.get("meta", {}).get("audit_key")
        if ak and self.keystore.get(audit_key_name(vid)) is None:
            self.keystore.set(audit_key_name(vid), crypto.b64d(ak))
        self._update_state(unlocked_at=time.time())
        return kind

    def lock(self) -> None:
        if self.exists():
            self.keystore.delete(dek_name(self.vault_id))
        self._update_state(unlocked_at=None)

    def is_unlocked(self) -> bool:
        try:
            self.dek()
            return True
        except (VaultLocked, VaultNotInitialized):
            return False

    def auto_lock_remaining(self) -> float | None:
        hours = self.config.get("auto_lock_hours")
        at = self.state.load().get("unlocked_at")
        if not hours or not at:
            return None
        return at + hours * 3600 - time.time()

    def dek(self) -> bytes:
        vid = self.vault_id
        remaining = self.auto_lock_remaining()
        if remaining is not None and remaining <= 0:
            self.lock()
            raise VaultLocked(f"(auto-locked after {self.config.get('auto_lock_hours')}h)")
        dek = self.keystore.get(dek_name(vid))
        if dek is None:
            raise VaultLocked()
        return dek

    def audit_key(self) -> bytes | None:
        try:
            return self.keystore.get(audit_key_name(self.vault_id))
        except (KeymasterError, VaultNotInitialized):
            return None

    # ---------------------------------------------------------------- transactions
    @contextlib.contextmanager
    def transaction(self, write: bool = False) -> Iterator[dict]:
        with self._flock(exclusive=write):
            doc = self.document()
            dek = self.dek()
            payload = open_document(doc, dek)
            last = self.state.load().get("last_generation", 0)
            self.rollback_warning = (
                f"Vault generation {doc['generation']} is older than last seen {last} — "
                "the vault file may have been rolled back to an earlier copy."
                if doc["generation"] < last
                else None
            )
            yield payload
            if write:
                self._save(doc, payload, dek)

    def _save(self, doc: dict, payload: dict, dek: bytes) -> None:
        self._backup()
        doc["generation"] = int(doc["generation"]) + 1
        doc["updated_at"] = now_iso()
        atomic_write(self.layout.vault, json.dumps(seal_document(doc, payload, dek), indent=1).encode())
        st = self.state.load()
        st["last_generation"] = max(doc["generation"], st.get("last_generation", 0))
        self.state.save(st)

    def _backup(self) -> None:
        if not self.layout.vault.exists():
            return
        ts = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        shutil.copy2(self.layout.vault, self.layout.backups / f"vault-{ts}.km")
        keep = int(self.config.get("backup_count"))
        snaps = sorted(self.layout.backups.glob("vault-*.km"))
        for old in snaps[: max(0, len(snaps) - keep)]:
            old.unlink(missing_ok=True)

    def backups(self) -> list[Path]:
        return sorted(self.layout.backups.glob("vault-*.km"), reverse=True)

    # ---------------------------------------------------------------- key management
    def _rewrite_header(self, mutate) -> None:
        with self._flock(exclusive=True):
            doc = self.document()
            mutate(doc)
            self._backup()
            atomic_write(self.layout.vault, json.dumps(doc, indent=1).encode())

    def change_passphrase(self, current: str, new: str) -> None:
        if len(new) < 10:
            raise KeymasterError("Master passphrase must be at least 10 characters.")
        dek, _ = self.verify_secret(current)

        def mutate(doc: dict) -> None:
            doc["slots"] = [s for s in doc["slots"] if s["kind"] != "passphrase"] + [
                make_slot(doc["vault_id"], "passphrase", new, dek, self._kdf_params)
            ]

        self._rewrite_header(mutate)

    def new_recovery_code(self, current: str) -> str:
        dek, _ = self.verify_secret(current)
        code = crypto.new_recovery_code()

        def mutate(doc: dict) -> None:
            doc["slots"] = [s for s in doc["slots"] if s["kind"] != "recovery"] + [
                make_slot(doc["vault_id"], "recovery", code, dek, self._kdf_params)
            ]

        self._rewrite_header(mutate)
        return code

    def rotate_dek(self, passphrase: str) -> str:
        """Re-encrypt everything under a brand-new DEK. Returns a new recovery code."""
        old_dek, kind = self.verify_secret(passphrase)
        if kind != "passphrase":
            raise KeymasterError("Key rotation needs the master passphrase, not the recovery code.")
        code = crypto.new_recovery_code()
        new_dek = crypto.random_key()
        with self._flock(exclusive=True):
            doc = self.document()
            payload = open_document(doc, old_dek)
            vid = doc["vault_id"]
            doc["slots"] = [
                make_slot(vid, "passphrase", passphrase, new_dek, self._kdf_params),
                make_slot(vid, "recovery", code, new_dek, self._kdf_params),
            ]
            self._save(doc, payload, new_dek)
            self.keystore.set(dek_name(vid), new_dek)
        return code


# ---------------------------------------------------------------- portable export files
def export_document(payload: dict, passphrase: str, kdf_params: dict | None = None) -> dict:
    vault_id = uuid.uuid4().hex
    dek = crypto.random_key()
    doc = {
        "format": FORMAT,
        "version": VERSION,
        "vault_id": vault_id,
        "created_at": now_iso(),
        "generation": 1,
        "export": True,
        "slots": [make_slot(vault_id, "passphrase", passphrase, dek, kdf_params)],
    }
    body = {"schema": SCHEMA, "credentials": payload["credentials"], "grants": {}, "meta": {}}
    return seal_document(doc, body, dek)


def import_document(path: Path, passphrase: str) -> dict:
    doc = read_document(path)
    dek, _ = unwrap_with(doc, passphrase)
    return open_document(doc, dek)
