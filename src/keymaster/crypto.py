"""Cryptographic primitives.

Design (envelope encryption, LUKS-style key slots):

* A random 256-bit Data Encryption Key (DEK) encrypts the vault payload with AES-256-GCM.
* The DEK is wrapped by one or more *slots*. Each slot derives a Key Encryption Key (KEK)
  from a human secret (master passphrase, or recovery code) with Argon2id, then seals the
  DEK with AES-256-GCM. Changing the passphrase only re-wraps a slot.
* Every AEAD operation binds associated data (vault id, slot kind, generation) so blobs
  cannot be swapped between vaults, slots or versions without detection.
* Sub-keys for other purposes (audit MACs, approval grants) come from HKDF-SHA256.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import unicodedata

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

try:  # cryptography >= 44
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
except ImportError:  # pragma: no cover
    Argon2id = None  # type: ignore[assignment]

from .errors import BadPassphrase, VaultCorrupted

KEY_LEN = 32
NONCE_LEN = 12

# OWASP-grade defaults: 64 MiB, 3 passes, 4 lanes (~0.3s on Apple Silicon).
ARGON2_DEFAULT = {"t": 3, "m": 65536, "p": 4}
# Used only by the test-suite; stored in the header so a vault always records its own params.
ARGON2_TEST = {"t": 1, "m": 8, "p": 1}


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def random_key() -> bytes:
    return secrets.token_bytes(KEY_LEN)


def new_kdf(params: dict | None = None) -> dict:
    salt = b64e(secrets.token_bytes(16))
    if Argon2id is not None:
        return {"name": "argon2id", "salt": salt, **(params or ARGON2_DEFAULT)}
    return {"name": "scrypt", "salt": salt, "n": 2**17, "r": 8, "p": 1}  # pragma: no cover


def _normalize(secret: str) -> bytes:
    # NFKC so the same passphrase typed on different keyboards/OSes derives the same key.
    return unicodedata.normalize("NFKC", secret).encode("utf-8")


def derive_kek(secret: str, kdf: dict) -> bytes:
    salt = b64d(kdf["salt"])
    pw = _normalize(secret)
    if kdf["name"] == "argon2id":
        if Argon2id is None:  # pragma: no cover
            raise VaultCorrupted("Vault uses Argon2id but this cryptography build lacks it.")
        return Argon2id(salt=salt, length=KEY_LEN, iterations=kdf["t"], lanes=kdf["p"], memory_cost=kdf["m"]).derive(pw)
    if kdf["name"] == "scrypt":
        return Scrypt(salt=salt, length=KEY_LEN, n=kdf["n"], r=kdf["r"], p=kdf["p"]).derive(pw)
    raise VaultCorrupted(f"Unknown KDF {kdf['name']!r}")


def seal(key: bytes, plaintext: bytes, aad: bytes) -> dict:
    nonce = secrets.token_bytes(NONCE_LEN)
    return {"nonce": b64e(nonce), "ct": b64e(AESGCM(key).encrypt(nonce, plaintext, aad))}


def unseal(key: bytes, box: dict, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(b64d(box["nonce"]), b64d(box["ct"]), aad)
    except InvalidTag as e:
        raise BadPassphrase("Decryption failed (wrong key or tampered data).") from e
    except (KeyError, ValueError) as e:
        raise VaultCorrupted(f"Malformed encrypted blob: {e}") from e


def subkey(master: bytes, label: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=None, info=label.encode()).derive(master)


def mac(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def mac_ok(key: bytes, data: bytes, expected: str) -> bool:
    return hmac.compare_digest(mac(key, data), expected)


_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # no I, L, O, U — easy to read aloud


def new_recovery_code() -> str:
    """30 Crockford-base32 chars = 150 bits, printed as 6 groups of 5."""
    raw = "".join(secrets.choice(_CROCKFORD) for _ in range(30))
    return "-".join(raw[i : i + 5] for i in range(0, 30, 5))


def normalize_recovery_code(code: str) -> str:
    c = code.upper().replace("-", "").replace(" ", "")
    c = c.replace("O", "0").replace("I", "1").replace("L", "1")
    return "-".join(c[i : i + 5] for i in range(0, len(c), 5))


def looks_like_recovery_code(s: str) -> bool:
    c = s.upper().replace("-", "").replace(" ", "")
    return len(c) == 30 and all(ch in _CROCKFORD + "OIL" for ch in c)


def wipe(buf: bytearray) -> None:
    """Best-effort zeroing. Python gives no hard guarantees; this narrows the window."""
    for i in range(len(buf)):
        buf[i] = 0


def fingerprint(key: bytes) -> str:
    """Short, non-reversible identifier for a key (shown in `km status`)."""
    return hashlib.sha256(b"keymaster-fp" + key).hexdigest()[:12]
