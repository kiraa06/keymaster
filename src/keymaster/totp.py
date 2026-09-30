"""RFC 6238 TOTP (and otpauth:// URI parsing) — no third-party deps."""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlsplit

from .errors import ValidationError

_ALGOS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


@dataclass
class TotpSpec:
    secret: bytes
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"


def _b32(s: str) -> bytes:
    s = s.strip().replace(" ", "").replace("-", "").upper()
    s += "=" * (-len(s) % 8)
    try:
        return base64.b32decode(s)
    except Exception as e:
        raise ValidationError("TOTP secret is not valid base32") from e


def parse(value: str) -> TotpSpec:
    """Accepts a raw base32 seed or a full otpauth://totp/... URI."""
    value = value.strip()
    if value.lower().startswith("otpauth://"):
        u = urlsplit(value)
        if u.netloc.lower() != "totp":
            raise ValidationError("Only otpauth://totp URIs are supported (not hotp)")
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if "secret" not in q:
            raise ValidationError("otpauth URI has no secret")
        algo = q.get("algorithm", "SHA1").upper()
        if algo not in _ALGOS:
            raise ValidationError(f"Unsupported TOTP algorithm {algo}")
        return TotpSpec(_b32(unquote(q["secret"])), int(q.get("digits", 6)), int(q.get("period", 30)), algo)
    return TotpSpec(_b32(value))


def code_at(spec: TotpSpec, t: float) -> str:
    counter = int(t // spec.period)
    digest = hmac.new(spec.secret, struct.pack(">Q", counter), _ALGOS[spec.algorithm]).digest()
    off = digest[-1] & 0x0F
    val = struct.unpack(">I", digest[off : off + 4])[0] & 0x7FFFFFFF
    return str(val % 10**spec.digits).zfill(spec.digits)


def now(value: str) -> dict:
    spec = parse(value)
    t = time.time()
    remaining = spec.period - int(t) % spec.period
    return {
        "code": code_at(spec, t),
        "seconds_remaining": remaining,
        "next_code": code_at(spec, t + spec.period),
        "digits": spec.digits,
        "period": spec.period,
    }
