"""Password / passphrase generation and a pragmatic strength estimate."""

from __future__ import annotations

import math
import re
import secrets
import string
from functools import lru_cache
from pathlib import Path

AMBIGUOUS = set("Il1O0o`'\"|")
SAFE_SYMBOLS = "!@#$%^&*()-_=+[]{}:,.?~"


def password(
    length: int = 24,
    symbols: bool = True,
    digits: bool = True,
    uppercase: bool = True,
    exclude_ambiguous: bool = True,
    symbol_set: str = SAFE_SYMBOLS,
) -> str:
    if not 8 <= length <= 256:
        raise ValueError("length must be between 8 and 256")
    pools = [string.ascii_lowercase]
    if uppercase:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(symbol_set)
    if exclude_ambiguous:
        pools = ["".join(c for c in p if c not in AMBIGUOUS) for p in pools]
    alphabet = "".join(pools)
    while True:  # rejection-sample until every requested class is present
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in p for c in pw) for p in pools):
            return pw


@lru_cache(maxsize=1)
def _wordlist() -> tuple[str, ...]:
    p = Path("/usr/share/dict/words")
    if p.exists():
        words = {w.strip().lower() for w in p.read_text(errors="ignore").splitlines()}
        words = {w for w in words if w.isalpha() and w.isascii() and 4 <= len(w) <= 8}
        if len(words) > 5000:
            return tuple(sorted(words))
    # Fallback: pronounceable CVCV syllable pairs (20*5*20*5 = 10,000 "words").
    c, v = "bdfghjklmnprstvwxyz" + "c", "aeiou"
    return tuple(a + b + d + e for a in c for b in v for d in c for e in v)


def passphrase(words: int = 5, separator: str = "-", capitalize: bool = True, number: bool = True) -> str:
    if not 3 <= words <= 20:
        raise ValueError("words must be between 3 and 20")
    wl = _wordlist()
    parts = [secrets.choice(wl) for _ in range(words)]
    if capitalize:
        parts = [p.capitalize() for p in parts]
    if number:
        i = secrets.randbelow(len(parts))
        parts[i] = parts[i] + str(secrets.randbelow(100))
    return separator.join(parts)


def passphrase_bits(words: int) -> float:
    return words * math.log2(len(_wordlist()))


_COMMON = {
    "password",
    "passw0rd",
    "123456",
    "12345678",
    "qwerty",
    "letmein",
    "welcome",
    "admin",
    "iloveyou",
    "monkey",
    "dragon",
    "master",
    "login",
    "abc123",
    "changeme",
    "secret",
    "jenkins",
    "root",
    "toor",
    "test",
    "default",
}


def strength(pw: str) -> dict:
    """Charset-entropy estimate with penalties for the classic weak patterns."""
    if not pw:
        return {"bits": 0, "rating": "empty", "issues": ["empty"]}
    pool = 0
    if re.search(r"[a-z]", pw):
        pool += 26
    if re.search(r"[A-Z]", pw):
        pool += 26
    if re.search(r"\d", pw):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", pw):
        pool += 33
    bits = len(pw) * math.log2(max(pool, 2))
    issues = []
    low = pw.lower()
    if any(w in low for w in _COMMON):
        bits = min(bits, 20)
        issues.append("contains a very common password")
    if len(set(pw)) <= max(2, len(pw) // 4):
        bits *= 0.5
        issues.append("few distinct characters")
    if re.search(r"(.)\1\1", pw):
        bits -= 8
        issues.append("repeated characters")
    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|qwer|asdf)", low):
        bits -= 10
        issues.append("keyboard/number sequence")
    if len(pw) < 12:
        issues.append("shorter than 12 characters")
    bits = max(0.0, bits)
    rating = "weak" if bits < 50 else "fair" if bits < 70 else "strong" if bits < 100 else "excellent"
    return {"bits": round(bits, 1), "rating": rating, "issues": issues}
