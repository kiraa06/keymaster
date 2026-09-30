"""Vault health: weak / reused / expired / stale / pwned secrets, graded A–F."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import UTC, datetime

import httpx

from .generator import strength
from .models import Credential

PASSWORDISH = {"password", "passphrase", "pin", "secret"}


def pwned_count(secret: str, client: httpx.Client) -> int:
    """HaveIBeenPwned k-anonymity: only the first 5 hex chars of SHA-1 leave the machine."""
    h = hashlib.sha1(secret.encode(), usedforsecurity=False).hexdigest().upper()
    r = client.get(f"https://api.pwnedpasswords.com/range/{h[:5]}", headers={"Add-Padding": "true"})
    r.raise_for_status()
    for line in r.text.splitlines():
        suffix, _, count = line.partition(":")
        if suffix == h[5:]:
            return int(count)
    return 0


def report(creds: list[Credential], stale_days: int = 180, check_pwned: bool = False) -> dict:
    issues: list[dict] = []

    def add(c: Credential, kind: str, severity: str, msg: str) -> None:
        issues.append({"cred": c.name, "id": c.id, "kind": kind, "severity": severity, "message": msg})

    seen: dict[str, list[str]] = defaultdict(list)
    now = datetime.now(UTC)
    for c in creds:
        for f, v in c.secrets.items():
            if f == "note":
                continue
            seen[hashlib.sha256(v.encode()).hexdigest()].append(f"{c.name}.{f}")
            if f in PASSWORDISH:
                s = strength(v)
                if s["rating"] == "weak":
                    add(
                        c, "weak", "high", f"{f} is weak (~{s['bits']} bits: {', '.join(s['issues']) or 'low entropy'})"
                    )
        for w in c.warnings(stale_days):
            sev = "high" if "EXPIRED" in w else "medium"
            add(c, "expiry" if "expire" in w.lower() else "stale", sev, w)
        if not c.urls and not c.aliases:
            add(c, "unfindable", "low", "no URLs or aliases — the agent can only find it by exact name")
        created = datetime.fromisoformat(c.created_at)
        if not c.last_used_at and (now - created).days > 90:
            add(c, "unused", "low", "never used in 90+ days — still needed?")
    for where in seen.values():
        if len(where) > 1:
            names = sorted(where)
            for c in creds:
                if any(w.startswith(c.name + ".") for w in names):
                    add(c, "reused", "high", f"same secret used in {', '.join(names)}")
                    break
    pwned_checked = 0
    if check_pwned:
        with httpx.Client(timeout=10, headers={"User-Agent": "keymaster-vault"}) as client:
            for c in creds:
                for f, v in c.secrets.items():
                    if f in PASSWORDISH:
                        try:
                            n = pwned_count(v, client)
                        except httpx.HTTPError as e:
                            add(c, "pwned-check-failed", "low", f"HIBP lookup failed: {e.__class__.__name__}")
                            continue
                        pwned_checked += 1
                        if n:
                            add(c, "pwned", "critical", f"{f} appears in {n:,} known breaches — rotate it now")
    weights = {"critical": 25, "high": 10, "medium": 4, "low": 1}
    penalty = sum(weights[i["severity"]] for i in issues)
    score = max(0, 100 - penalty) if creds else 100
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    issues.sort(key=lambda i: (order[i["severity"]], i["cred"]))
    return {
        "grade": grade,
        "score": score,
        "credentials": len(creds),
        "issues": issues,
        "pwned_checked": pwned_checked if check_pwned else None,
    }
