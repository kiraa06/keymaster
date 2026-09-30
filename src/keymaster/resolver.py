"""Turn whatever the agent has in hand — a URL, hostname, alias, or vague phrase like
"jenkins prod" — into the right credential, with a score and a human-readable reason."""

from __future__ import annotations

import difflib
import fnmatch
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .models import Credential

AMBIGUITY_GAP = 8
MIN_SCORE = 35


@dataclass
class Match:
    cred: Credential
    score: int
    reason: str


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int | None
    path: str


def parse_target(s: str) -> Target | None:
    s = s.strip()
    if not s or " " in s:
        return None
    if "://" not in s:
        # bare host / host:port / host/path — only if it looks like a host
        if not re.match(r"^(\*\.)?[A-Za-z0-9-]+(\.[A-Za-z0-9*-]+)+(:\d+)?(/.*)?$", s) and not re.match(
            r"^localhost(:\d+)?(/.*)?$", s
        ):
            return None
        s = "//" + s
    try:
        u = urlsplit(s)
        port = u.port
    except ValueError:
        return None
    if not u.hostname:
        return None
    return Target(u.scheme.lower(), u.hostname.lower(), port, u.path or "/")


def _base_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "gov", "ac"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def url_score(pattern: str, t: Target) -> tuple[int, str]:
    p = parse_target(pattern)
    if p is None:
        return 0, ""
    if "*" in p.host:
        if fnmatch.fnmatch(t.host, p.host):
            return 75, f"host {t.host} matches wildcard {p.host}"
        return 0, ""
    if p.host != t.host:
        if _base_domain(p.host) == _base_domain(t.host):
            return 30, f"same domain as {p.host}"
        return 0, ""
    if p.port and t.port and p.port != t.port:
        return 40, f"same host {p.host} but different port"
    score, why = 90, f"host {t.host}"
    if p.path not in ("", "/"):
        if t.path.startswith(p.path.rstrip("/")):
            score, why = 90 + min(9, len(p.path.strip("/").split("/"))), f"host+path {p.host}{p.path}"
        else:
            score, why = 85, f"host {t.host} (different path)"
    return score, why


def _tokens(s: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", s.lower()) if t]


def text_score(query: str, c: Credential) -> tuple[int, str]:
    q = query.strip().lower()
    for label in c.labels():
        if q == label.lower():
            return 95, f"exact {'name' if label == c.name else 'alias'} '{label}'"
    if q == c.id:
        return 100, "id"
    qt = set(_tokens(q))
    if not qt:
        return 0, ""
    hay: dict[str, str] = {}
    for label in c.labels():
        for t in _tokens(label):
            hay.setdefault(t, f"name/alias '{label}'")
    for tag in c.tags:
        for t in _tokens(tag):
            hay.setdefault(t, f"tag '{tag}'")
    for u in c.urls:
        pt = parse_target(u)
        for t in _tokens(pt.host if pt else u):
            if t not in ("com", "www", "in", "io", "net", "org", "https", "http"):
                hay.setdefault(t, f"url '{u}'")
    if c.username:
        for t in _tokens(c.username):
            hay.setdefault(t, f"username '{c.username}'")
    hit = [t for t in qt if t in hay]
    fuzzy = []
    for t in qt - set(hit):
        close = difflib.get_close_matches(t, list(hay), n=1, cutoff=0.8)
        if close:
            fuzzy.append(close[0])
    if not hit and not fuzzy:
        best = max((difflib.SequenceMatcher(None, q, lab.lower()).ratio() for lab in c.labels()), default=0)
        return (int(best * 50), "fuzzy name") if best >= 0.75 else (0, "")
    coverage = (len(hit) + 0.6 * len(fuzzy)) / len(qt)
    score = int(40 + 45 * coverage)
    reasons = sorted({hay[t] for t in hit + fuzzy})
    return score, "matched " + ", ".join(reasons[:3])


def rank(query: str, creds: list[Credential], limit: int = 5) -> list[Match]:
    t = parse_target(query)
    results: list[Match] = []
    for c in creds:
        best, why = text_score(query, c)
        if t:
            for u in c.urls:
                s, r = url_score(u, t)
                if s > best:
                    best, why = s, r
            if c.fields.get("host", "").lower() == t.host and best < 88:
                best, why = 88, f"field host={t.host}"
        if best >= MIN_SCORE:
            results.append(Match(c, best, why))
    results.sort(key=lambda m: (-m.score, -(m.cred.use_count or 0), m.cred.name))
    if t and results and results[0].score >= 75:
        # A real host match beats coincidental word overlap ("example", "ci", "com"...).
        results = [m for m in results if m.score >= 60]
    return results[:limit]


def is_ambiguous(matches: list[Match]) -> bool:
    return len(matches) > 1 and matches[0].score - matches[1].score < AMBIGUITY_GAP and matches[0].score < 100


def host_allowed(cred: Credential, url: str) -> bool:
    """Is `url` one of the hosts this credential is registered for? (exfiltration guard)"""
    t = parse_target(url)
    if not t:
        return False
    if cred.fields.get("host", "").lower() == t.host:
        return True
    return any(url_score(u, t)[0] >= 75 for u in cred.urls)
