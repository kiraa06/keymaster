"""The Keymaster service: every read/write/reveal goes through here, so the policy engine and
audit trail are identical for the MCP server and the CLI.

Policies (least -> most restrictive):

    open     agent may reveal and use freely
    confirm  agent may *use* freely (inject/http/clipboard); *revealing* the raw value needs a
             human approval, which can be granted for a while ("Allow for 8h")
    sealed   the raw value is never revealed to the agent; it can only be used
    strict   every use and every reveal needs a fresh human approval
"""

from __future__ import annotations

import difflib
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from . import approval as approval_mod
from . import generator, health, runner, totp
from .audit import AuditLog
from .config import POLICIES
from .errors import Ambiguous, KeymasterError, NotFound, PolicyDenied, ValidationError
from .models import TYPES, Credential, new_id, now_iso
from .resolver import is_ambiguous, rank
from .vault import Vault

POLICY_RANK = {p: i for i, p in enumerate(POLICIES)}
UNSET: Any = object()


@dataclass
class Actor:
    kind: str  # "agent" | "human"
    label: str

    @property
    def is_agent(self) -> bool:
        return self.kind == "agent"


AGENT = Actor("agent", "AI agent (MCP)")
HUMAN = Actor("human", "you (terminal)")


def _merge_list(current: list[str], set_to, add, remove, lower=False) -> list[str]:
    norm = (lambda s: s.strip().lower()) if lower else (lambda s: s.strip())
    out = list(current) if set_to is None else [norm(x) for x in set_to]
    for x in add or []:
        if norm(x) not in out:
            out.append(norm(x))
    rm = {norm(x) for x in remove or []}
    return [x for x in out if x not in rm]


class Keymaster:
    def __init__(self, vault: Vault | None = None, actor: Actor = AGENT, approver=None) -> None:
        self.vault = vault or Vault()
        self.actor = actor
        self.audit = AuditLog(self.vault.layout.audit, self.vault.audit_key)
        self._approver = approver

    # ------------------------------------------------------------------ infra
    @property
    def approver(self):
        if self._approver is None:
            self._approver = approval_mod.from_config(self.vault.config.get("approval"), self.vault.layout.bin)
        return self._approver

    def log(self, action: str, ok: bool = True, cred: Credential | None = None, **detail: Any) -> None:
        self.audit.append(action, actor=self.actor.kind, ok=ok, cred=cred, **detail)

    @staticmethod
    def _creds(payload: dict, include_deleted: bool = False) -> list[Credential]:
        cs = [Credential.from_dict(d) for d in payload["credentials"].values()]
        return [c for c in cs if include_deleted or not c.deleted]

    @staticmethod
    def _put(payload: dict, c: Credential) -> None:
        payload["credentials"][c.id] = c.to_dict()

    def _resolve(self, payload: dict, ref: str, deleted: bool | None = False) -> Credential:
        """deleted=False: live only; True: trash only; None: either."""
        ref = (ref or "").strip()
        if not ref:
            raise ValidationError("Empty credential reference")
        pool = self._creds(payload, include_deleted=deleted is not False)
        if deleted is True:
            pool = [c for c in pool if c.deleted]
        low = ref.lower()
        for c in pool:
            if c.id == ref or c.name.lower() == low or low in c.aliases:
                return c
        matches = rank(ref, pool, limit=5)
        if not matches:
            names = [c.name for c in pool] + [a for c in pool for a in c.aliases]
            close = difflib.get_close_matches(ref, names, n=3, cutoff=0.5)
            hint = f" Did you mean: {', '.join(close)}?" if close else ""
            raise NotFound(f"No credential matches '{ref}'.{hint}")
        if is_ambiguous(matches):
            raise Ambiguous(ref, [f"{m.cred.name} ({m.reason})" for m in matches[:4]])
        return matches[0].cred

    def _label_taken(self, payload: dict, labels: list[str], except_id: str | None = None) -> None:
        for c in self._creds(payload):
            if c.id == except_id:
                continue
            mine = {x.lower() for x in c.labels()}
            clash = [x for x in labels if x.lower() in mine]
            if clash:
                raise ValidationError(f"'{clash[0]}' is already used by credential '{c.name}'")

    # ------------------------------------------------------------------ approvals
    def _describe(self, c: Credential) -> str:
        who = f"{c.username} @ " if c.username else ""
        where = c.urls[0] if c.urls else c.type
        return f'"{c.name}" ({who}{where})'

    def _require_approval(self, c: Credential, action: str, purpose: str, allow_grant: bool) -> None:
        """Blocks on the human. Records a time-boxed grant if they chose 'Allow for …'."""
        if not self.actor.is_agent:
            return
        if allow_grant:
            with self.vault.transaction() as p:
                until = p.get("grants", {}).get(c.id, 0)
            if until > time.time():
                return
        minutes = int(self.vault.config.get("grant_minutes"))
        msg = f"{self.actor.label} wants to {action} {self._describe(c)}."
        if purpose:
            msg += f"\n\nReason given: {purpose[:300]}"
        msg += f"\n\nPolicy: {c.policy}"
        dec = self.approver.approve(
            approval_mod.Request("Keymaster — approve access", msg, allow_grant=allow_grant, grant_minutes=minutes)
        )
        self.log(
            "approval",
            ok=dec.allowed,
            cred=c,
            request=action,
            method=dec.method,
            grant=dec.grant,
            note=dec.note,
            purpose=purpose,
        )
        if not dec.allowed:
            raise PolicyDenied(
                f"The user did not approve access to '{c.name}' ({dec.note or 'denied'}). "
                "Do not retry automatically; ask the user how to proceed."
            )
        if dec.grant:
            with self.vault.transaction(write=True) as p:
                p.setdefault("grants", {})[c.id] = time.time() + minutes * 60

    def _gate(self, c: Credential, mode: str, purpose: str) -> None:
        """mode: 'reveal' or 'use'."""
        if not self.actor.is_agent:
            return
        if mode == "reveal":
            if c.policy == "open":
                return
            if c.policy == "sealed":
                raise PolicyDenied(
                    f"'{c.name}' is sealed: its value can't be revealed to the agent. Use it via "
                    "http_request / run_with_credential / copy_to_clipboard instead."
                )
            self._require_approval(c, "reveal the secret of", purpose, allow_grant=c.policy == "confirm")
        else:
            if c.policy == "strict":
                self._require_approval(c, "use", purpose, allow_grant=False)

    def _touch(self, cred_id: str) -> None:
        with self.vault.transaction(write=True) as p:
            d = p["credentials"].get(cred_id)
            if d:
                d["last_used_at"] = now_iso()
                d["use_count"] = int(d.get("use_count") or 0) + 1

    # ------------------------------------------------------------------ queries
    def status(self) -> dict:
        v = self.vault
        if not v.exists():
            return {"initialized": False, "hint": "Run `km init` in a terminal."}
        doc = v.document()
        out: dict[str, Any] = {
            "initialized": True,
            "unlocked": v.is_unlocked(),
            "vault": str(v.layout.vault),
            "vault_id": doc["vault_id"],
            "generation": doc["generation"],
            "slots": [s["kind"] for s in doc["slots"]],
            "backups": len(v.backups()),
            "approval": v.config.get("approval"),
            "default_policy": v.config.get("default_policy"),
        }
        rem = v.auto_lock_remaining()
        if rem is not None:
            out["auto_lock_in_minutes"] = max(0, int(rem // 60))
        if out["unlocked"]:
            with v.transaction() as p:
                creds = self._creds(p)
                out["credentials"] = len(creds)
                out["trash"] = len(self._creds(p, True)) - len(creds)
                out["by_type"] = {t: n for t in TYPES if (n := sum(c.type == t for c in creds))}
                out["active_grants"] = sum(1 for u in p.get("grants", {}).values() if u > time.time())
            if v.rollback_warning:
                out["warning"] = v.rollback_warning
        return out

    def find(self, query: str, limit: int = 5, type: str | None = None, tag: str | None = None) -> dict:
        stale = self.vault.config.get("stale_days")
        with self.vault.transaction() as p:
            pool = [c for c in self._creds(p) if (not type or c.type == type) and (not tag or tag.lower() in c.tags)]
            matches = rank(query, pool, limit)
        self.log("find", query=query[:200], hits=len(matches))
        res = [{"score": m.score, "match": m.reason, **m.cred.public(stale)} for m in matches]
        out: dict[str, Any] = {"query": query, "matches": res}
        if not res:
            out["hint"] = (
                "Nothing stored for this. Ask the user to add it — e.g. add_credential with "
                "prompt_human=true so they type the secret into a secure dialog."
            )
        elif is_ambiguous(matches):
            out["ambiguous"] = True
            out["hint"] = "Several credentials match equally well — ask the user which one to use."
        return out

    def list(self, type: str | None = None, tag: str | None = None, deleted: bool = False) -> list[dict]:
        stale = self.vault.config.get("stale_days")
        with self.vault.transaction() as p:
            cs = self._creds(p, include_deleted=deleted)
        if deleted:
            cs = [c for c in cs if c.deleted]
        cs = [c for c in cs if (not type or c.type == type) and (not tag or tag.lower() in c.tags)]
        return [c.public(stale) for c in sorted(cs, key=lambda c: c.name.lower())]

    def get(self, ref: str) -> dict:
        with self.vault.transaction() as p:
            c = self._resolve(p, ref)
        return c.public(self.vault.config.get("stale_days"))

    def credential(self, ref: str, deleted: bool | None = False) -> Credential:
        """Full object incl. secrets. Internal/CLI use — no policy gate."""
        with self.vault.transaction() as p:
            return self._resolve(p, ref, deleted=deleted)

    # ------------------------------------------------------------------ mutations
    def add(
        self,
        name: str,
        type: str = "password",
        *,
        username: str | None = None,
        secrets: dict[str, str] | None = None,
        fields: dict[str, str] | None = None,
        urls: list[str] | None = None,
        aliases: list[str] | None = None,
        tags: list[str] | None = None,
        notes: str = "",
        policy: str | None = None,
        expires_at: str | None = None,
        rotate_days: int | None = None,
    ) -> Credential:
        c = Credential(
            id=new_id(),
            name=name,
            type=type,
            username=username,
            secrets=dict(secrets or {}),
            fields=dict(fields or {}),
            urls=list(urls or []),
            aliases=list(aliases or []),
            tags=list(tags or []),
            notes=notes or "",
            policy=policy or self.vault.config.get("default_policy"),
            expires_at=expires_at,
            rotate_days=rotate_days,
        )
        c.normalize()
        c.validate()
        with self.vault.transaction(write=True) as p:
            self._label_taken(p, c.labels())
            while c.id in p["credentials"]:
                c.id = new_id()
            self._put(p, c)
        self.log("add", cred=c, type=c.type, policy=c.policy)
        return c

    def update(
        self,
        ref: str,
        *,
        name: str | None = None,
        type: str | None = None,
        username: Any = UNSET,
        secrets: dict[str, str | None] | None = None,
        fields: dict[str, str | None] | None = None,
        urls: list[str] | None = None,
        add_urls: list[str] | None = None,
        remove_urls: list[str] | None = None,
        aliases: list[str] | None = None,
        add_aliases: list[str] | None = None,
        remove_aliases: list[str] | None = None,
        tags: list[str] | None = None,
        add_tags: list[str] | None = None,
        remove_tags: list[str] | None = None,
        notes: str | None = None,
        policy: str | None = None,
        expires_at: Any = UNSET,
        rotate_days: Any = UNSET,
        reason: str = "",
    ) -> tuple[Credential, list[str]]:
        with self.vault.transaction() as p:
            before = self._resolve(p, ref)
        if policy and policy in POLICY_RANK and POLICY_RANK[policy] < POLICY_RANK[before.policy]:
            # An agent must not be able to loosen its own leash.
            self._require_approval(before, f"loosen policy {before.policy}→{policy} on", reason, allow_grant=False)
        depth = int(self.vault.config.get("history_depth"))
        with self.vault.transaction(write=True) as p:
            c = self._resolve(p, before.id)
            snap = c.snapshot(reason or "update")
            changed: list[str] = []
            if name is not None and name != c.name:
                c.name = name
                changed.append("name")
            if type is not None and type != c.type:
                c.type = type
                changed.append("type")
            if username is not UNSET and username != c.username:
                c.username = username
                changed.append("username")
            secret_changed = False
            for k, v in (secrets or {}).items():
                k = k.strip().lower()
                if v in (None, ""):
                    if k in c.secrets:
                        del c.secrets[k]
                        secret_changed = True
                elif c.secrets.get(k) != v:
                    c.secrets[k] = v
                    secret_changed = True
            if secret_changed:
                changed.append("secrets")
            for k, v in (fields or {}).items():
                k = k.strip().lower()
                if v in (None, ""):
                    c.fields.pop(k, None)
                else:
                    c.fields[k] = str(v)
            if fields:
                changed.append("fields")
            for attr, s, a, r, low in (
                ("urls", urls, add_urls, remove_urls, False),
                ("aliases", aliases, add_aliases, remove_aliases, True),
                ("tags", tags, add_tags, remove_tags, True),
            ):
                if s is not None or a or r:
                    new = _merge_list(getattr(c, attr), s, a, r, lower=low)
                    if new != getattr(c, attr):
                        setattr(c, attr, new)
                        changed.append(attr)
            if notes is not None and notes != c.notes:
                c.notes = notes
                changed.append("notes")
            if policy is not None and policy != c.policy:
                c.policy = policy
                changed.append("policy")
            if expires_at is not UNSET and expires_at != c.expires_at:
                c.expires_at = expires_at or None
                changed.append("expires_at")
            if rotate_days is not UNSET and rotate_days != c.rotate_days:
                c.rotate_days = rotate_days or None
                changed.append("rotate_days")
            if not changed:
                return c, []
            c.normalize()
            c.validate()
            self._label_taken(p, c.labels(), except_id=c.id)
            if secret_changed or "username" in changed:
                c.history = (c.history + [snap])[-depth:]
            if secret_changed:
                c.secret_changed_at = now_iso()
                p.get("grants", {}).pop(c.id, None)  # new secret -> old approvals lapse
            c.updated_at = now_iso()
            self._put(p, c)
        self.log("update", cred=c, changed=changed, reason=reason)
        return c, changed

    def delete(self, ref: str) -> Credential:
        with self.vault.transaction(write=True) as p:
            c = self._resolve(p, ref)
            c.deleted_at = now_iso()
            self._put(p, c)
            p.get("grants", {}).pop(c.id, None)
        self.log("delete", cred=c)
        return c

    def restore(self, ref: str) -> Credential:
        with self.vault.transaction(write=True) as p:
            c = self._resolve(p, ref, deleted=True)
            c.deleted_at = None
            self._label_taken(p, c.labels(), except_id=c.id)
            self._put(p, c)
        self.log("restore", cred=c)
        return c

    def purge(self, ref: str) -> Credential:
        with self.vault.transaction() as p:
            c = self._resolve(p, ref, deleted=True)
        self._require_approval(c, "PERMANENTLY destroy", "purge from trash", allow_grant=False)
        with self.vault.transaction(write=True) as p:
            p["credentials"].pop(c.id, None)
        self.log("purge", cred=c)
        return c

    def empty_trash(self, older_than_days: int = 0) -> int:
        cutoff = time.time() - older_than_days * 86400
        with self.vault.transaction(write=True) as p:
            gone = [
                cid for cid, d in p["credentials"].items() if d.get("deleted_at") and _ts(d["deleted_at"]) <= cutoff
            ]
            for cid in gone:
                p["credentials"].pop(cid)
        self.log("empty_trash", count=len(gone))
        return len(gone)

    def history(self, ref: str) -> list[dict]:
        with self.vault.transaction() as p:
            c = self._resolve(p, ref, deleted=None)
        out, nxt = [], {"username": c.username, "secrets": c.secrets}
        for h in reversed(c.history):
            diff = sorted(
                k for k in set(h["secrets"]) | set(nxt["secrets"]) if h["secrets"].get(k) != nxt["secrets"].get(k)
            )
            if h.get("username") != nxt["username"]:
                diff.append("username")
            out.append(
                {
                    "version": h["version"],
                    "replaced_at": h["at"],
                    "reason": h.get("reason", ""),
                    "fields_that_changed_after": diff,
                }
            )
            nxt = h
        return out

    def rollback(self, ref: str, version: int) -> Credential:
        with self.vault.transaction() as p:
            c = self._resolve(p, ref)
        snap = next((h for h in c.history if h["version"] == version), None)
        if not snap:
            raise NotFound(f"'{c.name}' has no version {version}. Versions: {[h['version'] for h in c.history]}")
        wipe = {k: None for k in c.secrets if k not in snap["secrets"]}
        c2, _ = self.update(
            c.id, username=snap["username"], secrets={**wipe, **snap["secrets"]}, reason=f"rollback to v{version}"
        )
        return c2

    # ------------------------------------------------------------------ secret access
    def reveal(self, ref: str, fields: list[str] | None = None, purpose: str = "") -> tuple[Credential, dict]:
        with self.vault.transaction() as p:
            c = self._resolve(p, ref)
        try:
            self._gate(c, "reveal", purpose)
        except PolicyDenied as e:
            self.log("reveal", ok=False, cred=c, reason=str(e)[:120], purpose=purpose)
            raise
        want = fields or list(c.secrets)
        missing = [f for f in want if f not in c.secrets]
        if missing:
            raise NotFound(f"'{c.name}' has no secret field(s) {missing}. Fields: {sorted(c.secrets)}")
        self._touch(c.id)
        self.log("reveal", cred=c, fields=want, purpose=purpose)
        return c, {f: c.secrets[f] for f in want}

    def use(self, ref: str, action: str, purpose: str = "") -> Credential:
        with self.vault.transaction() as p:
            c = self._resolve(p, ref)
        try:
            self._gate(c, "use", purpose)
        except PolicyDenied:
            self.log(action, ok=False, cred=c, purpose=purpose)
            raise
        self._touch(c.id)
        return c

    def totp(self, ref: str, purpose: str = "") -> dict:
        c = self.use(ref, "totp", purpose)
        seed = c.secrets.get("totp_secret")
        if not seed:
            raise NotFound(f"'{c.name}' has no totp_secret. Add one: update_credential secrets={{'totp_secret': ...}}")
        self.log("totp", cred=c, purpose=purpose)
        return {"credential": c.name, **totp.now(seed)}

    def run(self, ref: str, command: str, purpose: str = "", **kw: Any) -> dict:
        c = self.use(ref, "run", purpose)
        res = runner.run_command(c, command, **kw)
        self.log("run", cred=c, command=command[:300], exit_code=res["exit_code"], purpose=purpose)
        return res

    def http(self, ref: str, method: str, url: str, purpose: str = "", **kw: Any) -> dict:
        c = self.use(ref, "http", purpose)
        kw.setdefault("allow_insecure", bool(self.vault.config.get("allow_insecure_http")))
        try:
            res = runner.http_request(c, method, url, **kw)
        except KeymasterError as e:
            self.log("http", ok=False, cred=c, method=method, url=url[:300], error=str(e)[:200])
            raise
        except Exception as e:  # network errors can echo URLs/headers — scrub before surfacing
            from .redact import Redactor

            self.log("http", ok=False, cred=c, method=method, url=url[:300], error=e.__class__.__name__)
            raise KeymasterError(f"HTTP request failed: {e.__class__.__name__}: {Redactor([c])(str(e))}") from None
        self.log("http", cred=c, method=method, url=url[:300], status=res["status"], purpose=purpose)
        return res

    def copy(self, ref: str, field: str | None = None, purpose: str = "", seconds: int | None = None) -> dict:
        from . import clipboard

        c = self.use(ref, "copy", purpose)
        f = field or c.primary_field
        if f == "username":
            value = c.username
        elif f == "totp":
            value = totp.now(c.secrets["totp_secret"])["code"] if "totp_secret" in c.secrets else None
        else:
            value = c.secrets.get(f)
        if not value:
            raise NotFound(f"'{c.name}' has no field '{f}'")
        secs = int(self.vault.config.get("clipboard_seconds") if seconds is None else seconds)
        clipboard.copy(value, secs)
        approval_mod.notify("Keymaster", f"{c.name}.{f} copied — clears in {secs}s")
        self.log("copy", cred=c, field=f, purpose=purpose)
        return {"copied": f"{c.name}.{f}", "clears_in_seconds": secs}

    def health(self, check_pwned: bool = False) -> dict:
        with self.vault.transaction() as p:
            creds = self._creds(p)
        r = health.report(creds, self.vault.config.get("stale_days"), check_pwned)
        self.log("health", grade=r["grade"], pwned=check_pwned)
        return r

    def audit_tail(self, limit: int = 50, ref: str | None = None) -> list[dict]:
        cid = None
        if ref:
            with self.vault.transaction() as p:
                cid = self._resolve(p, ref, deleted=None).id
        return [{k: v for k, v in e.items() if k not in ("mac", "prev")} for e in self.audit.tail(limit, cid)]

    def revoke_grants(self) -> int:
        with self.vault.transaction(write=True) as p:
            n = len(p.get("grants", {}))
            p["grants"] = {}
        self.log("revoke_grants", count=n)
        return n

    # ------------------------------------------------------------------ helpers for adders
    def secret_from_human(self, cred_name: str, field: str) -> str:
        v = self.approver.ask_secret(
            "Keymaster — enter secret",
            f'Enter the {field} for "{cred_name}".\n\nIt goes straight into the encrypted vault; '
            "the AI agent never sees what you type.",
        )
        if not v:
            raise PolicyDenied("The user cancelled the secure input dialog.")
        return v


def generate(kind: str = "password", length: int = 24, words: int = 5, symbols: bool = True) -> str:
    return generator.passphrase(words) if kind == "passphrase" else generator.password(length, symbols=symbols)


def _ts(iso: str) -> float:
    from datetime import datetime

    return datetime.fromisoformat(iso).timestamp()


Factory = Callable[[], Keymaster]


def ensure_ready(km: Keymaster) -> None:
    if not km.vault.exists():
        from .errors import VaultNotInitialized

        raise VaultNotInitialized()
    km.vault.dek()  # raises VaultLocked with a helpful message


__all__ = ["Keymaster", "AGENT", "HUMAN", "Actor", "generate", "ensure_ready", "KeymasterError"]
