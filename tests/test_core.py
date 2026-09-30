import time

import pytest

from keymaster.approval import StaticApprover
from keymaster.core import AGENT, Keymaster
from keymaster.errors import Ambiguous, NotFound, PolicyDenied, ValidationError


def add_jenkins(k, policy="open", **kw):
    return k.add(
        "jenkins-ci",
        "token",
        username="kiran",
        secrets={"token": "11aa22bb33cc44dd55ee"},
        urls=["https://ci.jenkins.example.com"],
        aliases=["jenkins", "ci"],
        tags=["prod"],
        policy=policy,
        **kw,
    )


def test_add_and_lookup_by_everything(agent):
    c = add_jenkins(agent)
    for ref in ("jenkins-ci", "JENKINS", "ci", c.id, "https://ci.jenkins.example.com/job/foo/build"):
        assert agent.credential(ref).id == c.id


def test_public_view_hides_secrets(agent):
    add_jenkins(agent)
    d = agent.get("jenkins")
    assert "11aa22" not in str(d)
    assert d["secrets"] == {"token": "<hidden: 20 chars>"}


def test_duplicate_labels_rejected(agent):
    add_jenkins(agent)
    with pytest.raises(ValidationError):
        agent.add("other", secrets={"password": "abcdefghijkl"}, aliases=["Jenkins"])
    with pytest.raises(ValidationError):
        agent.add("CI", secrets={"password": "abcdefghijkl"})


def test_validation(agent):
    with pytest.raises(ValidationError):
        agent.add("bad name!", secrets={"password": "x"})
    with pytest.raises(ValidationError):
        agent.add("ok", type="nope", secrets={"password": "x"})
    with pytest.raises(ValidationError):
        agent.add("ok", secrets={})
    with pytest.raises(ValidationError):
        agent.add("ok", secrets={"password": "x"}, expires_at="tomorrow")


def test_update_merges_and_keeps_history(agent):
    add_jenkins(agent)
    c, changed = agent.update(
        "jenkins",
        secrets={"token": "new-token-value-999"},
        add_urls=["https://ci2.example.com"],
        add_aliases=["build"],
        remove_tags=["prod"],
        fields={"region": "sg"},
        reason="rotated",
    )
    assert set(changed) >= {"secrets", "urls", "aliases", "tags", "fields"}
    assert c.secrets["token"] == "new-token-value-999"
    assert c.urls == ["https://ci.jenkins.example.com", "https://ci2.example.com"]
    assert "build" in c.aliases and c.tags == []
    hist = agent.history("jenkins")
    assert hist[0]["version"] == 1 and "token" in hist[0]["fields_that_changed_after"]
    agent.rollback("jenkins", 1)
    assert agent.credential("jenkins").secrets["token"] == "11aa22bb33cc44dd55ee"


def test_history_depth(agent, vault):
    vault.config.set("history_depth", 3)
    add_jenkins(agent)
    for i in range(6):
        agent.update("jenkins", secrets={"token": f"token-{i}-abcdefgh"})
    assert len(agent.credential("jenkins").history) == 3


def test_trash_restore_purge(agent, approver):
    add_jenkins(agent)
    agent.delete("jenkins")
    with pytest.raises(NotFound):
        agent.credential("jenkins")
    assert [c["name"] for c in agent.list(deleted=True)] == ["jenkins-ci"]
    agent.restore("jenkins-ci")
    agent.credential("jenkins")
    agent.delete("jenkins")
    agent.purge("jenkins-ci")
    assert approver.requests and "PERMANENTLY" in approver.requests[-1].message
    assert agent.list(deleted=True) == []


def test_purge_denied_without_approval(vault):
    k = Keymaster(vault, actor=AGENT, approver=StaticApprover(allow=False))
    add_jenkins(k)
    k.delete("jenkins")
    with pytest.raises(PolicyDenied):
        k.purge("jenkins-ci")


# ------------------------------------------------------------------ policies
def test_open_reveals_without_asking(agent, approver):
    add_jenkins(agent, policy="open")
    _, vals = agent.reveal("jenkins")
    assert vals == {"token": "11aa22bb33cc44dd55ee"}
    assert approver.requests == []


def test_confirm_denied(vault):
    k = Keymaster(vault, actor=AGENT, approver=StaticApprover(allow=False))
    add_jenkins(k, policy="confirm")
    with pytest.raises(PolicyDenied):
        k.reveal("jenkins", purpose="login")
    # ...but using it (no reveal) is fine
    assert k.use("jenkins", "http").name == "jenkins-ci"


def test_confirm_grant_is_remembered_then_revoked(vault):
    ap = StaticApprover(allow=True, grant=True)
    k = Keymaster(vault, actor=AGENT, approver=ap)
    add_jenkins(k, policy="confirm")
    k.reveal("jenkins", purpose="login")
    k.reveal("jenkins", purpose="login again")
    assert len(ap.requests) == 1
    k.revoke_grants()
    k.reveal("jenkins")
    assert len(ap.requests) == 2


def test_secret_change_voids_grant(vault):
    ap = StaticApprover(allow=True, grant=True)
    k = Keymaster(vault, actor=AGENT, approver=ap)
    add_jenkins(k, policy="confirm")
    k.reveal("jenkins")
    k.update("jenkins", secrets={"token": "rotated-token-abcdef"})
    k.reveal("jenkins")
    assert len(ap.requests) == 2


def test_expired_grant(vault):
    ap = StaticApprover(allow=True, grant=True)
    k = Keymaster(vault, actor=AGENT, approver=ap)
    c = add_jenkins(k, policy="confirm")
    k.reveal("jenkins")
    with vault.transaction(write=True) as p:
        p["grants"][c.id] = time.time() - 1
    k.reveal("jenkins")
    assert len(ap.requests) == 2


def test_sealed_never_reveals_but_can_be_used(agent, approver):
    add_jenkins(agent, policy="sealed")
    with pytest.raises(PolicyDenied, match="sealed"):
        agent.reveal("jenkins")
    agent.use("jenkins", "run")
    assert approver.requests == []


def test_strict_asks_every_time(agent, approver):
    add_jenkins(agent, policy="strict")
    agent.use("jenkins", "run")
    agent.use("jenkins", "run")
    agent.reveal("jenkins")
    assert len(approver.requests) == 3
    assert all(not r.allow_grant for r in approver.requests)


def test_agent_cannot_loosen_policy_without_approval(vault):
    k = Keymaster(vault, actor=AGENT, approver=StaticApprover(allow=False))
    add_jenkins(k, policy="strict")
    with pytest.raises(PolicyDenied):
        k.update("jenkins", policy="open")
    k.update("jenkins", notes="tightening is fine")
    assert k.credential("jenkins").policy == "strict"


def test_human_bypasses_policy(human):
    add_jenkins(human, policy="sealed")
    _, vals = human.reveal("jenkins")
    assert vals["token"]


def test_usage_tracking(agent):
    add_jenkins(agent)
    agent.use("jenkins", "run")
    agent.reveal("jenkins")
    c = agent.credential("jenkins")
    assert c.use_count == 2 and c.last_used_at


def test_find_ambiguous_and_hint(agent):
    agent.add("jenkins-sg", secrets={"password": "abcdefghijkl1"}, urls=["https://jenkins-sg.example.com"], tags=["sg"])
    agent.add(
        "jenkins-mum", secrets={"password": "abcdefghijkl2"}, urls=["https://jenkins-mum.example.com"], tags=["mum"]
    )
    r = agent.find("jenkins")
    assert r["ambiguous"] and len(r["matches"]) == 2
    with pytest.raises(Ambiguous):
        agent.credential("jenkins")
    assert agent.find("jenkins mum")["matches"][0]["name"] == "jenkins-mum"
    assert agent.find("nothing-like-this-zzz")["hint"]


def test_not_found_suggests(agent):
    add_jenkins(agent)
    assert agent.credential("jnknsci").name == "jenkins-ci"  # typo-tolerant
    with pytest.raises(NotFound):
        agent.credential("totally-unrelated-thing")


def test_audit_trail_records_everything(agent, vault):
    add_jenkins(agent)
    agent.reveal("jenkins", purpose="login")
    agent.update("jenkins", notes="n")
    actions = [e["action"] for e in agent.audit_tail(50)]
    assert actions[-3:] == ["add", "reveal", "update"]
    assert all("11aa22" not in str(e) for e in agent.audit.entries())
    assert agent.audit.verify()["ok"]


def test_totp(agent):
    agent.add("aws-console", secrets={"password": "abcdefghijk1", "totp_secret": "JBSWY3DPEHPK3PXP"})
    r = agent.totp("aws-console")
    assert len(r["code"]) == 6 and 1 <= r["seconds_remaining"] <= 30


def test_health(agent):
    agent.add("a", secrets={"password": "password123"})
    agent.add("b", secrets={"password": "password123"}, urls=["https://b.com"])
    agent.add("c", secrets={"password": "Zq8#vR2!mK9$wL4^tP7&"}, urls=["https://c.com"], expires_at="2000-01-01")
    r = agent.health()
    kinds = {(i["cred"], i["kind"]) for i in r["issues"]}
    assert ("a", "weak") in kinds and ("a", "unfindable") in kinds and ("c", "expiry") in kinds
    assert any(i["kind"] == "reused" for i in r["issues"])
    assert r["grade"] in "CDF"
