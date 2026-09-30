"""Exercise the MCP tool layer in-process (keystore swapped for memory)."""

import asyncio
import json

import pytest

import keymaster.server as srv
from keymaster.approval import StaticApprover
from keymaster.core import AGENT, Keymaster


@pytest.fixture
def mcp_env(vault, monkeypatch):
    ap = StaticApprover(allow=True, secrets=["typed-in-dialog-secret"])
    monkeypatch.setattr(srv, "km", lambda: Keymaster(vault, actor=AGENT, approver=ap))
    return ap


def call(_tool, **args):
    res = asyncio.run(srv.mcp.call_tool(_tool, args))
    blocks = res[0] if isinstance(res, tuple) else getattr(res, "content", res)
    text = "".join(getattr(b, "text", "") for b in blocks)
    return json.loads(text)


def test_full_agent_flow(mcp_env):
    r = call(
        "add_credential",
        name="jenkins-ci",
        type="token",
        username="kiran",
        urls=["https://ci.jenkins.example.com"],
        aliases=["jenkins"],
        secret_source="prompt",
        policy="confirm",
    )
    assert r["secret"].startswith("typed by user")
    assert "typed-in-dialog" not in json.dumps(r)
    found = call("find_credentials", query="https://ci.jenkins.example.com/job/deploy")
    assert found["matches"][0]["name"] == "jenkins-ci"
    got = call("get_credential", ref="jenkins", reveal=True, purpose="log into Jenkins UI")
    assert got["secrets"]["token"] == "typed-in-dialog-secret"
    assert mcp_env.requests and "log into Jenkins UI" in mcp_env.requests[0].message
    ran = call("run_with_credential", ref="jenkins", command='echo "$KM_USERNAME:$KM_TOKEN"')
    assert ran["stdout"].strip() == "«redacted:jenkins-ci.basic-auth»"  # user:token pair scrubbed too
    upd = call("update_credential", ref="jenkins", add_aliases=["build server"], secret_source="generate")
    assert "aliases" in upd["changed"] and "secrets" in upd["changed"]
    assert call("credential_history", ref="jenkins")["versions"]
    gen = call("generate_secret", store_in="jenkins", reason="rotation")
    assert "value" not in gen and gen["stored_in"] == "jenkins-ci.token"
    call("delete_credential", ref="jenkins")
    assert call("list_trash")["trash"][0]["name"] == "jenkins-ci"
    call("restore_credential", ref="jenkins-ci")
    log = call("audit_log", limit=50)
    assert log["chain"]["ok"]
    assert {"add", "reveal", "run", "update", "delete", "restore"} <= {e["action"] for e in log["entries"]}


def test_locked_vault_gives_friendly_error(vault, mcp_env):
    vault.lock()
    from mcp.server.mcpserver.exceptions import ToolError

    with pytest.raises(ToolError, match="km unlock"):
        asyncio.run(srv.mcp.call_tool("find_credentials", {"query": "x"}))


def test_status_works_when_locked(vault, mcp_env):
    vault.lock()
    assert call("vault_status")["unlocked"] is False
