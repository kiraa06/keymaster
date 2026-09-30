import json

import pytest

from keymaster import hook, integrations
from keymaster.vault import Vault


@pytest.mark.parametrize(
    "prompt",
    [
        "what all creds u have?",
        "log in to jenkins and restart the job",
        "use my github token to open a PR",
        "what's the password for grafana",
        "call the billing API with the api key",
        "I need the 2FA code for okta",
    ],
)
def test_intent_triggers(prompt, tmp_path):
    assert hook.build_context(prompt, vault=Vault(tmp_path / "none"))


@pytest.mark.parametrize(
    "prompt",
    [
        "refactor this function to be async",
        "summarise https://docs.python.org/3/library/asyncio.html",
        "why is the test flaky?",
    ],
)
def test_ordinary_prompts_stay_quiet(prompt, tmp_path):
    assert hook.build_context(prompt, vault=Vault(tmp_path / "none")) is None


def test_names_matching_credentials(vault, agent):
    agent.add(
        "jenkins-ci", "token", secrets={"token": "abcdef123456"}, urls=["https://ci.example.com"], aliases=["jenkins"]
    )
    agent.add("prod-db", "database", secrets={"password": "abcdef123456"}, fields={"host": "db1.internal"})
    ctx = hook.build_context("check the last build on ci.example.com", vault=vault)
    assert ctx and "jenkins-ci" in ctx and "prod-db" not in ctx
    ctx = hook.build_context("is db1.internal up?", vault=vault)
    assert ctx and "prod-db" in ctx
    assert "abcdef" not in (ctx or "")


def test_main_emits_hook_json(monkeypatch, capsys):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"prompt": "what creds do you have"})))
    hook.main()
    out = json.loads(capsys.readouterr().out)
    assert out["hookSpecificOutput"]["hookEventName"] == "UserPromptSubmit"
    assert "find_credentials" in out["hookSpecificOutput"]["additionalContext"]


def test_main_never_crashes_on_garbage(monkeypatch, capsys):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
    hook.main()
    assert capsys.readouterr().out == ""


def test_settings_hook_install_is_idempotent_and_preserves_others(tmp_path):
    s = tmp_path / "settings.json"
    other = {"hooks": [{"type": "command", "command": "/usr/bin/other-hook"}]}
    s.write_text(json.dumps({"model": "opus", "hooks": {"UserPromptSubmit": [other], "Stop": [other]}}))
    assert integrations.install_hook(s, "/x/keymaster-hook") == "added"
    assert integrations.install_hook(s, "/x/keymaster-hook") == "unchanged"
    assert integrations.install_hook(s, "/y/keymaster-hook") == "updated"
    data = json.loads(s.read_text())
    ups = data["hooks"]["UserPromptSubmit"]
    assert len(ups) == 2 and ups[0] == other and ups[1]["hooks"][0]["command"] == "/y/keymaster-hook"
    assert data["model"] == "opus" and data["hooks"]["Stop"] == [other]
    assert integrations.remove_hook(s)
    data = json.loads(s.read_text())
    assert data["hooks"]["UserPromptSubmit"] == [other] and data["hooks"]["Stop"] == [other]
    assert (tmp_path / "settings.json.keymaster.bak").exists()


def test_claude_md_block_add_update_remove(tmp_path):
    md = tmp_path / "CLAUDE.md"
    md.write_text("# My rules\n\n- be nice")
    assert integrations.install_claude_md(md) == "added"
    assert integrations.install_claude_md(md) == "unchanged"
    text = md.read_text()
    assert text.startswith("# My rules\n\n- be nice\n") and text.count(integrations.START) == 1
    md.write_text(text.replace("Keymaster (MCP", "OLD Keymaster (MCP"))
    assert integrations.install_claude_md(md) == "updated"
    assert "OLD" not in md.read_text()
    assert integrations.remove_claude_md(md)
    assert md.read_text() == "# My rules\n\n- be nice\n"


def test_claude_md_created_when_missing(tmp_path):
    md = tmp_path / "sub" / "CLAUDE.md"
    assert integrations.install_claude_md(md) == "added"
    assert md.read_text().startswith(integrations.START)
