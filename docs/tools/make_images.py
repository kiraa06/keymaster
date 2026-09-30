"""Render the README images from a fabricated, in-memory vault (nothing real is touched).

uv run python docs/tools/make_images.py
"""

import contextlib
import tempfile
from pathlib import Path

from rich.console import Console

from keymaster import cli, crypto
from keymaster.approval import StaticApprover
from keymaster.core import AGENT, HUMAN, Keymaster
from keymaster.keystore import MemoryKeyStore
from keymaster.vault import Vault

DOCS = Path(__file__).resolve().parents[1]


def demo_vault() -> Keymaster:
    v = Vault(Path(tempfile.mkdtemp()) / "km", keystore=MemoryKeyStore())
    v._kdf_params = crypto.ARGON2_TEST
    v.create("demo passphrase for screenshots")
    k = Keymaster(v, HUMAN)
    add = k.add
    add(
        "jenkins-ci",
        "token",
        username="ada",
        secrets={"token": "11c0ffee22" * 3},
        urls=["https://ci.example.com"],
        aliases=["jenkins", "ci"],
        tags=["prod"],
        policy="confirm",
    )
    add(
        "jenkins-staging",
        "token",
        username="ada",
        secrets={"token": "33beef44" * 4},
        urls=["https://ci-staging.example.com"],
        tags=["staging"],
        policy="open",
    )
    add(
        "aws-prod",
        "aws",
        username="AKIAIOSFODNN7EXAMPLE",
        secrets={"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
        fields={"region": "eu-central-1"},
        aliases=["aws"],
        tags=["prod"],
        policy="sealed",
    )
    add(
        "orders-db",
        "database",
        username="app",
        secrets={"password": "Zq8#vR2!mK9$wL4^tP7&"},
        fields={"host": "db1.internal", "port": "5432"},
        aliases=["postgres"],
        tags=["prod"],
        policy="sealed",
    )
    add(
        "github",
        "token",
        username="ada",
        secrets={"token": "ghp_" + "x" * 36, "totp_secret": "JBSWY3DPEHPK3PXP"},
        urls=["github.com"],
        aliases=["gh"],
        policy="open",
    )
    add(
        "grafana",
        "password",
        username="admin",
        secrets={"password": "admin123"},
        urls=["*.grafana.example.com"],
        policy="strict",
        expires_at="2026-10-05",
    )
    add(
        "okta",
        "password",
        username="ada@example.com",
        secrets={"password": "admin123", "totp_secret": "JBSWY3DPEHPK3PXQ"},
        urls=["example.okta.com"],
        policy="confirm",
    )

    approver = StaticApprover(allow=True, grant=True)
    approver.method = "touchid"
    agent = Keymaster(v, AGENT, approver=approver)
    agent.find("https://ci.example.com/job/deploy-api/412/console")
    agent.reveal("jenkins", purpose="log in to the Jenkins UI")
    agent.run("orders-db", 'test -n "$PGPASSWORD"', purpose="check the DB connection is wired up")
    agent.totp("github", purpose="2FA prompt on github.com")
    try:
        agent.reveal("aws-prod")
    except Exception:
        pass
    return k


def shot(k: Keymaster, name: str, width: int, *commands) -> None:
    con = Console(record=True, width=width, force_terminal=True, color_system="truecolor")
    con.status = lambda *a, **kw: contextlib.nullcontext()  # no spinners in screenshots
    cli.console = con
    cli._ready = lambda actor=None: k
    cli._km = lambda actor=None: k
    for i, (prompt, fn) in enumerate(commands):
        if i:
            con.print()
        con.print(f"[bold green]❯[/] [bold]{prompt}[/]")
        fn()
    con.save_svg(str(DOCS / name), title="km")
    print("wrote", DOCS / name)


if __name__ == "__main__":
    k = demo_vault()
    shot(
        k,
        "demo.svg",
        118,
        (
            "km find https://ci.example.com/job/deploy-api/412",
            lambda: cli.find("https://ci.example.com/job/deploy-api/412", limit=3),
        ),
        ("km ls", lambda: cli.list_(type=None, tag=None, as_json=False)),
    )
    shot(
        k,
        "audit.svg",
        118,
        ("km audit", lambda: cli.audit(limit=8, ref=None, verify=False)),
        ("km health", lambda: cli.health(pwned=False)),
    )
