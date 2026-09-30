import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from keymaster import crypto, generator, totp
from keymaster.audit import AuditLog
from keymaster.errors import BadPassphrase, PolicyDenied
from keymaster.models import Credential
from keymaster.redact import Redactor
from keymaster.resolver import host_allowed, rank
from keymaster.runner import http_request, run_command


# ------------------------------------------------------------------ crypto
def test_seal_roundtrip_and_aad_binding():
    k = crypto.random_key()
    box = crypto.seal(k, b"hello", b"aad-1")
    assert crypto.unseal(k, box, b"aad-1") == b"hello"
    with pytest.raises(BadPassphrase):
        crypto.unseal(k, box, b"aad-2")
    with pytest.raises(BadPassphrase):
        crypto.unseal(crypto.random_key(), box, b"aad-1")


def test_kdf_deterministic_and_unicode_normalized():
    kdf = crypto.new_kdf(crypto.ARGON2_TEST)
    assert crypto.derive_kek("café", kdf) == crypto.derive_kek("café", kdf)
    assert crypto.derive_kek("a", kdf) != crypto.derive_kek("b", kdf)


def test_recovery_code_shape():
    c = crypto.new_recovery_code()
    assert crypto.looks_like_recovery_code(c) and len(c) == 35
    assert crypto.normalize_recovery_code(c.lower().replace("-", "")) == c


# ------------------------------------------------------------------ totp (RFC 6238 appendix B)
RFC_SEED = base64.b32encode(b"12345678901234567890").decode()


@pytest.mark.parametrize(
    "t,code", [(59, "94287082"), (1111111109, "07081804"), (1234567890, "89005924"), (20000000000, "65353130")]
)
def test_totp_rfc_vectors(t, code):
    assert totp.code_at(totp.TotpSpec(base64.b32decode(RFC_SEED), digits=8), t) == code


def test_totp_otpauth_uri():
    spec = totp.parse(f"otpauth://totp/ACME:kiran?secret={RFC_SEED}&digits=8&period=30&algorithm=SHA1&issuer=ACME")
    assert spec.digits == 8 and totp.code_at(spec, 59) == "94287082"


# ------------------------------------------------------------------ generator
def test_password_generator():
    for _ in range(50):
        p = generator.password(20)
        assert len(p) == 20
        assert any(c.isupper() for c in p) and any(c.islower() for c in p) and any(c.isdigit() for c in p)
        assert not set(p) & generator.AMBIGUOUS
    assert generator.password(12, symbols=False).isalnum()


def test_passphrase_and_strength():
    pp = generator.passphrase(5)
    assert len(pp.split("-")) == 5
    assert generator.strength("password1")["rating"] == "weak"
    assert generator.strength(generator.password(24))["rating"] in ("strong", "excellent")


# ------------------------------------------------------------------ resolver
def creds():
    return [
        Credential(
            id="1",
            name="jenkins-sg",
            type="token",
            secrets={"token": "t"},
            urls=["https://jenkins-sg.corp.com"],
            tags=["sg"],
        ),
        Credential(
            id="2",
            name="jenkins-mum",
            type="token",
            secrets={"token": "t"},
            urls=["https://jenkins-mum.corp.com/ci/"],
            aliases=["mumbai ci"],
        ),
        Credential(id="3", name="grafana", type="password", secrets={"password": "p"}, urls=["*.grafana.corp.com"]),
        Credential(
            id="4",
            name="prod-db",
            type="database",
            secrets={"password": "p"},
            fields={"host": "db1.internal"},
            tags=["prod", "postgres"],
        ),
    ]


@pytest.mark.parametrize(
    "q,expected",
    [
        ("https://jenkins-sg.corp.com/job/deploy/42/console", "jenkins-sg"),
        ("jenkins-mum.corp.com/ci/job/x", "jenkins-mum"),
        ("https://eu.grafana.corp.com/d/abc", "grafana"),
        ("mumbai ci", "jenkins-mum"),
        ("jenkns sg", "jenkins-sg"),
        ("postgres prod", "prod-db"),
        ("db1.internal", "prod-db"),
    ],
)
def test_rank(q, expected):
    assert rank(q, creds())[0].cred.name == expected


def test_url_query_drops_word_overlap_noise():
    cs = creds() + [Credential(id="5", name="ci-notes", type="note", secrets={"note": "n"}, tags=["corp"])]
    names = [m.cred.name for m in rank("https://jenkins-sg.corp.com/job/x", cs)]
    assert names == ["jenkins-sg"]


def test_host_guard():
    c = creds()[0]
    assert host_allowed(c, "https://jenkins-sg.corp.com/api/json")
    assert not host_allowed(c, "https://evil.com/?x=jenkins-sg.corp.com")
    assert not host_allowed(c, "https://jenkins-sg.corp.com.evil.com/")


# ------------------------------------------------------------------ redaction
def test_redactor_catches_encodings():
    c = Credential(id="1", name="x", type="password", username="kiran", secrets={"password": "S3cr3t!Pass"})
    r = Redactor([c])
    raw = "S3cr3t!Pass"
    text = f"a {raw} b {base64.b64encode(raw.encode()).decode()} c {base64.b64encode(b'kiran:S3cr3t!Pass').decode()} d S3cr3t%21Pass"
    out = r(text)
    assert "S3cr3t" not in out and "UzNjcjN0" not in out
    assert "«redacted:x.password»" in out and "«redacted:x.basic-auth»" in out


# ------------------------------------------------------------------ runner
def test_run_command_env_and_redaction():
    c = Credential(
        id="1",
        name="aws-sg",
        type="aws",
        username="AKIAEXAMPLE",
        secrets={"secret_access_key": "wJalrXUtnFEMI/K7MDENG"},
        fields={"region": "ap-southeast-1"},
    )
    r = run_command(c, 'echo "$AWS_ACCESS_KEY_ID $AWS_REGION $AWS_SECRET_ACCESS_KEY"; echo "$KM_SECRET" | base64')
    assert r["exit_code"] == 0
    assert "AKIAEXAMPLE ap-southeast-1 «redacted:aws-sg.secret_access_key»" in r["stdout"]
    assert "wJalr" not in r["stdout"]


def test_run_command_ssh_keyfile_is_cleaned_up():
    c = Credential(
        id="1",
        name="gh",
        type="ssh_key",
        secrets={"private_key": "-----BEGIN KEY-----\nabcdefghijklmnopqrstuvwxyz0123\n-----END KEY-----"},
    )
    r = run_command(
        c,
        'python3 -c "import os,sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777)[2:])" "$KM_KEY_FILE"; echo "$KM_KEY_FILE"',
    )
    mode, path = r["stdout"].split()
    assert mode == "600"
    import os

    assert not os.path.exists(path)


def test_run_command_env_mapping_and_stdin():
    c = Credential(id="1", name="j", type="token", username="me", secrets={"token": "tok-123456"})
    r = run_command(c, 'echo "$MY"; cat', env_map={"MY": "{{km.username}}@x"}, stdin="{{km.username}}!")
    assert r["stdout"] == "me@x\nme!"


class _Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"auth": self.headers.get("Authorization"), "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    s = HTTPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{s.server_port}"
    s.shutdown()


def test_http_request_injects_auth_and_redacts(server):
    c = Credential(
        id="1", name="jenkins", type="token", username="kiran", secrets={"token": "abcdef123456"}, urls=[server]
    )
    r = http_request(c, "GET", f"{server}/api/json")
    assert r["status"] == 200 and r["auth_style"] == "basic"
    assert "abcdef123456" not in r["body"] and "YWJj" not in r["body"]
    assert "«redacted:jenkins.basic-auth»" in r["body"]
    c.username = None
    r = http_request(c, "GET", f"{server}/x?t={{{{km.token}}}}")
    assert "Bearer «redacted:jenkins.token»" in r["body"] and "?t=«redacted:jenkins.token»" in r["body"]


def test_http_request_host_guard(server):
    c = Credential(
        id="1", name="jenkins", type="token", secrets={"token": "abcdef123456"}, urls=["https://ci.corp.com"]
    )
    with pytest.raises(PolicyDenied, match="not registered"):
        http_request(c, "GET", f"{server}/steal")
    with pytest.raises(PolicyDenied, match="plain http"):
        http_request(c, "GET", "http://ci.corp.com/", allow_any_host=True)


# ------------------------------------------------------------------ audit
def test_audit_chain_detects_edits_and_deletions(tmp_path):
    key = crypto.random_key()
    log = AuditLog(tmp_path / "a.jsonl", lambda: key)
    for i in range(5):
        log.append("reveal", actor="agent", n=i)
    assert log.verify() == {"ok": True, "entries": 5}
    lines = (tmp_path / "a.jsonl").read_text().splitlines()
    (tmp_path / "a.jsonl").write_text("\n".join(lines[:2] + lines[3:]) + "\n")
    assert not log.verify()["ok"]
    edited = lines[:]
    edited[1] = edited[1].replace('"reveal"', '"find"')
    (tmp_path / "a.jsonl").write_text("\n".join(edited) + "\n")
    r = log.verify()
    assert not r["ok"] and r["broken_at_line"] == 2
