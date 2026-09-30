import json

import pytest

from keymaster import crypto
from keymaster.errors import BadPassphrase, LockedOut, VaultCorrupted, VaultLocked
from keymaster.vault import export_document, import_document

from .conftest import PASS, make_vault


def test_create_unlock_lock(vault):
    assert vault.is_unlocked()
    vault.lock()
    assert not vault.is_unlocked()
    with pytest.raises(VaultLocked):
        with vault.transaction():
            pass
    assert vault.unlock(PASS) == "passphrase"
    assert vault.is_unlocked()


def test_file_is_private_and_has_no_plaintext(vault, agent):
    agent.add("jenkins", username="kiran", secrets={"password": "hunter2-super-secret"})
    raw = vault.layout.vault.read_text()
    assert "hunter2" not in raw and "jenkins" not in raw and "kiran" not in raw
    assert oct(vault.layout.vault.stat().st_mode & 0o777) == "0o600"
    assert oct(vault.layout.root.stat().st_mode & 0o777) == "0o700"


def test_wrong_passphrase_and_lockout(vault):
    vault.lock()
    for _ in range(4):
        with pytest.raises(BadPassphrase):
            vault.unlock("nope nope nope")
    with pytest.raises(BadPassphrase, match="Locked out"):
        vault.unlock("nope nope nope")
    with pytest.raises(LockedOut):
        vault.unlock(PASS)


def test_recovery_code_unlocks_even_with_sloppy_formatting(vault):
    vault.lock()
    code = vault.recovery_code.lower().replace("-", " ")
    assert vault.unlock(code) == "recovery"


def test_change_passphrase(vault):
    vault.change_passphrase(PASS, "a brand new passphrase")
    vault.lock()
    with pytest.raises(BadPassphrase):
        vault.unlock(PASS)
    vault.unlock("a brand new passphrase")


def test_rotate_dek_keeps_data(vault, agent):
    agent.add("x", secrets={"password": "p@ssw0rd-long-enough"})
    old = vault.dek()
    code = vault.rotate_dek(PASS)
    assert vault.dek() != old
    assert agent.credential("x").secrets["password"] == "p@ssw0rd-long-enough"
    vault.lock()
    assert vault.unlock(code) == "recovery"


def test_tampered_ciphertext_detected(vault):
    doc = json.loads(vault.layout.vault.read_text())
    ct = bytearray(crypto.b64d(doc["payload"]["ct"]))
    ct[5] ^= 1
    doc["payload"]["ct"] = crypto.b64e(bytes(ct))
    vault.layout.vault.write_text(json.dumps(doc))
    with pytest.raises(VaultCorrupted):
        with vault.transaction():
            pass


def test_generation_splice_detected(vault, agent):
    old = json.loads(vault.layout.vault.read_text())
    agent.add("x", secrets={"password": "abcdefgh12345"})
    new = json.loads(vault.layout.vault.read_text())
    new["payload"] = old["payload"]  # old payload under new header
    vault.layout.vault.write_text(json.dumps(new))
    with pytest.raises(VaultCorrupted):
        with vault.transaction():
            pass


def test_rollback_warning(vault, agent):
    snapshot = vault.layout.vault.read_bytes()
    agent.add("x", secrets={"password": "abcdefgh12345"})
    vault.layout.vault.write_bytes(snapshot)
    with vault.transaction():
        pass
    assert vault.rollback_warning and "rolled back" in vault.rollback_warning


def test_backups_pruned(vault, agent):
    vault.config.set("backup_count", 3)
    for i in range(6):
        agent.add(f"c{i}", secrets={"password": f"password-number-{i}"})
    assert len(vault.backups()) == 3


def test_export_import_roundtrip(vault, agent, tmp_path):
    agent.add("x", username="u", secrets={"password": "secret-value-123"}, urls=["https://x.com"])
    with vault.transaction() as p:
        doc = export_document(p, "export passphrase", kdf_params=crypto.ARGON2_TEST)
    f = tmp_path / "out.kmx"
    f.write_text(json.dumps(doc))
    assert "secret-value" not in f.read_text()
    payload = import_document(f, "export passphrase")
    (c,) = payload["credentials"].values()
    assert c["secrets"]["password"] == "secret-value-123"
    with pytest.raises(BadPassphrase):
        import_document(f, "wrong")


def test_auto_lock(vault):
    vault.config.set("auto_lock_hours", 1)
    st = vault.state.load()
    st["unlocked_at"] -= 7200
    vault.state.save(st)
    with pytest.raises(VaultLocked, match="auto-locked"):
        vault.dek()


def test_concurrent_writers_do_not_lose_updates(tmp_path):
    import threading

    from keymaster.core import HUMAN, Keymaster
    from keymaster.keystore import MemoryKeyStore

    ks = MemoryKeyStore()
    v = make_vault(tmp_path, ks)
    v.create(PASS)
    errors = []

    def worker(n):
        try:
            k = Keymaster(make_vault(tmp_path, ks), actor=HUMAN)
            for i in range(5):
                k.add(f"w{n}-{i}", secrets={"password": f"pw-{n}-{i}-xxxxxxxx"})
        except Exception as e:  # pragma: no cover
            errors.append(e)

    ts = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errors
    assert len(Keymaster(v, actor=HUMAN).list()) == 20
