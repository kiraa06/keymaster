import pytest

from keymaster import crypto
from keymaster.approval import StaticApprover
from keymaster.core import AGENT, HUMAN, Keymaster
from keymaster.keystore import MemoryKeyStore
from keymaster.vault import Vault

PASS = "correct horse battery staple"


def make_vault(tmp_path, keystore=None) -> Vault:
    v = Vault(tmp_path / "km", keystore=keystore or MemoryKeyStore())
    v._kdf_params = crypto.ARGON2_TEST
    return v


@pytest.fixture
def vault(tmp_path):
    v = make_vault(tmp_path)
    v.recovery_code = v.create(PASS)
    return v


@pytest.fixture
def approver():
    return StaticApprover(allow=True)


@pytest.fixture
def agent(vault, approver):
    return Keymaster(vault, actor=AGENT, approver=approver)


@pytest.fixture
def human(vault):
    return Keymaster(vault, actor=HUMAN, approver=StaticApprover(allow=False))
