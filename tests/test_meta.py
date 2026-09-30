import tomllib
from pathlib import Path

import keymaster


def test_version_matches_pyproject():
    meta = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())
    assert meta["project"]["version"] == keymaster.__version__
