# Contributing

Thanks for taking a look. Issues and pull requests are both welcome. For anything
security-related, please read [SECURITY.md](SECURITY.md) first.

## Getting set up

```sh
git clone https://github.com/kiraa06/keymaster
cd keymaster
uv sync
uv run pytest -q
uv tool install --editable .     # `km` and `keymaster-mcp` now run your checkout
```

Python 3.11 or newer. [uv](https://docs.astral.sh/uv) manages everything else.

## Before opening a pull request

CI runs these on Linux and macOS (Python 3.11 and 3.13), so run them first:

```sh
uvx ruff check src tests
uvx ruff format --check src tests
uv run pytest -q
```

The tests never touch your real vault or keychain. They use an in-memory keystore and cheap KDF
parameters. If you add an MCP tool, add it to `tests/test_mcp.py`. If you touch crypto, the file
format or the policy engine, add a test that shows the attack failing.

## How the code is laid out

See [`docs/DESIGN.md`](docs/DESIGN.md#layout). In short: `core.py` is the only place that
decides what's allowed. `server.py` (MCP) and `cli.py` (`km`) are thin layers over it, so a rule
added there applies to both.

## Trying the MCP server by hand

```sh
KEYMASTER_HOME=/tmp/km-dev km init                 # a throwaway vault
KEYMASTER_HOME=/tmp/km-dev npx @modelcontextprotocol/inspector keymaster-mcp
```

## Regenerating the README images

`docs/demo.svg` and `docs/audit.svg` are rendered from a fabricated in-memory vault. Nothing on
your machine is read:

```sh
uv run python docs/tools/make_images.py
```

## Releasing

Bump `version` in `pyproject.toml` and `src/keymaster/__init__.py`, then push a matching tag
(`git tag v1.2.3 && git push --tags`). The release workflow tests, builds the wheel, writes
`checksums.txt`, and publishes the GitHub release that `install.sh` installs from.
