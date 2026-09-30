#!/bin/sh
# Install Keymaster — a local, encrypted credential vault with an MCP server.
#
#   curl -fsSL https://raw.githubusercontent.com/kiraa06/keymaster/main/install.sh | sh
#
# What it does (idempotent — safe to re-run to upgrade):
#   1. installs uv (https://docs.astral.sh/uv) if it isn't already there
#   2. installs the `km` and `keymaster-mcp` commands from the latest release
#      (checksum-verified), with their own Python — nothing touches your system Python
#   3. registers the MCP server with Claude Code, if `claude` is on your PATH
#   4. offers to create your vault (`km init`)
#
# Environment:
#   VERSION=v1.2.3          install a specific release (default: latest)
#   KEYMASTER_SOURCE=path   install from a local checkout / URL instead of a release
#   KEYMASTER_SKIP_INIT=1   don't offer to create a vault
#   KEYMASTER_SKIP_MCP=1    don't register with Claude Code

set -eu

REPO="kiraa06/keymaster"
PY="3.12"

say() { printf '\033[1;33m==>\033[0m %s\n' "$*"; }
ok() { printf '\033[1;32m ✓\033[0m %s\n' "$*"; }
warn() { printf '\033[1;35m !\033[0m %s\n' "$*" >&2; }
die() {
	printf '\033[1;31minstall: %s\033[0m\n' "$*" >&2
	exit 1
}

case "$(uname -s)" in
Darwin) os=macos ;;
Linux) os=linux ;;
*) die "unsupported operating system: $(uname -s) (Keymaster supports macOS and Linux)" ;;
esac

command -v curl >/dev/null 2>&1 || die "curl is required"

cat <<'EOF'

      .--.
     /.-. '----------.
     \'-' .--"--""-"-'    K E Y M A S T E R
      '--'                "Are you the Keymaster?"

EOF

# ---------------------------------------------------------------- 1. uv
ORIG_PATH="$PATH"
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
if ! command -v uv >/dev/null 2>&1; then
	say "Installing uv (Python package manager from Astral)"
	curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null || die "uv install failed"
	command -v uv >/dev/null 2>&1 || die "uv installed but not on PATH; open a new shell and re-run"
fi
ok "uv $(uv --version | awk '{print $2}')"

# ---------------------------------------------------------------- 2. keymaster
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

if [ -n "${KEYMASTER_SOURCE:-}" ]; then
	target="$KEYMASTER_SOURCE"
	label="$KEYMASTER_SOURCE"
else
	api="https://api.github.com/repos/$REPO/releases"
	if [ -n "${VERSION:-}" ]; then
		meta="$(curl -fsSL "$api/tags/$VERSION" 2>/dev/null || true)"
	else
		meta="$(curl -fsSL "$api/latest" 2>/dev/null || true)"
	fi
	version="$(printf '%s' "$meta" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
	wheel_url="$(printf '%s' "$meta" | sed -n 's/.*"browser_download_url": *"\([^"]*\.whl\)".*/\1/p' | head -n 1)"

	if [ -n "$wheel_url" ]; then
		wheel="$tmp/$(basename "$wheel_url")"
		say "Downloading Keymaster $version"
		curl -fsSL "$wheel_url" -o "$wheel" || die "download failed: $wheel_url"
		sums_url="https://github.com/$REPO/releases/download/$version/checksums.txt"
		if curl -fsSL "$sums_url" -o "$tmp/checksums.txt" 2>/dev/null; then
			expected="$(grep " $(basename "$wheel")\$" "$tmp/checksums.txt" | awk '{print $1}' | head -n 1)"
			if command -v shasum >/dev/null 2>&1; then
				actual="$(shasum -a 256 "$wheel" | awk '{print $1}')"
			else
				actual="$(sha256sum "$wheel" | awk '{print $1}')"
			fi
			if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
				die "checksum mismatch for $(basename "$wheel")"
			fi
			ok "checksum verified"
		fi
		target="$wheel"
		label="$version"
	else
		[ -n "${VERSION:-}" ] && die "release $VERSION not found"
		warn "no release found; installing from the main branch"
		target="keymaster @ https://github.com/$REPO/archive/refs/heads/main.tar.gz"
		label="main"
	fi
fi

say "Installing km + keymaster-mcp ($label)"
uv tool install --force --quiet --python "$PY" "$target" || die "uv tool install failed"
bindir="$(uv tool dir --bin 2>/dev/null || echo "$HOME/.local/bin")"
export PATH="$bindir:$PATH"
command -v km >/dev/null 2>&1 || die "km was installed to $bindir but can't be found"
ok "$(km version) → $bindir"

# ---------------------------------------------------------------- 3. MCP registration
if [ -z "${KEYMASTER_SKIP_MCP:-}" ]; then
	if command -v claude >/dev/null 2>&1; then
		if km install-mcp >/dev/null 2>&1; then
			ok "registered with Claude Code (user scope) — restart Claude Code to load it"
		else
			warn "couldn't register with Claude Code; run: km install-mcp"
		fi
	else
		warn "Claude Code not found. For any MCP client, point it at: $bindir/keymaster-mcp"
	fi
fi

# ---------------------------------------------------------------- 4. vault
home="${KEYMASTER_HOME:-$HOME/.keymaster}"
if [ -f "$home/vault.km" ]; then
	ok "existing vault found at $home (kept as is)"
elif [ -z "${KEYMASTER_SKIP_INIT:-}" ] && [ -r /dev/tty ] && [ -w /dev/tty ]; then
	printf '\nCreate your vault now? [Y/n] ' >/dev/tty
	read -r answer </dev/tty || answer=n
	case "$answer" in
	"" | y | Y | yes) km init </dev/tty >/dev/tty 2>&1 || warn "km init did not finish; run it again any time" ;;
	*) say "Skipped. Create it later with: km init" ;;
	esac
else
	say "Next: km init"
fi

echo
if [ "$os" = macos ]; then
	echo "Tip: approve access with your fingerprint →  km touchid setup"
else
	echo "Linux: needs a Secret Service (GNOME Keyring / KWallet); approval dialogs use zenity."
fi
echo "Add a login:   km add jenkins -t token -u me --url https://ci.example.com"
echo "Then just ask your agent: \"check the last build on ci.example.com\""

case ":$ORIG_PATH:" in
*":$bindir:"*) ;;
*)
	echo
	echo "$bindir is not on your PATH. Add it:"
	echo "  echo 'export PATH=\"$bindir:\$PATH\"' >> ~/.zshrc && exec zsh"
	;;
esac
