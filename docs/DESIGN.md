# Keymaster design

## Goals

1. An agent should be able to authenticate to anything you've stored **without you saying where
   the secret is**, and ideally without the secret entering the conversation at all.
2. Secrets are safe **at rest**: a copied vault file, a synced backup or a stolen disk reveals
   nothing.
3. **You** stay in control: nothing sensitive happens without a trace, and the risky things need
   your approval, given out-of-band where the agent can't answer for you.

## Layout

```
~/.keymaster/
  vault.km          encrypted vault (JSON envelope, 0600)
  audit.jsonl       HMAC hash-chained audit log (no secret values)
  state.json        non-secret runtime state: unlock time, failed attempts, last generation
  config.json       settings
  backups/          rolling encrypted snapshots, taken before every change
  bin/km-touchid    optional Touch ID helper, compiled locally from Swift
```

| module | responsibility |
|---|---|
| `crypto` | Argon2id / scrypt KDF, AES-256-GCM seal/unseal, HKDF sub-keys, recovery codes |
| `vault` | file format, key slots, atomic writes, `flock`, backups, rollback detection |
| `keystore` | where the unwrapped key lives while unlocked (OS keychain) |
| `models` | the `Credential` record and validation |
| `resolver` | URL / host / alias / fuzzy-text ranking, the host allow-list guard |
| `core` | the one service everything goes through: policy engine, approvals, audit |
| `runner` | env injection, authenticated HTTP, placeholder substitution |
| `redact` | scrubbing secrets and their encodings out of text |
| `approval` | native dialogs (osascript / zenity), Touch ID, secure input |
| `server` / `cli` | MCP tools / `km` command, both thin layers over `core` |

## Cryptography

**Envelope encryption with key slots**, similar to LUKS:

- A random 256-bit **DEK** encrypts the payload (all credentials, approval grants and meta)
  with **AES-256-GCM** and a fresh 96-bit nonce per write.
- Each **slot** wraps the DEK with a KEK derived from a human secret:
  - `passphrase`: Argon2id with `t=3, m=64 MiB, p=4` and a 16-byte random salt. The
    parameters are stored per slot, so they can be raised later without breaking old vaults.
  - `recovery`: the same KDF over a 30-character Crockford-base32 code (150 bits).
- Passphrases are NFKC-normalised, so the same passphrase typed on different keyboards derives
  the same key.
- Changing the passphrase rewrites one slot. `km rotate-key` generates a new DEK, re-encrypts
  the payload and re-wraps both slots.

**Associated data** binds every ciphertext to its context:

| blob | AAD |
|---|---|
| slot | `keymaster-slot:v1:<vault_id>:<kind>` |
| payload | `keymaster-payload:v1:<vault_id>:<generation>` |

`generation` increments on every write and is also stored inside the payload, so:

- **tampering**: any flipped bit fails authentication.
- **splicing** (an old payload under a new header): the generation mismatch fails authentication.
- **rollback** (replacing the whole file with an older copy): the ciphertext is valid, but
  `state.json` remembers the highest generation seen, so it's reported as a warning.
  `km backups restore` resets that marker deliberately.

**Sub-keys** come from HKDF-SHA256. The audit log uses its own random key, kept in the keychain
even while the vault is locked, so failed unlock attempts are still recorded in the chain.

## Unlocking

"Unlocked" means the DEK is stored in the OS keychain: the macOS Keychain via Security.framework,
or the Secret Service on Linux (both through `keyring`, never on a command line). The MCP server
and the CLI are stateless. Every operation takes a file lock, reads the DEK from the keychain,
decrypts, works and re-encrypts. The CLI and the server therefore can't disagree, and there's no
long-lived process holding plaintext.

`km lock` / `km panic` / `lock_vault` delete the keychain item. `auto_lock_hours` does the same
on a timer. Unlocking always needs the human: either the terminal, or a secure dialog that the
agent triggers but can't fill in.

After 5 consecutive wrong passphrases, each further attempt locks out for 30s, doubling up to 1h.
This throttles the online paths (dialog, CLI). An offline attacker with the file still faces
Argon2id.

## Policy engine

All access goes through `Keymaster` in `core.py`, with an **actor**:

- `human`: the `km` CLI with a real TTY on both stdin and stdout.
- `agent`: the MCP server, and **`km` without a TTY** (for example when the agent shells out).

| policy | agent: use | agent: reveal |
|---|---|---|
| open | ✓ | ✓ |
| confirm | ✓ | approval; can grant for `grant_minutes` |
| sealed | ✓ | ✗ |
| strict | approval each time | approval each time |

Grants are stored inside the encrypted payload, so they can't be forged by editing a file. A new
secret voids existing grants. `revoke_approvals` and `km panic` clear them all. Loosening a
policy (for example `strict → open`) and purging a credential always need a fresh approval. The
agent can't widen its own access.

Approvals happen outside the agent's channel: an AppleScript or zenity dialog, or Touch ID
through a tiny Swift helper using `LocalAuthentication`, compiled on your machine by
`km touchid setup`. Only the decision comes back. Dialogs time out after 90s, and a timeout
counts as a denial.

## Using without revealing

- **`run_with_credential`** runs `bash -c` with the credential in environment variables.
  stdout and stderr go through the redactor, which replaces every secret with
  `«redacted:name.field»`. It also catches the raw value, standard and URL-safe base64, URL
  encoding, hex, JSON-escaped newlines, every 16+ character line of multi-line secrets (PEM
  bodies), and `username:secret` in all those encodings. SSH keys go to a `0600` temp file that
  is overwritten and unlinked afterwards.
- **`http_request`** refuses any host that isn't registered on the credential. It matches the
  exact host (with an optional path prefix), a wildcard, or a `host` field, so a prompt-injected
  "send the token to evil.com" fails. It refuses plain `http` except to localhost, and follows
  redirects only while they stay on registered hosts. `{{km.field}}` placeholders are filled in
  inside the Keymaster process.

The scrubber is a safety net for accidents, not a sandbox. An agent actively trying to exfiltrate
through `run_with_credential` (for example by reversing the string) can get around it. That's
what `sealed` + `http_request` and `strict` are for.

## Resolver

Scores run from 0 to 100:

| score | signal |
|---|---|
| 100 | exact id |
| 95 | exact name / alias |
| 90–99 | URL host (+ path-prefix depth) |
| 88 | `host` field |
| 85 | same host, different path |
| 75 | wildcard host |
| 40–85 | token overlap across name, aliases, tags, URL hosts and username, with difflib typo matching |
| 30 | same registrable domain |

Matches under 35 are dropped. When a URL query has a real host match (75+), matches under 60 are
also dropped, so shared words like `example` or `ci` don't add noise. If the top two scores are
within 8 points, the result is flagged `ambiguous` and the agent is told to ask you.

## Getting the agent to use it

A server's instructions are a weak signal. Claude Code shows an MCP server's instructions once,
truncates them past about 2 KB, and with many servers it *defers* their tools, so the model sees
only names until it searches for them. In practice an agent asked "what creds do you have?"
would fall back to `aws configure list-profiles` and `gh auth status`. So Keymaster installs
three layers:

| layer | when it acts | strength |
|---|---|---|
| server instructions + tool descriptions (rule in the first line) | tools are listed | weak |
| `~/.claude/CLAUDE.md` block | every session, always in context | strong |
| `keymaster-hook` on `UserPromptSubmit` | every prompt that looks credential-related | strongest: specific and timely |

The hook matches credential-intent words, plus stored names, aliases and hosts (read only when
the vault is already unlocked). It prints only credential names. It never raises and always
exits 0, so it can't block a prompt.

## Durability

- Writes go to a temp file, then `fsync`, `rename` and a directory `fsync`.
- Every read/write takes `flock` (shared or exclusive), so the CLI and several MCP server
  processes can run at once. A test covers 4 concurrent writers.
- A snapshot is taken before each change, and the last `backup_count` are kept.
- Each credential keeps `history_depth` versions of its username and secrets.

## Known limits

- Python can't guarantee that memory is zeroed. Secrets live in ordinary `str` objects for the
  duration of a call.
- Old snapshots still open with the passphrase that was current when they were taken. Run
  `km backups prune` after changing a compromised passphrase.
- Malware running as your user while the vault is unlocked can read the keychain item. That's
  true of any password manager that auto-unlocks.
