# Security policy

Keymaster stores other people's secrets, so security reports get priority.

## Reporting a vulnerability

Please **don't open a public issue**. Instead, either:

- use GitHub's private reporting: **Security → Report a vulnerability** on this repository, or
- email **kiran.p.jose02@gmail.com** with `keymaster security` in the subject.

Include a description, steps to reproduce, and the version (`km version`). You'll get an answer
within a few days. Once a fix ships, you'll be credited in the release notes unless you'd rather
not be.

## Scope

In scope: anything that exposes secret values, weakens the encryption or its integrity checks,
lets the agent get around a policy (`sealed`, `strict`, approvals, the host guard), or forges or
breaks the audit chain without detection.

Out of scope: attacks that need code already running as your user while the vault is unlocked,
and `run_with_credential` output deliberately obfuscated by an agent to slip past the scrubber.
Both are documented limits (see [`docs/DESIGN.md`](docs/DESIGN.md#known-limits)).
