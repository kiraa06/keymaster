"""Exception hierarchy. Every message is safe to show to the agent (never contains secrets)."""


class KeymasterError(Exception):
    """Base class for all Keymaster errors."""


class VaultNotInitialized(KeymasterError):
    def __init__(self) -> None:
        super().__init__("No vault found. Run `km init` in a terminal to create one.")


class VaultLocked(KeymasterError):
    def __init__(self, extra: str = "") -> None:
        msg = "Vault is locked. Ask the user to run `km unlock` in a terminal"
        msg += " (or call the `unlock_vault` tool, which pops a secure passphrase dialog)."
        super().__init__(msg + (f" {extra}" if extra else ""))


class BadPassphrase(KeymasterError):
    pass


class LockedOut(KeymasterError):
    pass


class VaultCorrupted(KeymasterError):
    pass


class NotFound(KeymasterError):
    pass


class Ambiguous(KeymasterError):
    def __init__(self, ref: str, candidates: list[str]) -> None:
        self.candidates = candidates
        super().__init__(
            f"'{ref}' matches several credentials: {', '.join(candidates)}. "
            "Use the exact name/id, or ask the user which one they mean."
        )


class PolicyDenied(KeymasterError):
    pass


class ValidationError(KeymasterError):
    pass
