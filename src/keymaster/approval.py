"""Human-in-the-loop approvals and secure input, out-of-band from the agent.

The agent never sees what the human types here: dialogs run in a separate process
(osascript / a tiny Touch ID helper) and only the *decision* flows back.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .errors import KeymasterError

DIALOG_TIMEOUT = 90


@dataclass
class Request:
    title: str
    message: str
    allow_grant: bool = True
    grant_minutes: int = 480


@dataclass
class Decision:
    allowed: bool
    grant: bool = False
    method: str = ""
    note: str = ""


class Approver(Protocol):
    def approve(self, req: Request) -> Decision: ...
    def ask_secret(self, title: str, message: str) -> str | None: ...


NO_DIALOG = (
    "No way to show a secure dialog here (needs macOS, or Linux with zenity and a desktop session). "
    "On headless machines run `km config set approval deny` and use policy `open`/`sealed`."
)


def _backend() -> str:
    if sys.platform == "darwin" and shutil.which("osascript"):
        return "osascript"
    if shutil.which("zenity") and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return "zenity"
    raise KeymasterError(NO_DIALOG)


def _osascript(script: str, *args: str, timeout: int = DIALOG_TIMEOUT + 30) -> subprocess.CompletedProcess:
    return subprocess.run(["osascript", "-e", script, *args], capture_output=True, text=True, timeout=timeout)


_APPROVE_SCRIPT = f"""
on run argv
  activate
  set btns to {{"Deny", "Allow once"}}
  if (count of argv) > 2 then set end of btns to (item 3 of argv)
  set r to display dialog (item 2 of argv) with title (item 1 of argv) buttons btns ¬
    default button "Deny" cancel button "Deny" with icon caution giving up after {DIALOG_TIMEOUT}
  if gave up of r then return "timeout"
  return button returned of r
end run
"""

_SECRET_SCRIPT = """
on run argv
  activate
  set r to display dialog (item 2 of argv) with title (item 1 of argv) default answer "" ¬
    with hidden answer buttons {"Cancel", "OK"} default button "OK" cancel button "Cancel" ¬
    with icon note giving up after 300
  if gave up of r then return "TIMEOUT"
  return "OK:" & (text returned of r)
end run
"""

_NOTIFY_SCRIPT = """
on run argv
  display notification (item 2 of argv) with title (item 1 of argv) sound name "Glass"
end run
"""


def notify(title: str, message: str) -> None:
    """Fire-and-forget macOS notification; never raises."""
    try:
        if sys.platform == "darwin":
            cmd = ["osascript", "-e", _NOTIFY_SCRIPT, title, message]
        elif shutil.which("notify-send"):
            cmd = ["notify-send", "--app-name=Keymaster", title, message]
        else:
            return
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    except Exception:
        pass


def dialog_ask_secret(title: str, message: str) -> str | None:
    if _backend() == "zenity":
        try:
            r = subprocess.run(
                ["zenity", "--entry", "--hide-text", f"--title={title}", f"--text={message}", "--timeout=300"],
                capture_output=True,
                text=True,
                timeout=330,
            )
        except subprocess.TimeoutExpired:
            return None
        out = r.stdout[:-1] if r.stdout.endswith("\n") else r.stdout
        return out if r.returncode == 0 and out else None
    try:
        r = _osascript(_SECRET_SCRIPT, title, message, timeout=330)
    except subprocess.TimeoutExpired:
        return None
    if r.returncode != 0:
        return None  # cancelled
    out = r.stdout[:-1] if r.stdout.endswith("\n") else r.stdout
    if not out.startswith("OK:"):
        return None
    return out[3:] or None


class DialogApprover:
    method = "dialog"

    def approve(self, req: Request) -> Decision:
        grant_label = f"Allow for {_fmt_minutes(req.grant_minutes)}"
        if _backend() == "zenity":
            return self._zenity(req, grant_label)
        args = [req.title, req.message] + ([grant_label] if req.allow_grant else [])
        try:
            r = _osascript(_APPROVE_SCRIPT, *args)
        except subprocess.TimeoutExpired:
            return Decision(False, method=self.method, note="dialog timed out")
        if r.returncode != 0:
            return Decision(False, method=self.method, note="denied by user")
        choice = r.stdout.strip()
        if choice == "timeout":
            return Decision(False, method=self.method, note="no answer within 90s")
        if choice == "Allow once":
            return Decision(True, method=self.method)
        if choice == grant_label:
            return Decision(True, grant=True, method=self.method)
        return Decision(False, method=self.method, note="denied by user")

    def _zenity(self, req: Request, grant_label: str) -> Decision:
        cmd = [
            "zenity",
            "--question",
            f"--title={req.title}",
            f"--text={req.message}",
            "--ok-label=Allow once",
            "--cancel-label=Deny",
            f"--timeout={DIALOG_TIMEOUT}",
            "--icon-name=dialog-warning",
        ]
        if req.allow_grant:
            cmd.append(f"--extra-button={grant_label}")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=DIALOG_TIMEOUT + 30)
        except subprocess.TimeoutExpired:
            return Decision(False, method=self.method, note="dialog timed out")
        if r.returncode == 0:
            return Decision(True, method=self.method)
        if req.allow_grant and r.stdout.strip() == grant_label:
            return Decision(True, grant=True, method=self.method)
        note = "no answer within 90s" if r.returncode == 5 else "denied by user"
        return Decision(False, method=self.method, note=note)

    def ask_secret(self, title: str, message: str) -> str | None:
        return dialog_ask_secret(title, message)


TOUCHID_SWIFT = r"""
import Foundation
import LocalAuthentication

let args = CommandLine.arguments
let ctx = LAContext()
var err: NSError?
guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) else {
    FileHandle.standardError.write("unavailable: \(err?.localizedDescription ?? "unknown")\n".data(using: .utf8)!)
    exit(2)
}
if args.count > 1 && args[1] == "--check" { exit(0) }
let reason = args.count > 1 ? args[1] : "unlock a Keymaster credential"
let done = DispatchSemaphore(value: 0)
var ok = false
ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, e in
    ok = success
    if !success { FileHandle.standardError.write("\(e?.localizedDescription ?? "denied")\n".data(using: .utf8)!) }
    done.signal()
}
_ = done.wait(timeout: .now() + 120)
exit(ok ? 0 : 1)
"""


def touchid_binary(bin_dir: Path) -> Path:
    return bin_dir / "km-touchid"


def build_touchid(bin_dir: Path) -> Path:
    swiftc = shutil.which("swiftc")
    if not swiftc:
        raise KeymasterError("swiftc not found — install Xcode Command Line Tools (xcode-select --install).")
    bin_dir.mkdir(parents=True, exist_ok=True)
    src = bin_dir / "km-touchid.swift"
    src.write_text(TOUCHID_SWIFT)
    out = touchid_binary(bin_dir)
    r = subprocess.run([swiftc, "-O", "-o", str(out), str(src)], capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        raise KeymasterError(f"Touch ID helper failed to compile:\n{r.stderr[-2000:]}")
    os.chmod(out, 0o700)
    return out


class TouchIDApprover:
    method = "touchid"

    def __init__(self, bin_dir: Path) -> None:
        self.binary = touchid_binary(bin_dir)

    def approve(self, req: Request) -> Decision:
        if not self.binary.exists():
            return DialogApprover().approve(req)  # graceful fallback
        # Touch ID's sheet reads "<process> is trying to <reason>"; keep it short and specific.
        reason = req.message.split("\n", 1)[0][:150]
        try:
            r = subprocess.run([str(self.binary), reason], capture_output=True, text=True, timeout=150)
        except subprocess.TimeoutExpired:
            return Decision(False, method=self.method, note="Touch ID timed out")
        if r.returncode == 2:
            return DialogApprover().approve(req)
        ok = r.returncode == 0
        return Decision(
            ok, grant=ok and req.allow_grant, method=self.method, note="" if ok else (r.stderr.strip() or "denied")
        )

    def ask_secret(self, title: str, message: str) -> str | None:
        return dialog_ask_secret(title, message)


class DenyApprover:
    method = "deny"

    def approve(self, req: Request) -> Decision:
        return Decision(False, method=self.method, note="approvals disabled (approval=deny)")

    def ask_secret(self, title: str, message: str) -> str | None:
        return None


class StaticApprover:
    """Tests: approve/deny deterministically, and answer secret prompts from a queue."""

    method = "static"

    def __init__(self, allow: bool = True, grant: bool = False, secrets: list[str] | None = None) -> None:
        self.allow, self.grant, self.secrets = allow, grant, list(secrets or [])
        self.requests: list[Request] = []

    def approve(self, req: Request) -> Decision:
        self.requests.append(req)
        return Decision(self.allow, grant=self.grant and req.allow_grant, method=self.method)

    def ask_secret(self, title: str, message: str) -> str | None:
        return self.secrets.pop(0) if self.secrets else None


def from_config(method: str, bin_dir: Path) -> Approver:
    if method == "touchid":
        return TouchIDApprover(bin_dir)
    if method == "deny":
        return DenyApprover()
    return DialogApprover()


def _fmt_minutes(m: int) -> str:
    if m % 60 == 0:
        return f"{m // 60}h"
    return f"{m}m"
