"""Clipboard with auto-clear: the secret goes human-ward without passing through the agent.

Backends: macOS pbcopy/pbpaste, Wayland wl-copy/wl-paste, X11 xclip or xsel.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

from .errors import KeymasterError

_CLEARER = r"""
import hashlib, json, subprocess, sys, time
copy_cmd, paste_cmd = json.loads(sys.argv[2]), json.loads(sys.argv[3])
target = hashlib.sha256(sys.stdin.buffer.read()).digest()
time.sleep(float(sys.argv[1]))
cur = subprocess.run(paste_cmd, capture_output=True).stdout
if hashlib.sha256(cur).digest() == target or hashlib.sha256(cur.rstrip(b"\n")).digest() == target:
    subprocess.run(copy_cmd, input=b"")
"""


def _backend() -> tuple[list[str], list[str]]:
    if sys.platform == "darwin" and shutil.which("pbcopy"):
        return ["pbcopy"], ["pbpaste"]
    if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-copy"):
        return ["wl-copy"], ["wl-paste", "--no-newline"]
    if shutil.which("xclip"):
        return ["xclip", "-selection", "clipboard", "-in"], ["xclip", "-selection", "clipboard", "-out"]
    if shutil.which("xsel"):
        return ["xsel", "--clipboard", "--input"], ["xsel", "--clipboard", "--output"]
    raise KeymasterError("No clipboard tool found (need pbcopy on macOS, or wl-clipboard / xclip / xsel on Linux).")


def copy(value: str, clear_after: int) -> None:
    copy_cmd, paste_cmd = _backend()
    subprocess.run(copy_cmd, input=value.encode(), check=True)
    if clear_after > 0:
        p = subprocess.Popen(
            [sys.executable, "-c", _CLEARER, str(clear_after), json.dumps(copy_cmd), json.dumps(paste_cmd)],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        assert p.stdin is not None
        p.stdin.write(value.encode())
        p.stdin.close()


def paste() -> str:
    _, paste_cmd = _backend()
    return subprocess.run(paste_cmd, capture_output=True, check=True).stdout.decode()


def clear() -> None:
    copy_cmd, _ = _backend()
    subprocess.run(copy_cmd, input=b"", check=True)
