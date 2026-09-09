"""
apply.py

Applies a saved Sysmon config file to the local Sysmon service by shelling
out to sysmon.exe -c <path>.

Sysmon itself only runs on Windows. This app is developed/tested under
WSL/Linux, so:
  - On native Windows (or WSL with Windows interop enabled, which is the
    default in WSL2/WSLg), we try `sysmon.exe`, `sysmon64.exe`, then
    `Sysmon64.exe` on PATH.
  - On Linux without Windows interop, this will fail with a clear message
    rather than a confusing traceback.
"""

import shutil
import subprocess
import sys
from typing import Tuple

CANDIDATE_BINARIES = ["sysmon64.exe", "sysmon.exe", "Sysmon64.exe", "Sysmon.exe"]


def find_sysmon_binary():
    for name in CANDIDATE_BINARIES:
        path = shutil.which(name)
        if path:
            return path
    return None


def apply_config(config_path: str) -> Tuple[bool, str]:
    """Returns (success, message)."""
    binary = find_sysmon_binary()
    if not binary:
        return False, (
            "Could not find sysmon.exe / sysmon64.exe on PATH.\n\n"
            "Sysmon only runs on Windows. If you're testing this app under WSL, "
            "make sure Windows interop is enabled (it is by default on WSL2) and that "
            "the folder containing sysmon64.exe is on your Windows PATH, or place "
            "sysmon64.exe somewhere WSL can see it and add that to PATH inside WSL, e.g.:\n"
            "  export PATH=$PATH:/mnt/c/Tools/Sysmon\n\n"
            "Applying the config also requires Administrator privileges."
        )

    try:
        result = subprocess.run(
            [binary, "-c", config_path],
            capture_output=True, text=True, timeout=30,
        )
    except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
        return False, f"Failed to run {binary}: {exc}"

    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode == 0:
        return True, output or "Sysmon configuration applied successfully."
    return False, (
        f"sysmon exited with code {result.returncode}. This usually means the app "
        "isn't running elevated (Administrator), or the config has an error.\n\n"
        f"{output}"
    )
