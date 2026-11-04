"""A child process whose locale encoding is not UTF-8, for the scripts that read git's output: the Windows code page
(cp950 on the host these bugs were found on), or ASCII on Linux, with the C locale and neither PEP 538 nor PEP 540 to
turn it into UTF-8. git writes UTF-8 whatever the locale, so a script that decodes it in the locale's encoding breaks
there, and only there."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest


def not_utf8_env() -> dict[str, str]:
    """The environment for such a child; skips the test where the host's locale stays UTF-8 even so."""
    env = {**os.environ, "LC_ALL": "C", "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0", "PYTHONIOENCODING": "utf-8"}
    probe = subprocess.run([sys.executable, "-c", "import locale; print(locale.getencoding())"], env=env,
                           capture_output=True, text=True, check=True).stdout.strip()
    if probe.lower().replace("-", "") in ("utf8", "cp65001"):
        pytest.skip(f"this host's locale encoding is {probe} even with LC_ALL=C and PYTHONUTF8=0")
    return env
