"""Replace a file with a finished one, tried again for a moment while Windows refuses it.

Both records the workbench reads while a review runs (the progress record, `mara.progress`, and the records of a
run, a job and the settings, `mara.web.procs.write_json`) are written to a temporary file and moved over the real
one, so a reader sees the old file or the new one, never half of one. Windows refuses that move while another
process holds the target open (a scanner, an indexer) and while another thread of this process is moving over it
at the same moment; an `os.replace` refused so is tried again, and anything else, or a refusal that outlasts the
retries, is raised.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

REPLACE_RETRIES = 10
REPLACE_PAUSE = 0.02  # seconds: about 200 ms in all, longer than another process held the record in any we saw


def replace(tmp: Path, path: Path) -> None:
    """os.replace(tmp, path), tried again for a moment while Windows refuses it with a PermissionError."""
    for _ in range(REPLACE_RETRIES):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            time.sleep(REPLACE_PAUSE)
    os.replace(tmp, path)
