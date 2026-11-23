"""`python -m mara` runs the CLI, so the package can be run without the installed `mara` entry-point script
(mara.cli.app). `python -m mara` alone starts the workbench, as `mara` does."""
from __future__ import annotations

from .cli import app

if __name__ == "__main__":
    app()
