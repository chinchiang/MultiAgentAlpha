"""Fetch the public labelled corpora for a live calibration run (not committed to this repo).

Each corpus is pinned to the commit of a release tag, so the human-authored labels (file, line, CWE) in its
labels.json keep pointing at the code they were written for: a `git clone --depth 1` of the default branch
drifted with every upstream push, and two calibration runs of "the same" corpus reviewed different code.
The commit is fetched by its id and verified with `git rev-parse HEAD`; an existing checkout at another commit
is refused, never silently reused. Labels must be authored by a human; see calib/README.md.

To move a corpus to a newer release: update its `tag` and `commit` below (`git ls-remote --tags <url> <tag>`,
the peeled `^{}` id for an annotated tag) and re-check its labels.json against the new code.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class Corpus:
    name: str
    url: str
    tag: str
    commit: str  # the commit the tag names (peeled), checked after the fetch


CORPORA = (
    # git ls-remote --tags, 2026-10-12: v20.3.0 is annotated (aa81d67), its commit is f189f52
    Corpus("juice-shop", "https://github.com/juice-shop/juice-shop", "v20.3.0", "f189f521266f42c6bd05884468292000cee852ed"),
    # v2026.4 is a lightweight tag on 872d614
    Corpus("WebGoat", "https://github.com/WebGoat/WebGoat", "v2026.4", "872d6149d4ef29e4929c2f4eda279f7fbedc52e8"),
)


class FetchError(RuntimeError):
    pass


def _git(*args: str, cwd: Path | None = None) -> str:
    r = subprocess.run(["git", "-c", "advice.detachedHead=false", *args], cwd=cwd, capture_output=True, text=True, check=False)
    if r.returncode != 0:
        raise FetchError(f"git {' '.join(args)}: {(r.stderr or r.stdout).strip()[-300:]}")
    return r.stdout.strip()


def head(dest: Path) -> str:
    return _git("rev-parse", "HEAD", cwd=dest)


def fetch(corpus: Corpus, dest: Path) -> str:
    """Check out exactly corpus.commit into dest (a new directory) and return it; an existing dest must
    already be at that commit."""
    if not COMMIT_RE.match(corpus.commit):
        raise FetchError(f"{corpus.name}: pinned commit {corpus.commit!r} is not a full 40-character id")
    if dest.exists():
        have = head(dest) if (dest / ".git").exists() else "not a git checkout"
        if have != corpus.commit:
            raise FetchError(f"{dest} is at {have}, not the pinned {corpus.name} {corpus.tag} ({corpus.commit}); "
                             "move it away and fetch again, or update the pin and the labels together")
        return have
    dest.mkdir(parents=True)
    try:
        _git("init", "-q", cwd=dest)
        _git("remote", "add", "origin", corpus.url, cwd=dest)
        _git("fetch", "-q", "--depth", "1", "origin", corpus.commit, cwd=dest)
        _git("checkout", "-q", "--detach", "FETCH_HEAD", cwd=dest)
        have = head(dest)
    except FetchError:
        import shutil

        shutil.rmtree(dest, ignore_errors=True)  # never leave a half-fetched corpus behind to be reused later
        raise
    if have != corpus.commit:
        raise FetchError(f"{corpus.name}: fetched {have}, expected {corpus.commit}")
    return have


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dest", type=Path, default=ROOT / "calib" / "corpora", help="default: calib/corpora")
    args = ap.parse_args(argv)
    try:
        for c in CORPORA:
            commit = fetch(c, args.dest / c.name)
            print(f"{c.name}: {c.tag} at {commit}")
    except FetchError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    print(f"corpora ready under {args.dest} (add labels.json to each before running mara review)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
