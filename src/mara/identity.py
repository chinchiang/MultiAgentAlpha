"""Finding identity: which file, which place, which finding - one rule for every module that matches or keys findings.

Path normalisation, the "same place" rule and the keys derived from them used to be re-implemented in seven places
with different rules: one module stripped every leading `./`, another only the first, a third used `str.lstrip("./")`
(which also eats the dot of `.github` and merges `../x` with `x`), and the provenance check did not normalise at all.
"""

from __future__ import annotations

import hashlib

NEAR_LINES = 3  # a finding and a tool result, two findings, or a finding and a label within this many lines are one place


def norm_path(path: str) -> str:
    """Forward slashes and no leading `./` (any number of them); nothing else changes, so `.github/x` and `../x` stay."""
    path = str(path).replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def norm_cwe(cwe: str) -> str:
    return str(cwe).strip().upper()


def same_place(file_a: str, line_a: int, cwe_a: str, file_b: str, line_b: int, cwe_b: str) -> bool:
    """One file, one CWE, and lines at most NEAR_LINES apart."""
    return (norm_path(file_a) == norm_path(file_b) and norm_cwe(cwe_a) == norm_cwe(cwe_b)
            and abs(int(line_a) - int(line_b)) <= NEAR_LINES)


def quote_digest(quote: str) -> str:
    """The whitespace-normalised evidence quote, hashed: what identifies a finding when its line moves."""
    return hashlib.sha256(" ".join(str(quote).split()).encode()).hexdigest()[:16]
