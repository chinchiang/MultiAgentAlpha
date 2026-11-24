"""The organisation's internal names stay out of the repository, which is public: its DNS zone and gateway host, its
internal certificate authorities, the address of its gateway and its approval numbers. The shipped configs carry
placeholders (`llm.corp.example`, `RETENTION-APPROVAL-0001`, `~/.mara/internal-ca.pem`); the real values live in a
config the repository ignores (`config/local/`, INSTALL.md). The names are held here as SHA-256 digests, so that the
check does not itself publish them: a word of a tracked text file, or an IPv4 address in one, whose digest is listed
fails."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from tests.tracked import tracked_files

ROOT = Path(__file__).resolve().parents[1]
WORDS = frozenset({
    "93545bdb2e610b6b46061035ca138f8747ee4497cfa725028d4b87f3603718f8",
    "bd5be91f9b1d4d02804ad1eae8def635968c17853a7beb65fe2b8bcaf26328f8",
    "d350719762a6cd3188b71332875b649c02b0914c361e7e35c4a047411dd2c7db",
})
ADDRESSES = frozenset({"46206bbb647125ac73c2fbf9da90cb6e8fc5137c5061d7829c2cdad5135a0311"})
_WORD = re.compile(r"[A-Za-z]{4,}")
_ADDRESS = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def named(text: str) -> list[str]:
    """How each internal name `text` holds is spelled there, in order, once each."""
    found = [w for w in dict.fromkeys(_WORD.findall(text)) if _digest(w.lower()) in WORDS]
    return found + [a for a in dict.fromkeys(_ADDRESS.findall(text)) if _digest(a) in ADDRESSES]


def test_no_tracked_file_names_the_organisations_internal_infrastructure():
    leaks = {}
    for rel in tracked_files(ROOT):
        try:
            text = (ROOT / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # not text: a font, an image, a signature bundle
        if found := named(text):
            leaks[rel] = found
    assert not leaks, "replace with the placeholders the shipped configs use: " + ", ".join(sorted(leaks))


def test_the_check_sees_a_name_whatever_its_case_and_inside_a_host_name_and_nothing_else():
    """With names of the test's own: the listed digests are swapped for those of two made-up ones."""
    import tests.test_no_internal_names as mod

    words, addresses = mod.WORDS, mod.ADDRESSES
    try:
        mod.WORDS, mod.ADDRESSES = frozenset({_digest("acmecorp")}), frozenset({_digest("192.0.2.7")})
        assert named("base_url: https://llm.hq.AcmeCorp/v1  # at 192.0.2.7") == ["AcmeCorp", "192.0.2.7"]
        assert named("~/.mara/acmecorp-ca.pem and ACMECORP-IT") == ["acmecorp", "ACMECORP"]
        assert named("acmecorporation, acme corp, 192.0.2.70, 1192.0.2.7, 192.0.2.7.1") == []
    finally:
        mod.WORDS, mod.ADDRESSES = words, addresses
