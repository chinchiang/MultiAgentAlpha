"""The facts a new advisory on a hash-locked tool closure needs before it is relocked or given a dated exception.

  .venv/bin/python scripts/advisory_facts.py --lockfile tools/model-eval-requirements.txt langgraph langgraph-sdk

For each package named, at the version the lockfile pins: the advisories osv.dev lists on it and each one's first fix;
the closure's packages that require it outside extras (from PyPI) and whether each accepts the release that fixes them
all; how that release's own requirements differ; its file with the tags of the file the lockfile's hash pins, and that
file's SHA-256. Then either a draft of the lockfile header's hand-applied note, or the dependents that keep a relock from
reaching the fix (the case for a dated exception). Whether MARA's use reaches the vulnerable code is not decided here:
that takes reading the tool's own source. It reads the network (osv.dev, PyPI) unless main() is given another fetch.
Exit 0 with the facts printed, 2 when a package is not pinned in the lockfile.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from collections.abc import Callable
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

OSV_QUERY = "https://api.osv.dev/v1/query"
PYPI = "https://pypi.org/pypi/{name}/{version}/json"
ALLOWED = ("https://api.osv.dev/v1/", "https://pypi.org/pypi/")  # every URL fetch_json opens starts with one of these
LOCK_LINE = re.compile(r"^([A-Za-z0-9_.\-]+)==(\S+) \\$")
LOCK_HASH = re.compile(r"^    --hash=sha256:([0-9a-f]{64})$")

Fetch = Callable[..., dict]


class UsageError(Exception):
    """A request the lockfile cannot answer; nothing has been fetched."""


def fetch_json(url: str, body: dict | None = None) -> dict:
    """GET (or, with a body, POST as JSON) and parse the answer; the network adapter main() uses unless given another.
    Only osv.dev's API and PyPI's JSON API, over https (tools/semgrep-triage.yaml accepts the urlopen on that ground)."""
    if not url.startswith(ALLOWED):
        raise ValueError(f"fetch_json opens only osv.dev and PyPI over https, not {url}")
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="GET" if body is None else "POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "mara-advisory-facts"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def read_lock(path: Path) -> dict[str, tuple[str, str]]:
    """{canonical name: (version, sha256)} of a hash-locked requirements file."""
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line and not line.startswith("#")]
    pins: dict[str, tuple[str, str]] = {}
    for req, digest in zip(lines[::2], lines[1::2], strict=False):
        m, h = LOCK_LINE.match(req), LOCK_HASH.match(digest)
        if m and h:
            pins[canonicalize_name(m.group(1))] = (m.group(2), h.group(1))
    return pins


def _version(text: str) -> Version | None:
    try:
        return Version(text)
    except InvalidVersion:
        return None


def first_fix(vuln: dict, name: str, pinned: Version) -> tuple[str, str] | None:
    """How the affected interval that holds `pinned` ends: ("fixed", the first fixed release) or ("last_affected", the
    last release affected, when the advisory names no fix); a range may list several intervals in turn."""
    for affected in vuln.get("affected", []):
        if canonicalize_name(affected.get("package", {}).get("name", "")) != name:
            continue
        for rng in affected.get("ranges", []):
            introduced: Version | None = None
            for event in rng.get("events", []):
                if "introduced" in event:
                    introduced = Version("0") if event["introduced"] == "0" else _version(event["introduced"])
                elif ("fixed" in event or "last_affected" in event) and introduced is not None:
                    kind = "fixed" if "fixed" in event else "last_affected"
                    end = _version(event[kind])
                    if end is not None and introduced <= pinned and (pinned < end if kind == "fixed" else pinned <= end):
                        return kind, event[kind]
                    introduced = None
    return None


def requirements(info: dict) -> list[tuple[str, Requirement]]:
    """A release's requirements outside extras: (the text PyPI gives, without its marker; the parsed requirement)."""
    out = []
    for text in info.get("requires_dist") or []:
        try:
            req = Requirement(text)
        except InvalidRequirement:
            continue
        if req.marker is None or "extra" not in str(req.marker):
            out.append((text.split(";", 1)[0].strip(), req))
    return out


def _tags(filename: str) -> tuple[str, ...] | None:
    """A wheel's python, abi and platform tags (the last three fields of its name)."""
    return tuple(filename[: -len(".whl")].split("-")[-3:]) if filename.endswith(".whl") else None


def wheel_like(pinned: dict, fixed: dict, digest: str) -> str:
    """The fix's file with the tags of the file the lockfile's hash pins, or why there is none."""
    pinned_file = next((u for u in pinned.get("urls", []) if u.get("digests", {}).get("sha256") == digest), None)
    if pinned_file is None:
        return "the pinned hash matches no file of the pinned release on PyPI"
    tags = _tags(pinned_file["filename"])
    for u in fixed.get("urls", []):
        if (tags is None and u["packagetype"] == "sdist") or (tags is not None and _tags(u["filename"]) == tags):
            return f"{u['filename']}, sha256 {u['digests']['sha256']}"
    return f"none with the tags of {pinned_file['filename']}"


def wheel_phrase(pinned: dict, fixed: dict, digest: str) -> str:
    """How the lockfile header names the hashed file: "its one wheel, <file>" or "its <python-abi-platform> wheel"."""
    wheels = [u["filename"] for u in fixed.get("urls", []) if u["packagetype"] == "bdist_wheel"]
    if len(wheels) == 1:
        return f"its one wheel, {wheels[0]}"
    pinned_file = next((u["filename"] for u in pinned.get("urls", []) if u.get("digests", {}).get("sha256") == digest), "")
    return f"its {'-'.join(_tags(pinned_file) or ('?',))} wheel"


def report(lockfile: Path, packages: list[str], fetch: Fetch) -> list[str]:
    pins = read_lock(lockfile)
    if missing := [p for p in packages if canonicalize_name(p) not in pins]:
        raise UsageError(f"{', '.join(missing)} is not pinned in {lockfile}")
    seen: dict[str, dict] = {}
    uncached = fetch

    def fetch(url: str, body: dict | None = None) -> dict:  # each closure package's release is read once per run
        key = url if body is None else url + json.dumps(body, sort_keys=True)
        if key not in seen:
            seen[key] = uncached(url) if body is None else uncached(url, body)
        return seen[key]

    out: list[str] = []
    for package in packages:
        name = canonicalize_name(package)
        version, digest = pins[name]
        out.append(f"{name} {version} ({lockfile})")
        vulns = fetch(OSV_QUERY, {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}).get("vulns", [])
        if not vulns:
            out.append("  osv.dev lists no advisory on it")
        ends: list[tuple[str, str] | None] = []
        all_ids: list[str] = []
        for vuln in vulns:
            ids = " / ".join([vuln["id"], *sorted(a for a in vuln.get("aliases", []) if a != vuln["id"])])
            all_ids.append(ids)
            end = first_fix(vuln, name, Version(version))
            ends.append(end)
            told = ("no fixed release" if end is None else f"first fixed in {end[1]}" if end[0] == "fixed"
                    else f"affected up to {end[1]}, no fixed release named")
            out.append(f"  {ids}: {vuln.get('summary', '')}; {told}")
        # the release that clears every advisory: the highest named fix, if it is above every last affected release
        fixed = [Version(e[1]) for e in ends if e and e[0] == "fixed"]
        last = [Version(e[1]) for e in ends if e and e[0] == "last_affected"]
        target = max(fixed) if fixed and all(ends) and all(max(fixed) > v for v in last) else None
        if vulns and target is None:
            out.append("  no release named clears every advisory: neither a relock nor a draft can be proposed")
        if target is not None:
            pinned_release = fetch(PYPI.format(name=name, version=version))
            fixed_release = fetch(PYPI.format(name=name, version=target))
            before = {text for text, _ in requirements(pinned_release.get("info", {}))}
            after = {text for text, _ in requirements(fixed_release.get("info", {}))}
            change = " ".join([*(f"- {t}" for t in sorted(before - after)), *(f"+ {t}" for t in sorted(after - before))])
            out.append(f"  requirements of {target} against {version}: {change or 'unchanged'}")
            out.append(f"  wheel of {target} for the pinned platform: {wheel_like(pinned_release, fixed_release, digest)}")
        refusers: list[str] = []
        for other, (other_version, _) in sorted(pins.items()):
            if other == name:
                continue
            info = fetch(PYPI.format(name=other, version=other_version)).get("info", {})
            for text, req in requirements(info):
                if canonicalize_name(req.name) == name:
                    accepts = target is None or req.specifier.contains(target, prereleases=True)
                    if not accepts:
                        refusers.append(f"{other} {other_version}")
                    verdict = "" if target is None else f", {'accepts' if accepts else 'refuses'} {target}"
                    out.append(f"  required by {other} {other_version}: {text}{verdict}")
        if target is not None and refusers:
            out.append(f"  a relock cannot reach {target}: {', '.join(f'{r} refuses it' for r in refusers)}")
        elif target is not None:
            out.append(f"  draft: # - <date>: {name} {version} -> {target} ({', '.join(all_ids)}), the SHA-256 of "
                       f"{wheel_phrase(pinned_release, fixed_release, digest)}")
    return out


def main(argv: list[str] | None = None, fetch: Fetch = fetch_json) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--lockfile", type=Path, required=True, help="a hash-locked closure, e.g. tools/semgrep-requirements.txt")
    ap.add_argument("packages", nargs="+", help="the packages the advisory hits")
    args = ap.parse_args(argv)
    try:
        lines = report(args.lockfile, args.packages, fetch)
    except UsageError as e:
        print(f"advisory_facts: {e}", file=sys.stderr)
        return 2
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
