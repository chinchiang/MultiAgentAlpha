"""The execution environment as the workbench's 工具與執行環境 page shows it (GLOSSARY.md: workbench;
docs/adr/0006-local-web-workbench.md): read, never changed here.

Tools: every entry of `tools/versions.lock` against what `scripts/install_tools.py` recorded in the tool
directory's manifest (installed version, signature verification) and whether the runner would find it
(`runner.tool_path`, never PATH). The trivy database: `trivy_db.check`, the same freshness and integrity rule a
review applies (cached while the database file is unchanged, since the check hashes it). Configs: every file
under `config/` and `config/examples/`, checked by `policy.check_config_file`, the check `mara check-config` renders
too: whether its structure is valid and, when it is, the eight policy results. Credentials are reported by environment
variable name and presence only, never by value.

Not pure: it reads the workspace, the tool directory, the trivy database, the environment and the clock (the trivy
database's age), runs `node --version`, and keeps the trivy check and the node version in caches of the module's own.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .. import __version__
from ..config import ModelSpec
from ..invocation import config_provider_mode
from ..policy import check_config_file
from ..tools import pins, trivy_db
from ..tools.csp_eval import node_exe
from ..tools.runner import TOOL_DIMENSIONS, installed_manifest_entry, tool_path, tools_dir
from . import jobs
from .configs import config_files

WORKSPACE_ENV = ("MARA_HOME", "MARA_TOOLS_DIR", "MARA_TRIVY_CACHE_DIR", "MARA_NODE", "MARA_SEMGREP_CONFIG", "MARA_ZIZMOR_ONLINE",
                 "MARA_SUMMARY_KEY", "SSL_CERT_FILE", "SSL_CERT_DIR", "AWS_PROFILE", "AWS_REGION")
DEFAULT_KEY_ENV = {"anthropic": "ANTHROPIC_API_KEY", "gemini": "GEMINI_API_KEY"}  # the providers' own defaults
NODE_MIN_MAJOR = 18

_cache_lock = threading.Lock()
_trivy_cache: dict[tuple[str, int, int, float], dict[str, Any]] = {}
_node_cache: dict[str, str | None] = {}


def _sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def tools(workspace: Path) -> dict[str, Any]:
    lock_path = workspace / pins.LOCK
    lock = pins.read_lock(lock_path)
    tdir = tools_dir()
    rows = []
    for name, spec in pins.locked_tools(lock).items():
        entry = installed_manifest_entry(name)
        kind = str(spec.get("kind", ""))
        installed = (tdir / name).is_dir() if kind == "git" else tool_path(name) is not None
        locked = str(spec.get("version", ""))
        have = str(entry.get("version")) if entry and entry.get("version") is not None else None
        status = pins.install_status(locked, entry, installed=installed)
        rows.append({
            "name": name,
            "role": str(spec.get("role", "scanner")),
            "kind": kind,
            "license": str(spec.get("license", "")),
            "locked_version": locked,
            "installed_version": have,
            "installed": installed,
            "verify_method": str((spec.get("verify") or {}).get("method", "")) if isinstance(spec.get("verify"), dict) else "",
            "signature_verified": bool(entry.get("signature_verified")) if entry else None,
            "installed_at": entry.get("installed_at") if entry else None,
            "dimensions": TOOL_DIMENSIONS.get(name, []),
            "status": status,
        })
    manifest_lock = None
    manifest_path = tdir / "manifest.json"
    if manifest_path.is_file():
        try:
            manifest_lock = json.loads(manifest_path.read_text(encoding="utf-8")).get("lock_sha256")
        except (OSError, ValueError, AttributeError):
            manifest_lock = None
    lock_sha = _sha256(lock_path)
    platform_lock = lock.get("platform") if isinstance(lock.get("platform"), dict) else {}
    return {
        "lock_present": lock_path.is_file(),
        "lock_sha256": lock_sha,
        "manifest_lock_sha256": manifest_lock,
        "lock_matches_manifest": (manifest_lock == lock_sha) if manifest_lock else None,
        "locked_platform": platform_lock,
        "host_platform": {"os": sys.platform, "arch": platform.machine()},
        "tools_dir": str(tdir),
        "rows": rows,
    }


def trivy(cache: Path | None = None) -> dict[str, Any]:
    cache = cache or trivy_db.cache_dir()
    db = trivy_db.db_path(cache)
    limit = trivy_db.max_age_hours()
    try:
        st = db.stat()
    except OSError:
        return {"present": False, "ok": False, "cache_dir": str(cache), "max_age_hours": limit,
                "lines": [f"no database at {db}: run scripts/trivy_db.py download (or import a bundle)"]}
    key = (str(db), st.st_mtime_ns, st.st_size, limit)
    with _cache_lock:
        hit = _trivy_cache.get(key)
    if hit is None or hit.get("_checked_hour") != _hour():
        ok, lines = trivy_db.check(cache, limit)
        hit = {"present": True, "ok": ok, "cache_dir": str(cache), "max_age_hours": limit, "lines": lines, "_checked_hour": _hour()}
        with _cache_lock:
            _trivy_cache.clear()
            _trivy_cache[key] = hit
    return {k: v for k, v in hit.items() if not k.startswith("_")}


def _hour() -> int:
    return int(time.time() // 3600)  # the age verdict is re-evaluated at least hourly even for an unchanged file


def node() -> dict[str, Any]:
    exe = node_exe()
    if not exe:
        return {"path": None, "version": None, "ok": False}
    with _cache_lock:
        known = exe in _node_cache
        version = _node_cache.get(exe)
    if not known:
        try:
            cp = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=10, check=False,
                                encoding="utf-8", errors="replace")
            version = cp.stdout.strip() or None
        except (OSError, subprocess.TimeoutExpired):
            version = None
        with _cache_lock:
            _node_cache[exe] = version
    m = re.match(r"v?(\d+)", version or "")
    return {"path": exe, "version": version, "ok": bool(m and int(m.group(1)) >= NODE_MIN_MAJOR)}


def credential(m: ModelSpec) -> dict[str, Any]:
    """Which credential a model needs and whether it is present: the variable's name, never its value."""
    if m.provider == "mock":
        return {"kind": "none", "env": None, "present": True}
    if m.provider == "bedrock":
        return {"kind": "aws_chain", "env": "AWS_PROFILE",
                "present": bool(os.environ.get("AWS_PROFILE") or os.environ.get("AWS_ACCESS_KEY_ID"))}
    name = m.api_key_env or DEFAULT_KEY_ENV.get(m.provider)
    return {"kind": "env", "env": name, "present": bool(name and os.environ.get(name))}


def configs(workspace: Path) -> list[dict[str, Any]]:
    out = []
    for path in config_files(workspace):
        rel = path.relative_to(workspace).as_posix()
        check = check_config_file(path)  # the check `mara check-config` renders too
        entry: dict[str, Any] = {"path": rel, "name": path.stem, "structure_ok": check.structure_ok, "loadable": check.passed,
                                 "error": " ".join(check.error.split())[:600], "provider_mode": None,
                                 "models": [], "roles": {}, "policies": [], "dimensions": [], "rollout_phase": None}
        cfg = check.config
        if cfg is None:
            out.append(entry)
            continue
        entry.update(
            provider_mode=config_provider_mode(m.provider for m in cfg.models),
            policies=[{"id": r.id, "name": r.name, "passed": r.passed, "reason": r.reason} for r in check.policies],
            roles={"context": cfg.roles.context, "reviewers": list(cfg.roles.reviewers), "skeptic": cfg.roles.skeptic,
                   "redteam": cfg.roles.redteam, "judges": list(cfg.roles.judges)},
            dimensions=list(cfg.dimensions),
            rollout_phase=cfg.rollout.phase,
            models=[{"name": m.name, "family": m.family.value, "provider": m.provider, "model": m.model, "data_residency": m.data_residency,
                     "region": m.region, "weight": m.weight, "endpoint_host": urlparse(m.base_url).hostname if m.base_url else None,
                     "credential": credential(m)} for m in cfg.models],
        )
        out.append(entry)
    return out


def environment(workspace: Path, out_dir: Path) -> dict[str, Any]:
    return {
        "version": __version__,
        "python": {"version": platform.python_version(), "executable": sys.executable},
        "platform": platform.platform(),
        "workspace": str(workspace),
        "out_dir": str(out_dir),
        "env_vars": {name: bool(os.environ.get(name)) for name in WORKSPACE_ENV},
        "tools": tools(workspace),
        "trivy_db": trivy(),
        "node": node(),
        "actions": jobs.available(workspace),
    }
