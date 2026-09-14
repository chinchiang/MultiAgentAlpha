"""G-7: an ML-BOM (CycloneDX 1.6) for the self-hosted model weights.

The pipeline calls self-hosted DeepSeek and Nemotron endpoints; the weights those endpoints serve
are supply-chain inputs like any other dependency. This module builds and checks a CycloneDX 1.6
BOM in which every self-hosted model is a `machine-learning-model` component carrying its source,
licence, per-file SHA-256 hashes (safetensors only, pickle formats are refused) and a component-level
digest, so the platform team can verify a weights directory against the BOM and sign the BOM with
cosign. Policy P7 and governance check G-7 read the same BOM; nothing here touches the network.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import MaraConfig

SPEC_VERSION = "1.6"
SCHEMA_DIR = Path(__file__).parent / "groundtruth" / "cyclonedx"
SCHEMA_FILES = ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json")
PICKLE_SUFFIXES = frozenset({".bin", ".pt", ".pth", ".pkl", ".pickle", ".ckpt"})
WEIGHT_SUFFIX = ".safetensors"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PROP = "mara:"
MARA_REF = "mara"
STATUS_COMPLETE, STATUS_PENDING, STATUS_INCOMPLETE, STATUS_ABSENT, STATUS_NO_BOM = "complete", "pending", "incomplete", "absent", "no-bom"
HF_HOST = "huggingface.co"
HF_TOKEN_ENV = "HF_TOKEN"
NON_LFS_MAX_BYTES = 50 * 1024 * 1024   # files stored in git rather than LFS are fetched and hashed; weights never are
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
Fetch = Callable[[str], tuple[bytes, dict]]


class PickleWeightsError(ValueError):
    """A weights directory contains a pickle-based checkpoint; only safetensors may be loaded (G-7)."""


@dataclass(frozen=True)
class FileEntry:
    path: str
    sha256: str
    size: int


@dataclass
class ModelEntry:
    model_id: str
    family: str
    name: str
    version: str
    source: dict = field(default_factory=dict)        # kind (huggingface | ngc | github), url, revision
    license: dict = field(default_factory=dict)       # id (SPDX) or name, url
    format: str = "safetensors"
    serving: str = ""                                  # vllm | nim
    architecture: dict = field(default_factory=dict)  # family, name
    signature: dict = field(default_factory=dict)     # method (cosign-keyless | ngc | none), identity, issuer, bundle
    files: list[FileEntry] = field(default_factory=list)
    note: str = ""

    @property
    def pending(self) -> bool:
        return not self.files

    @property
    def bom_ref(self) -> str:
        return f"model:{self.model_id}"


@dataclass(frozen=True)
class ModelStatus:
    model_name: str
    model_id: str
    status: str
    problems: tuple[str, ...] = ()
    component_name: str = ""
    component_version: str = ""
    digest: str = ""


# ---------------------------------------------------------------- hashing

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_dir(directory: Path | str) -> list[FileEntry]:
    """Hash every file under a weights directory. Refuses pickle-based checkpoints and requires at
    least one safetensors file, because only safetensors may be loaded (report Part VI, G-7)."""
    root = Path(directory)
    if not root.is_dir():
        raise FileNotFoundError(f"weights directory {root} does not exist")
    files = sorted(p for p in root.rglob("*") if p.is_file())
    pickles = [str(p.relative_to(root)) for p in files if p.suffix.lower() in PICKLE_SUFFIXES]
    if pickles:
        raise PickleWeightsError(f"pickle-based checkpoint(s) refused: {', '.join(pickles)}; convert to safetensors first")
    if not any(p.suffix.lower() == WEIGHT_SUFFIX for p in files):
        raise ValueError(f"no {WEIGHT_SUFFIX} file under {root}")
    return [FileEntry(str(p.relative_to(root)).replace(os.sep, "/"), sha256_file(p), p.stat().st_size) for p in files]


def manifest_digest(files: list[FileEntry]) -> str:
    """Component-level SHA-256: the digest of the sorted `sha256  path` lines (sha256sum format)."""
    lines = sorted(f"{f.sha256}  {f.path}" for f in files)
    return hashlib.sha256(("\n".join(lines) + "\n").encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- manifest (sbom/models.yaml)

def load_manifest(path: Path | str) -> list[ModelEntry]:
    import yaml

    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    entries = []
    for m in raw.get("models", []) or []:
        files = [FileEntry(str(f["path"]), str(f["sha256"]).lower(), int(f.get("size", 0))) for f in (m.get("files") or [])]
        for f in files:
            if not SHA256_RE.match(f.sha256):
                raise ValueError(f"{m.get('model_id')}: {f.path} has no valid sha256 ({f.sha256!r})")
        entries.append(ModelEntry(
            model_id=str(m["model_id"]), family=str(m.get("family", "")), name=str(m.get("name", m["model_id"])),
            version=str(m.get("version", "")), source=dict(m.get("source") or {}), license=dict(m.get("license") or {}),
            format=str(m.get("format", "safetensors")), serving=str(m.get("serving", "")),
            architecture=dict(m.get("architecture") or {}), signature=dict(m.get("signature") or {}),
            files=files, note=str(m.get("note", "")),
        ))
    ids = [e.model_id for e in entries]
    if len(ids) != len(set(ids)):
        raise ValueError(f"duplicate model_id in manifest: {sorted({i for i in ids if ids.count(i) > 1})}")
    return entries


def write_manifest_files(path: Path | str, model_id: str, files: list[FileEntry]) -> None:
    """Write hashed files back into the manifest entry for model_id (keeps everything else)."""
    import yaml

    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    for m in raw.get("models", []) or []:
        if m.get("model_id") == model_id:
            m["files"] = [{"path": f.path, "sha256": f.sha256, "size": f.size} for f in files]
            break
    else:
        raise KeyError(f"model_id {model_id!r} not in {p}")
    p.write_text(yaml.safe_dump(raw, sort_keys=False, allow_unicode=True, width=120), encoding="utf-8")


def write_manifest_source_revision(path: Path | str, model_id: str, revision: str) -> None:
    """Pin the exact commit the hashes were taken from into the manifest entry's source.revision."""
    import yaml

    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    for m in raw.get("models", []) or []:
        if m.get("model_id") == model_id:
            m.setdefault("source", {})["revision"] = revision
            break
    else:
        raise KeyError(f"model_id {model_id!r} not in {p}")
    p.write_text(yaml.safe_dump(raw, sort_keys=False, allow_unicode=True, width=120), encoding="utf-8")


# ---------------------------------------------------------------- registry hashes (Hugging Face)

def hf_repo_from_url(url: str) -> str:
    """'https://huggingface.co/<org>/<name>[/...]' -> '<org>/<name>'. Any other host is refused: the
    manifest's source must be the official Hugging Face repository, not a mirror."""
    u = urllib.parse.urlparse(url)
    if u.scheme != "https" or u.netloc.lower() != HF_HOST:
        raise ValueError(f"source url {url!r} is not on https://{HF_HOST}; registry hashes are taken from the official repository only")
    parts = [x for x in u.path.split("/") if x]
    if len(parts) < 2:
        raise ValueError(f"source url {url!r} does not name a repository (expected https://{HF_HOST}/<org>/<name>)")
    return f"{parts[0]}/{parts[1]}"


def _http_fetch(url: str, timeout: int = 60) -> tuple[bytes, dict]:
    headers = {"User-Agent": "mara-ml-bom/1"}
    token = os.environ.get(HF_TOKEN_ENV)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout) as r:
            return r.read(), {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        raise ValueError(f"{url}: HTTP {e.code} ({'set ' + HF_TOKEN_ENV + ' for a gated repository' if e.code in (401, 403) else e.reason})") from e
    except urllib.error.URLError as e:
        raise ValueError(f"{url}: {e.reason}") from e


def _next_link(headers: dict) -> str | None:
    for part in str(headers.get("link", "")).split(","):
        if 'rel="next"' in part:
            return part.split(";")[0].strip().strip("<>")
    return None


def registry_files(repo: str, revision: str = "main", fetch: Fetch | None = None) -> tuple[str, list[FileEntry]]:
    """(commit sha, files) for a Hugging Face repository at `revision`, without downloading the weights.

    The revision is resolved to its commit through /api/models/<repo>/revision/<rev>; every file in the
    tree at that commit is listed (paginated) and LFS-stored files (the weights) contribute the SHA-256
    Hugging Face already holds as the LFS object id, byte-identical to what `hash-dir` computes on a
    download. Files stored in plain git (config.json, tokenizer files) carry no SHA-256 in the API, so
    they are fetched (small, capped at NON_LFS_MAX_BYTES) and hashed here. The same rules as hash_dir
    apply: pickle checkpoints are refused and at least one safetensors file is required."""
    fetch = fetch or _http_fetch
    base = f"https://{HF_HOST}"
    info_raw, _ = fetch(f"{base}/api/models/{repo}/revision/{urllib.parse.quote(revision, safe='')}")
    info = json.loads(info_raw)
    commit = str(info.get("sha", ""))
    if not COMMIT_RE.match(commit):
        raise ValueError(f"{repo}@{revision}: the registry returned no commit sha ({commit!r})")
    url: str | None = f"{base}/api/models/{repo}/tree/{commit}?recursive=true&expand=false"
    entries: list[dict] = []
    while url:
        body, headers = fetch(url)
        page = json.loads(body)
        if not isinstance(page, list):
            raise ValueError(f"{repo}@{commit[:12]}: unexpected tree listing {str(page)[:120]!r}")
        entries.extend(page)
        url = _next_link(headers)
    paths = [str(e["path"]) for e in entries if e.get("type") == "file"]
    pickles = [p for p in paths if Path(p).suffix.lower() in PICKLE_SUFFIXES]
    if pickles:
        raise PickleWeightsError(f"pickle-based checkpoint(s) refused: {', '.join(sorted(pickles))}; the repository must be served as safetensors")
    if not any(p.lower().endswith(WEIGHT_SUFFIX) for p in paths):
        raise ValueError(f"{repo}@{commit[:12]}: no {WEIGHT_SUFFIX} file in the repository tree")
    files = []
    for e in sorted((e for e in entries if e.get("type") == "file"), key=lambda e: str(e["path"])):
        path = str(e["path"])
        lfs = e.get("lfs")
        if lfs:
            oid = str(lfs.get("oid", "")).lower()
            if not SHA256_RE.match(oid):
                raise ValueError(f"{path}: LFS object id {oid!r} is not a SHA-256")
            files.append(FileEntry(path, oid, int(lfs.get("size", e.get("size", 0)) or 0)))
            continue
        size = int(e.get("size", 0) or 0)
        if size > NON_LFS_MAX_BYTES:
            raise ValueError(f"{path}: {size} bytes stored outside LFS exceeds the {NON_LFS_MAX_BYTES} byte cap for fetching; "
                             "hash it with hash-dir instead")
        blob, _ = fetch(f"{base}/{repo}/resolve/{commit}/{urllib.parse.quote(path)}")
        files.append(FileEntry(path, hashlib.sha256(blob).hexdigest(), len(blob)))
    return commit, files


# ---------------------------------------------------------------- BOM

def _prop(name: str, value: str) -> dict:
    return {"name": PROP + name, "value": str(value)}


def _license(lic: dict) -> list[dict]:
    if not lic:
        return []
    inner: dict = {}
    if lic.get("id"):
        inner["id"] = str(lic["id"])
    elif lic.get("name"):
        inner["name"] = str(lic["name"])
    else:
        return []
    if lic.get("url"):
        inner["url"] = str(lic["url"])
    return [{"license": inner}]


def build_component(e: ModelEntry, *, allow_pending: bool) -> dict:
    if e.pending and not allow_pending:
        raise ValueError(f"{e.model_id}: no file hashes (pending); hash the weights with `ml_bom.py hash-dir` or pass --allow-pending")
    if e.format != "safetensors":
        raise ValueError(f"{e.model_id}: format must be safetensors (got {e.format!r})")
    bad = [f.path for f in e.files if Path(f.path).suffix.lower() in PICKLE_SUFFIXES]
    if bad:
        raise PickleWeightsError(f"{e.model_id}: pickle-based files listed: {', '.join(bad)}")
    comp: dict = {"type": "machine-learning-model", "bom-ref": e.bom_ref, "name": e.name, "version": e.version}
    if e.license:
        comp["licenses"] = _license(e.license)
    if e.files:
        comp["hashes"] = [{"alg": "SHA-256", "content": manifest_digest(e.files)}]
    refs = []
    if e.source.get("url"):
        comment = " ".join(x for x in (str(e.source.get("kind", "")), f"revision {e.source['revision']}" if e.source.get("revision") else "") if x)
        ref = {"type": "distribution", "url": str(e.source["url"])}
        if comment:
            ref["comment"] = comment
        refs.append(ref)
    if e.source.get("vcs"):
        refs.append({"type": "vcs", "url": str(e.source["vcs"])})
    if e.license.get("url"):
        refs.append({"type": "license", "url": str(e.license["url"])})
    if refs:
        comp["externalReferences"] = refs
    if e.architecture:
        params = {}
        if e.architecture.get("family"):
            params["architectureFamily"] = str(e.architecture["family"])
        if e.architecture.get("name"):
            params["modelArchitecture"] = str(e.architecture["name"])
        if params:
            comp["modelCard"] = {"modelParameters": params}
    sig = e.signature or {}
    comp["properties"] = [
        _prop("model-id", e.model_id), _prop("family", e.family), _prop("format", e.format),
        _prop("serving", e.serving or "unknown"), _prop("signature", sig.get("method") or "none"),
        _prop("status", STATUS_PENDING if e.pending else STATUS_COMPLETE), _prop("file-count", str(len(e.files))),
    ]
    for k in ("identity", "issuer", "bundle"):
        if sig.get(k):
            comp["properties"].append(_prop(f"signature-{k}", str(sig[k])))
    if e.note:
        comp["properties"].append(_prop("note", e.note))
    if e.files:
        comp["components"] = [
            {"type": "file", "bom-ref": f"{e.bom_ref}/{f.path}", "name": f.path,
             "hashes": [{"alg": "SHA-256", "content": f.sha256}], "properties": [_prop("size", str(f.size))]}
            for f in e.files
        ]
    return comp


def build_bom(entries: list[ModelEntry], *, allow_pending: bool = False, timestamp: str | None = None,
              serial: str | None = None, tool_version: str = "0.1.0") -> dict:
    comps = [build_component(e, allow_pending=allow_pending) for e in entries]
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp or dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "tools": {"components": [{"type": "application", "name": "mara", "version": tool_version,
                                      "description": "scripts/ml_bom.py (governance item G-7)"}]},
            "component": {"type": "application", "bom-ref": MARA_REF, "name": "mara", "version": tool_version,
                          "description": "Multi-Agent Review Architecture; the self-hosted models below are its inference dependencies"},
            "properties": [_prop("bom-kind", "ML-BOM"), _prop("weights-format-policy", "safetensors-only")],
        },
        "components": comps,
        "dependencies": [{"ref": MARA_REF, "dependsOn": [c["bom-ref"] for c in comps]}] + [{"ref": c["bom-ref"], "dependsOn": []} for c in comps],
    }


def load_bom(path: Path | str) -> dict:
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    if d.get("bomFormat") != "CycloneDX":
        raise ValueError(f"{path}: not a CycloneDX BOM")
    return d


def props(component: dict) -> dict[str, str]:
    return {p["name"][len(PROP):]: str(p.get("value", "")) for p in component.get("properties", []) if str(p.get("name", "")).startswith(PROP)}


def ml_components(bom: dict) -> dict[str, dict]:
    """model_id -> machine-learning-model component (keyed by the mara:model-id property, else the name)."""
    out = {}
    for c in bom.get("components", []):
        if c.get("type") == "machine-learning-model":
            out[props(c).get("model-id") or c.get("name", "")] = c
    return out


def component_problems(c: dict) -> list[str]:
    """Why a machine-learning-model component does not satisfy G-7. Empty means complete."""
    pr = props(c)
    problems = []
    if pr.get("status") == STATUS_PENDING:
        problems.append("status pending (weights not yet hashed)")
    hashes = [h for h in c.get("hashes", []) if h.get("alg") == "SHA-256" and SHA256_RE.match(str(h.get("content", "")))]
    if not hashes:
        problems.append("no SHA-256 hash")
    files = [x for x in c.get("components", []) if x.get("type") == "file"]
    if hashes and not files:
        problems.append("no per-file hashes")
    for f in files:
        if Path(f.get("name", "")).suffix.lower() in PICKLE_SUFFIXES:
            problems.append(f"pickle-based file listed: {f.get('name')}")
        if not any(SHA256_RE.match(str(h.get("content", ""))) for h in f.get("hashes", []) if h.get("alg") == "SHA-256"):
            problems.append(f"file without SHA-256: {f.get('name')}")
    if files and not any(str(f.get("name", "")).lower().endswith(WEIGHT_SUFFIX) for f in files):
        problems.append("no safetensors file among the hashed files")
    if pr.get("format", "safetensors") != "safetensors":
        problems.append(f"format {pr.get('format')!r} is not safetensors")
    if not c.get("licenses"):
        problems.append("no licence")
    if not any(r.get("type") == "distribution" and r.get("url") for r in c.get("externalReferences", [])):
        problems.append("no distribution source (externalReferences type distribution)")
    if pr.get("signature", "none") == "none":
        problems.append("no signature method (cosign-keyless or ngc)")
    return problems


def verify_dir(bom: dict, model_id: str, directory: Path | str) -> list[str]:
    """Re-hash a weights directory and compare it with the component's per-file hashes and digest."""
    comp = ml_components(bom).get(model_id)
    if comp is None:
        return [f"model_id {model_id!r} has no component in the BOM"]
    expected = {f["name"]: next((h["content"] for h in f.get("hashes", []) if h.get("alg") == "SHA-256"), "")
                for f in comp.get("components", []) if f.get("type") == "file"}
    if not expected:
        return [f"{model_id}: component has no per-file hashes to verify against"]
    actual = {f.path: f.sha256 for f in hash_dir(directory)}
    problems = [f"missing on disk: {p}" for p in sorted(set(expected) - set(actual))]
    problems += [f"not in BOM: {p}" for p in sorted(set(actual) - set(expected))]
    problems += [f"hash mismatch: {p}" for p in sorted(set(expected) & set(actual)) if expected[p] != actual[p]]
    digest = next((h["content"] for h in comp.get("hashes", []) if h.get("alg") == "SHA-256"), "")
    recomputed = manifest_digest([FileEntry(p, s, 0) for p, s in expected.items()])
    if digest != recomputed:
        problems.append(f"component digest {digest[:12]} does not match its own file list ({recomputed[:12]})")
    return problems


def bom_equal_ignoring_volatile(a: dict, b: dict) -> bool:
    def strip(d: dict) -> dict:
        d = json.loads(json.dumps(d))
        d.pop("serialNumber", None)
        d.get("metadata", {}).pop("timestamp", None)
        return d
    return strip(a) == strip(b)


def validate_schema(bom: dict) -> list[str]:
    """Validate against the vendored CycloneDX 1.6 JSON schema. Returns error messages (empty = valid)."""
    try:
        from jsonschema import Draft7Validator
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT7
    except ImportError as e:  # pragma: no cover - dev dependency
        raise ImportError("jsonschema is required for schema validation: pip install -e '.[dev]'") from e
    docs = {name: json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8")) for name in SCHEMA_FILES}
    resources = []
    for name, doc in docs.items():
        res = Resource.from_contents(doc, default_specification=DRAFT7)
        resources.append((name, res))
        resources.append((f"http://cyclonedx.org/schema/{name}", res))
        if doc.get("$id"):
            resources.append((doc["$id"], res))
    registry = Registry().with_resources(resources)
    validator = Draft7Validator(docs["bom-1.6.schema.json"], registry=registry)
    errors = sorted(validator.iter_errors(bom), key=lambda e: list(e.path))
    return [f"{'/'.join(str(x) for x in e.path) or '<root>'}: {e.message[:160]}" for e in errors]


# ---------------------------------------------------------------- cosign

def tools_bin(tools_dir: Path | str | None = None) -> Path:
    from .tools.runner import tools_dir as _td

    return (Path(tools_dir) if tools_dir else _td()) / "bin"


def cosign_verify_blob_cmd(bom_path: Path | str, bundle: Path | str, identity: str, issuer: str,
                           tools_dir: Path | str | None = None) -> list[str]:
    """Command line for the locked cosign (tools/versions.lock) to verify the BOM's keyless signature."""
    exe = tools_bin(tools_dir) / "cosign"
    if not exe.exists():
        raise FileNotFoundError(f"{exe} not installed; run scripts/install_tools.py")
    if not identity or not issuer:
        raise ValueError("certificate identity and OIDC issuer are required for keyless verification")
    return [str(exe), "verify-blob", "--bundle", str(bundle), "--certificate-identity", identity,
            "--certificate-oidc-issuer", issuer, str(bom_path)]


def cosign_sign_blob_cmd(bom_path: Path | str, bundle: Path | str, tools_dir: Path | str | None = None) -> list[str]:
    exe = tools_bin(tools_dir) / "cosign"
    return [str(exe), "sign-blob", "--bundle", str(bundle), str(bom_path)]


# ---------------------------------------------------------------- config view (policy P7, pipeline, governance)

def self_hosted_models(cfg: MaraConfig) -> list:
    return [m for m in cfg.models if m.provider == "openai_compatible"]


def status_for_config(cfg: MaraConfig, root: Path | str | None = None) -> dict[str, ModelStatus]:
    """One ModelStatus per self-hosted model in the config, read from cfg.ml_bom.path."""
    base = Path(root) if root else Path.cwd()
    bom_path = Path(cfg.ml_bom.path)
    if not bom_path.is_absolute():
        bom_path = base / bom_path
    comps: dict[str, dict] | None
    try:
        comps = ml_components(load_bom(bom_path))
    except (OSError, ValueError):
        comps = None
    out = {}
    for m in self_hosted_models(cfg):
        if comps is None:
            out[m.name] = ModelStatus(m.name, m.model, STATUS_NO_BOM, (f"{bom_path} missing or unreadable",))
            continue
        c = comps.get(m.model)
        if c is None:
            out[m.name] = ModelStatus(m.name, m.model, STATUS_ABSENT, (f"no machine-learning-model component with mara:model-id {m.model!r}",))
            continue
        pr = component_problems(c)
        digest = next((h["content"] for h in c.get("hashes", []) if h.get("alg") == "SHA-256"), "")
        status = STATUS_COMPLETE if not pr else (STATUS_PENDING if props(c).get("status") == STATUS_PENDING else STATUS_INCOMPLETE)
        out[m.name] = ModelStatus(m.name, m.model, status, tuple(pr), str(c.get("name", "")), str(c.get("version", "")), digest)
    return out
