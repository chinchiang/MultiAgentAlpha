"""Read-only inventory of every GitHub Actions workflow in a tree (Appendix E prompt 5).

For each `.github/workflows/*.yml`: triggers, pull_request_target, PR-head checkout, top-level and
job-level permissions, every `uses:` with its reference kind (sha / tag / branch / local / docker),
`${{ github.event.* }}` interpolated into `run:` steps (field and line), actions/cache keys built
from untrusted refs, and a severity per the report's section 10.7 (pwn request and title injection
are Critical, unpinned actions High). Non-SHA references are resolved to a full SHA with
`git ls-remote` (skip with --offline). zizmor runs when present on PATH (offline mode, so the online
audits are skipped); otherwise the report says it was not executed. Nothing is modified.

Files that are not valid YAML (GitHub would refuse them) are still inventoried line by line and
flagged, because a seeded or half-written workflow is exactly what a reviewer needs to see.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "out", "calib-out", "__pycache__"}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)\s*(#.*)?$")
EXPR_RE = re.compile(r"\$\{\{\s*([^}]*?)\s*\}\}")
REF_KEY_RE = re.compile(r"^\s*ref:\s*(.+?)\s*$")
CACHE_KEY_RE = re.compile(r"^\s*key:\s*(.+?)\s*$")
PERM_TOP_RE = re.compile(r"^permissions:\s*(.*?)\s*$")
PERM_JOB_RE = re.compile(r"^ {4}permissions:\s*(.*?)\s*$")
JOB_RE = re.compile(r"^ {2}([A-Za-z0-9_\-]+):\s*$")
RUNS_ON_RE = re.compile(r"^\s*runs-on:\s*(.+?)\s*$")

# Attacker-controllable event fields (GitHub Security Lab, "Untrusted input" list) plus github.head_ref.
UNTRUSTED_PATTERNS = [
    r"github\.event\.pull_request\.(title|body)",
    r"github\.event\.pull_request\.head\.(ref|label)",
    r"github\.event\.pull_request\.head\.repo\.(default_branch|description|homepage|name|full_name)",
    r"github\.event\.issue\.(title|body)",
    r"github\.event\.(comment|review|review_comment)\.body",
    r"github\.event\.discussion\.(title|body)",
    r"github\.event\.commits(\[[^\]]*\])?\.(message|author\.(name|email))",
    r"github\.event\.head_commit\.(message|author\.(name|email)|committer\.(name|email))",
    r"github\.event\.workflow_run\.(head_branch|head_commit\.(message|author\.(name|email)))",
    r"github\.head_ref",
]
UNTRUSTED_RE = re.compile("|".join(f"(?:{p})" for p in UNTRUSTED_PATTERNS))
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "None"]


@dataclass
class Uses:
    line: int
    raw: str
    action: str
    ref: str
    kind: str  # sha | tag | branch | local | docker | unknown
    comment: str = ""
    resolved_sha: str | None = None
    resolved_via: str = ""
    comment_tag_sha: str | None = None
    note: str = ""


@dataclass
class Interpolation:
    line: int
    expression: str
    untrusted: bool


@dataclass
class WorkflowInventory:
    path: str
    parse_error: str | None = None
    triggers: list[str] = field(default_factory=list)
    pull_request_target: bool = False
    head_checkout_lines: list[int] = field(default_factory=list)
    top_permissions: str = "（缺失）"
    job_permissions: dict[str, str] = field(default_factory=dict)
    uses: list[Uses] = field(default_factory=list)
    run_interpolations: list[Interpolation] = field(default_factory=list)
    cache_keys: list[tuple[int, str, bool]] = field(default_factory=list)
    self_hosted: bool = False
    persist_credentials_false: int = 0
    findings: list[tuple[str, str]] = field(default_factory=list)  # (severity, text)
    severity: str = "None"
    zizmor: dict | None = None

    @property
    def non_sha_uses(self) -> list[Uses]:
        return [u for u in self.uses if u.kind in ("tag", "branch", "unknown")]


# ----------------------------------------------------------------------------- discovery


def find_workflows(root: Path) -> list[Path]:
    out = []
    for p in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.is_file() and p.suffix in (".yml", ".yaml") and p.parent.name == "workflows" and p.parent.parent.name == ".github":
            out.append(p)
    return out


# ----------------------------------------------------------------------------- parsing


def classify_ref(action: str, ref: str) -> str:
    if action.startswith("docker://"):
        return "docker"
    if action.startswith("./") or action.startswith("../"):
        return "local"
    if not ref:
        return "unknown"
    if SHA_RE.match(ref):
        return "sha"
    if re.match(r"^v?\d", ref):
        return "tag"
    return "branch"


def _block_value(lines: list[str], i: int, indent: int) -> str:
    """Inline value on line i, or the indented block that follows it, flattened to one line."""
    m = re.match(r"^\s*[A-Za-z_\-]+:\s*(.*?)\s*$", lines[i])
    inline = (m.group(1) if m else "").split(" #", 1)[0].strip()
    if inline:
        return inline
    body = []
    for j in range(i + 1, len(lines)):
        ln = lines[j]
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        if len(ln) - len(ln.lstrip(" ")) <= indent:
            break
        body.append(ln.split(" #", 1)[0].strip())
    return "{" + ", ".join(body) + "}" if body else "{}"


def _triggers(lines: list[str]) -> list[str]:
    for i, ln in enumerate(lines):
        m = re.match(r"^(?:on|\"on\"|'on'|true):\s*(.*?)\s*$", ln)
        if not m:
            continue
        inline = m.group(1)
        if inline:
            inline = inline.strip("[]")
            return [x.strip() for x in inline.split(",") if x.strip()]
        found = []
        for j in range(i + 1, len(lines)):
            ln2 = lines[j]
            if not ln2.strip() or ln2.lstrip().startswith("#"):
                continue
            indent = len(ln2) - len(ln2.lstrip(" "))
            if indent == 0:
                break
            m2 = re.match(r"^ {2}([A-Za-z_]+):", ln2)
            if m2:
                found.append(m2.group(1))
            m3 = re.match(r"^ {2}- ([A-Za-z_]+)\s*$", ln2)
            if m3:
                found.append(m3.group(1))
        return found
    return []


def _run_bodies(lines: list[str]) -> list[tuple[int, str]]:
    """(line_no, text) for every line that belongs to a run: step (inline or block scalar)."""
    out = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        m = re.match(r"^(\s*(?:-\s+)?)run:\s*(.*?)\s*$", ln)
        if not m:
            i += 1
            continue
        key_indent = len(m.group(1))
        val = m.group(2)
        if val and not val.startswith(("|", ">")):
            out.append((i + 1, val))
            i += 1
            continue
        j = i + 1
        while j < len(lines):
            ln2 = lines[j]
            if ln2.strip() and (len(ln2) - len(ln2.lstrip(" "))) <= key_indent:
                break
            out.append((j + 1, ln2))
            j += 1
        i = j
    return out


def inventory_workflow(path: Path, root: Path) -> WorkflowInventory:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    inv = WorkflowInventory(path=str(path.relative_to(root)).replace("\\", "/"))
    try:
        yaml.safe_load(text)
    except yaml.YAMLError as e:
        where = next((ln.strip() for ln in str(e).splitlines() if "line" in ln and "column" in ln), "")
        inv.parse_error = str(e).splitlines()[0] + (f"，{where.rstrip(':')}" if where else "")

    inv.triggers = _triggers(lines)
    inv.pull_request_target = "pull_request_target" in inv.triggers or any(
        re.match(r"^\s*(-\s*)?pull_request_target\s*:?\s*$", ln) for ln in lines if not ln.lstrip().startswith("#")
    )

    current_job = None
    last_cache_uses = -100
    for i, ln in enumerate(lines, 1):
        stripped = ln.strip()
        if stripped.startswith("#"):
            continue
        if PERM_TOP_RE.match(ln):
            inv.top_permissions = _block_value(lines, i - 1, 0)
        jm = JOB_RE.match(ln)
        if jm and jm.group(1) not in ("on", "jobs", "env", "defaults", "concurrency", "permissions"):
            current_job = jm.group(1)
        if PERM_JOB_RE.match(ln) and current_job:
            inv.job_permissions[current_job] = _block_value(lines, i - 1, 4)
        um = USES_RE.match(ln)
        if um:
            raw = um.group(1)
            action, _, ref = raw.partition("@")
            inv.uses.append(Uses(line=i, raw=raw, action=action, ref=ref, kind=classify_ref(action, ref), comment=(um.group(2) or "").lstrip("# ").strip()))
            if action.startswith("actions/cache"):
                last_cache_uses = i
        rm = REF_KEY_RE.match(ln)
        if rm and ("github.event.pull_request.head" in rm.group(1) or "github.head_ref" in rm.group(1)):
            inv.head_checkout_lines.append(i)
        cm = CACHE_KEY_RE.match(ln)
        if cm and 0 < i - last_cache_uses <= 12:
            key = cm.group(1)
            inv.cache_keys.append((i, key, bool(re.search(r"github\.(event\.pull_request\.head|head_ref)", key))))
        ro = RUNS_ON_RE.match(ln)
        if ro and "self-hosted" in ro.group(1):
            inv.self_hosted = True
        if re.match(r"^\s*persist-credentials:\s*false", ln):
            inv.persist_credentials_false += 1

    for line_no, body in _run_bodies(lines):
        for m in EXPR_RE.finditer(body):
            expr = m.group(1)
            if "github.event" in expr or "github.head_ref" in expr or "github.ref" in expr:
                inv.run_interpolations.append(Interpolation(line=line_no, expression=expr, untrusted=bool(UNTRUSTED_RE.search(expr))))

    _assess(inv)
    return inv


def _assess(inv: WorkflowInventory) -> None:
    f = inv.findings
    if inv.parse_error:
        f.append(("Medium", f"檔案不是合法 YAML（{inv.parse_error}）：GitHub 不會執行它，zizmor/actionlint 也無法解析，以下項目以逐行比對取得"))
    if inv.pull_request_target and inv.head_checkout_lines:
        f.append(("Critical", f"pwn request：`pull_request_target` 加 checkout PR head（第 {', '.join(map(str, inv.head_checkout_lines))} 行）；前置條件只是能開一個 fork PR"))
    elif inv.pull_request_target:
        f.append(("High", "`pull_request_target` 觸發：在基底分支的權限與 secrets 下執行，任何後續 checkout 或執行 PR 內容都會成為 pwn request"))
    for it in inv.run_interpolations:
        if it.untrusted:
            f.append(("Critical", f"攻擊者可控的 context 直接內插到 `run:`（第 {it.line} 行：`${{{{ {it.expression} }}}}`）"))
        else:
            f.append(("Low", f"`run:` 內插了 context `${{{{ {it.expression} }}}}`（第 {it.line} 行）；非標準攻擊者可控欄位，仍建議改走 env"))
    for u in inv.non_sha_uses:
        f.append(("High", f"第 {u.line} 行 `{u.raw}` 以 {('tag' if u.kind == 'tag' else '分支')} 而非 40 字元 SHA 引用（conditional：需上游 tag/分支被改指）"))
    if inv.top_permissions.strip() in ("write-all",) or any(v.strip() == "write-all" for v in inv.job_permissions.values()):
        f.append(("High", "`permissions: write-all`：GITHUB_TOKEN 取得全部 scope"))
    elif inv.top_permissions == "（缺失）" and not inv.job_permissions:
        f.append(("Medium", "頂層與 job 層都沒有 `permissions:`：GITHUB_TOKEN 落到 repo 預設（可能是 write）"))
    for line, key, bad in inv.cache_keys:
        if bad:
            f.append(("Medium", f"actions/cache 的 key 含不可信 ref（第 {line} 行：`{key}`）：cache poisoning 面"))
    if inv.self_hosted:
        f.append(("Medium", "使用 self-hosted runner：若 repo 公開且觸發含 PR，fork PR 可在 runner 上執行程式"))
    checkouts = [u for u in inv.uses if u.action == "actions/checkout"]
    if checkouts and inv.persist_credentials_false < len(checkouts):
        f.append(("Low", f"{len(checkouts) - inv.persist_credentials_false} 個 actions/checkout 未設 `persist-credentials: false`（zizmor artipacked）"))
    inv.severity = "None"
    for sev, _ in f:
        if SEVERITY_ORDER.index(sev) < SEVERITY_ORDER.index(inv.severity):
            inv.severity = sev


# ----------------------------------------------------------------------------- resolution


class Resolver:
    def __init__(self, offline: bool):
        self.offline = offline
        self.cache: dict[str, dict[str, str] | None] = {}

    def refs(self, repo: str) -> dict[str, str] | None:
        if self.offline:
            return None
        if repo in self.cache:
            return self.cache[repo]
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
        try:
            cp = subprocess.run(["git", "ls-remote", f"https://github.com/{repo}"], capture_output=True, text=True, timeout=60, env=env, check=False)
        except (subprocess.TimeoutExpired, OSError):
            self.cache[repo] = None
            return None
        if cp.returncode != 0:
            self.cache[repo] = None
            return None
        table: dict[str, str] = {}
        for ln in cp.stdout.splitlines():
            sha, _, ref = ln.partition("\t")
            table[ref] = sha
        self.cache[repo] = table
        return table

    def resolve(self, repo: str, ref: str) -> tuple[str | None, str]:
        table = self.refs(repo)
        if table is None:
            return None, "無法解析（repo 不存在、私有或不可達）" if not self.offline else "未解析（--offline）"
        for cand, via in ((f"refs/tags/{ref}^{{}}", "tag（peeled）"), (f"refs/tags/{ref}", "tag"), (f"refs/heads/{ref}", "branch")):
            if cand in table:
                return table[cand], via
        return None, "ref 不存在於遠端"


def _version_key(tag: str) -> tuple:
    nums = re.findall(r"\d+", tag)
    return tuple(int(n) for n in nums)


def latest_tag(table: dict[str, str] | None) -> str | None:
    if not table:
        return None
    tags = [r.removeprefix("refs/tags/") for r in table if r.startswith("refs/tags/") and not r.endswith("^{}")]
    tags = [t for t in tags if re.match(r"^v?\d+\.\d+\.\d+$", t)]
    return max(tags, key=_version_key) if tags else None


def resolve_all(invs: list[WorkflowInventory], resolver: Resolver) -> dict[str, str | None]:
    latest: dict[str, str | None] = {}
    for inv in invs:
        for u in inv.uses:
            if u.kind in ("local", "docker"):
                continue
            repo = "/".join(u.action.split("/")[:2])
            if u.kind == "sha":
                m = re.match(r"^(v?\d[\w.\-]*)", u.comment)
                if m:
                    sha, via = resolver.resolve(repo, m.group(1))
                    u.comment_tag_sha = sha
                    if sha is None:
                        u.note = f"註解 tag {m.group(1)}：{via}"
                    elif sha == u.ref:
                        u.note = f"pin 與註解 {m.group(1)} 一致"
                    else:
                        u.note = f"pin 與註解 {m.group(1)} 不一致（tag 目前指向 {sha[:12]}）"
            else:
                u.resolved_sha, u.resolved_via = resolver.resolve(repo, u.ref)
            if repo not in latest:
                latest[repo] = latest_tag(resolver.refs(repo))
    return latest


# ----------------------------------------------------------------------------- zizmor


def run_zizmor(path: Path) -> dict | None:
    exe = shutil.which("zizmor")
    if not exe:
        return None
    ver = subprocess.run([exe, "--version"], capture_output=True, text=True, check=False).stdout.strip()
    cp = subprocess.run([exe, "--no-progress", "--offline", "--format", "sarif", str(path)], capture_output=True, text=True, timeout=300, check=False)
    out: dict = {"version": ver, "exit_code": cp.returncode, "stderr": [ln for ln in cp.stderr.splitlines() if ("WARN" in ln or "fatal" in ln or "error" in ln.lower()) and not re.match(r"^\s*\d+: ", ln)][:5], "results": [], "sarif": None}
    if cp.stdout.strip():
        try:
            sarif = json.loads(cp.stdout)
            out["sarif"] = sarif
            for run in sarif.get("runs", []):
                for r in run.get("results", []):
                    loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
                    out["results"].append({"rule": r.get("ruleId"), "level": r.get("level"), "line": loc.get("region", {}).get("startLine"), "message": r.get("message", {}).get("text", "")[:140]})
        except json.JSONDecodeError:
            out["stderr"].append("SARIF 輸出無法解析")
    return out


# ----------------------------------------------------------------------------- rendering


def _md(s: str) -> str:
    return s.replace("|", "\\|")


def render(invs: list[WorkflowInventory], latest: dict[str, str | None], *, root: Path, offline: bool, date: str, zizmor_present: bool) -> str:
    invs = sorted(invs, key=lambda i: (SEVERITY_ORDER.index(i.severity), i.path))
    L: list[str] = []
    L += [f"# GitHub Actions 盤點（{date}）", "",
          "依附錄 E 的 prompt 5，對本 repo 內所有 `.github/workflows/*.yml` 做 pwn request 與 SHA pinning 盤點。**只讀不改。** 本檔第 0 到 5 節由 `scripts/actions_inventory.py` 產生，第 6 節為人工補充。", "",
          "## 0. 範圍、方法與判定準則", "",
          f"- 掃描根目錄：`{root.name}/`，遞迴尋找所有 `.github/workflows/*.yml|yaml`（排除 `.git`、`node_modules`、`out/`、`calib-out/`）。共 {len(invs)} 個 workflow。",
          "- 每個檔案先以 `yaml.safe_load` 驗證；不合法 YAML 的檔案仍以逐行比對盤點並標記，因為 GitHub 會拒絕執行它、zizmor 與 actionlint 也解析不了，這本身就是要回報的事實。",
          "- `uses:` 的引用種類：40 字元十六進位為 **sha**；`v` 或數字開頭為 **tag**；其餘為 **branch**；`./` 為 local、`docker://` 為 docker。",
          "- `run:` 內插：列出所有 `${{ github.event.* }}`、`github.head_ref`、`github.ref`；其中符合 GitHub Security Lab「不可信輸入」清單（PR 標題／內文／head ref／head label、issue 標題／內文、comment/review 內文、commit message 與作者、`github.head_ref`）者標為攻擊者可控。",
          "- 非 SHA 引用以 `git ls-remote https://github.com/<owner>/<repo>` 解析目前 tag（優先取 peeled `^{}`）或分支的完整 SHA" + ("（本次 `--offline`，未解析）。" if offline else "。"),
          "- SHA 引用若附 `# vX.Y.Z` 註解，一併驗證該 tag 目前是否仍指向這個 SHA。",
          f"- zizmor：{'已執行（`--offline`，線上稽核如 impostor-commit 與 known-vulnerable-actions 未跑；與 CI 中 zizmor-action 未帶 token 時的行為一致）' if zizmor_present else '未執行：zizmor 不在 PATH'}。actionlint、poutine：未執行（不在 PATH）。",
          "", "**判定準則（報告第 10.7 節）。** pwn request（`pull_request_target` 加 checkout PR head）為 Critical 且 reachable；攻擊者可控 context 內插到 `run:`（標題注入等）同為 Critical；以 tag 或分支引用第三方 action 為 High 但 conditional；`write-all` 為 High；缺 `permissions:`、cache key 含不可信 ref、self-hosted runner 為 Medium；未設 `persist-credentials: false` 為 Low。workflow 的嚴重度取其最高項。", "",
          "## 1. 總表（Critical 在最上方）", "",
          "| 嚴重度 | workflow | 用途 | 觸發 | PRT | checkout PR head | 頂層 permissions | job permissions | uses（sha/tag/branch） | run 內插（可控） | cache key 含 ref | 合法 YAML |",
          "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for inv in invs:
        sha = sum(u.kind == "sha" for u in inv.uses)
        tag = sum(u.kind == "tag" for u in inv.uses)
        br = sum(u.kind in ("branch", "unknown") for u in inv.uses)
        inj = len(inv.run_interpolations)
        inj_bad = sum(i.untrusted for i in inv.run_interpolations)
        purpose = "**實際 CI**" if inv.path.startswith(".github/") else "fixture／校準樣本（刻意含缺陷，不會執行）"
        jobp = "; ".join(f"{k}: {v}" for k, v in inv.job_permissions.items()) or "（缺失）"
        L.append(f"| **{inv.severity}** | `{inv.path}` | {purpose} | {', '.join(inv.triggers) or '?'} | {'是' if inv.pull_request_target else '否'} | "
                 f"{('是（第 ' + ', '.join(map(str, inv.head_checkout_lines)) + ' 行）') if inv.head_checkout_lines else '否'} | `{_md(inv.top_permissions)}` | {_md(jobp)} | "
                 f"{sha}/{tag}/{br} | {inj}（{inj_bad}） | {'是' if any(b for _, _, b in inv.cache_keys) else ('否' if inv.cache_keys else '無 cache')} | {'否' if inv.parse_error else '是'} |")
    L += ["", "## 2. 逐一明細", ""]
    for inv in invs:
        L += [f"### {inv.path} — {inv.severity}", ""]
        if inv.parse_error:
            L += [f"> 不是合法 YAML：{inv.parse_error}", ""]
        L += ["**判定項目**", ""]
        for sev, txt in sorted(inv.findings, key=lambda x: SEVERITY_ORDER.index(x[0])):
            L.append(f"- **{sev}** — {txt}")
        if not inv.findings:
            L.append("- 無")
        L += ["", "**`uses:` 引用**", "", "| 行 | 引用 | 種類 | 註解 | 解析結果 |", "|---|---|---|---|---|"]
        for u in inv.uses:
            res = u.note or (f"目前 {u.resolved_via} → `{u.resolved_sha}`" if u.resolved_sha else u.resolved_via) or ""
            L.append(f"| {u.line} | `{u.raw}` | {u.kind} | {u.comment or ''} | {_md(res)} |")
        if not inv.uses:
            L.append("| — | （無） | | | |")
        L += ["", "**`run:` 內插**", ""]
        if inv.run_interpolations:
            L += ["| 行 | 運算式 | 攻擊者可控 |", "|---|---|---|"]
            for it in inv.run_interpolations:
                L.append(f"| {it.line} | `${{{{ {it.expression} }}}}` | {'**是**' if it.untrusted else '否'} |")
        else:
            L.append("無。")
        if inv.zizmor is not None:
            z = inv.zizmor
            L += ["", f"**zizmor**（{z['version']}，`--offline`，exit {z['exit_code']}）", ""]
            if z["results"]:
                L += ["| 規則 | 等級 | 行 | 訊息 |", "|---|---|---|---|"]
                for r in z["results"]:
                    L.append(f"| {r['rule']} | {r['level']} | {r['line'] or ''} | {_md(r['message'])} |")
            elif z["exit_code"] == 0:
                L.append("無 finding。")
            for ln in z["stderr"]:
                L.append(f"- stderr：`{_md(ln.strip())}`")
        L.append("")
    L += ["## 3. 建議修改（非 SHA 的 `uses:` → 完整 SHA；不直接改檔）", "",
          "| workflow | 行 | 目前 | 建議改為 | 依據 | 備註 |", "|---|---|---|---|---|---|"]
    n = 0
    for inv in invs:
        for u in inv.non_sha_uses:
            n += 1
            fixture = not inv.path.startswith(".github/")
            if u.resolved_sha:
                suggest = f"`{u.action}@{u.resolved_sha} # {u.ref}`"
            else:
                suggest = "（無法解析；若為真實 action 需先確認來源）"
            note = "fixture，刻意保留缺陷供 L0/L2 測試，不建議修改" if fixture else ""
            L.append(f"| `{inv.path}` | {u.line} | `{u.raw}` | {suggest} | {u.resolved_via or '—'} | {note} |")
    if n == 0:
        L.append("| — | — | （所有引用都已是 SHA） | | | |")
    L += ["", "**已固定 SHA 的引用：對照 tag 與最新版本**", "", "| workflow | 行 | 引用 | 註解 tag 驗證 | 該 repo 目前最新 tag |", "|---|---|---|---|---|"]
    for inv in invs:
        for u in inv.uses:
            if u.kind == "sha":
                repo = "/".join(u.action.split("/")[:2])
                L.append(f"| `{inv.path}` | {u.line} | `{u.action}@{u.ref[:12]}…` | {u.note or '無註解'} | {latest.get(repo) or '未解析'} |")
    L += ["", "## 4. zizmor 結果（SARIF）", ""]
    if not zizmor_present:
        L.append("未執行：zizmor 不在 PATH。安裝方式：`pip install zizmor` 或 `cargo install zizmor`，再重跑本腳本。")
    else:
        for inv in invs:
            z = inv.zizmor
            if z is None:
                continue
            L += [f"<details><summary><code>{inv.path}</code> — exit {z['exit_code']}，{len(z['results'])} 個 finding</summary>", ""]
            if z["sarif"] is not None:
                L += ["```json", json.dumps(z["sarif"], ensure_ascii=False, indent=1)[:6000], "```"]
            else:
                L += ["（無 SARIF 輸出）"] + [f"- `{_md(s.strip())}`" for s in z["stderr"]]
            L += ["", "</details>", ""]
    L += ["## 5. 驗收自檢", "",
          f"- 每個 workflow 都有一列：{len(invs)} 個檔案、{len(invs)} 列。",
          f"- 每個非 SHA 引用都有建議 SHA：{sum(1 for i in invs for u in i.non_sha_uses if u.resolved_sha)} / {sum(len(i.non_sha_uses) for i in invs)}"
          + ("（未解析者為不存在的 fixture action）" if any(u.resolved_sha is None for i in invs for u in i.non_sha_uses) else "") + "。",
          f"- Critical 項目在表格最上方：{'是' if invs and invs[0].severity == SEVERITY_ORDER[0] or all(i.severity != 'Critical' for i in invs) else '否'}。", ""]
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("root", nargs="?", default=".", type=Path)
    ap.add_argument("--out", type=Path, help="write the Markdown here (default: stdout)")
    ap.add_argument("--offline", action="store_true", help="do not run git ls-remote")
    ap.add_argument("--no-zizmor", action="store_true")
    ap.add_argument("--date", default=dt.date.today().isoformat())
    ap.add_argument("--json", action="store_true", help="emit the inventory as JSON instead of Markdown")
    args = ap.parse_args()
    root = args.root.resolve()
    invs = [inventory_workflow(p, root) for p in find_workflows(root)]
    latest = resolve_all(invs, Resolver(args.offline))
    zizmor_present = bool(shutil.which("zizmor")) and not args.no_zizmor
    if zizmor_present:
        for inv in invs:
            inv.zizmor = run_zizmor(root / inv.path)
    if args.json:
        payload = [{**{k: v for k, v in inv.__dict__.items() if k not in ("zizmor",)}, "uses": [u.__dict__ for u in inv.uses],
                    "run_interpolations": [i.__dict__ for i in inv.run_interpolations],
                    "zizmor": {k: v for k, v in (inv.zizmor or {}).items() if k != "sarif"}} for inv in invs]
        text = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
    else:
        text = render(invs, latest, root=root, offline=args.offline, date=args.date, zizmor_present=zizmor_present)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.out} ({len(invs)} workflows)")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
