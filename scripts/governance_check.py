"""Executable compliance checks for governance items G-1 to G-13 (Appendix E prompt 8).

Each item from Part X of the report becomes one check against this repository and its
configuration. A check is PASS or FAIL when it can be decided from files alone, and MANUAL when
it cannot; a MANUAL row says exactly which evidence a human has to produce. Every row carries
the evidence it looked at and the standard clauses from the report's section 25.4 table.

Exit status is 1 when any check FAILS (MANUAL rows never fail the run).

  python scripts/governance_check.py --out docs/governance-check-<date>.md
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from actions_inventory import inventory_workflow  # noqa: E402

PASS, FAIL, MANUAL = "PASS", "FAIL", "MANUAL"
STATUS_ZH = {PASS: "通過", FAIL: "失敗", MANUAL: "需人工"}
FRESH_DAYS = 90
DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")
COVERED_MARKERS = ("fable", "mythos")
ALLOWED_RESIDENCY = {"on_prem", "vendor_api_zdr"}
# Part X, section 25.4 對應總表
STANDARDS = {
    "G-1": "ISO/IEC 27001:2022 A.8.25, A.8.29；IEC 62443-4-1 SVV；NIST SSDF PW.7, PW.8",
    "G-2": "NIST AI 600-1（Harmful Bias and Homogenization）；ISO/IEC 42001",
    "G-3": "ISO/IEC 27001:2022 A.5.19–5.21*, A.8.10；Anthropic 資料保留條款",
    "G-4": "ISO/IEC 27001:2022 A.5.20*；NIST CSF 2.0 GV.SC",
    "G-5": "ISO/IEC 27001:2022 A.8.8*；IEC 62443-4-1 SM-9；NIST SP 800-204D；SLSA v1.2",
    "G-6": "ISO/IEC 27001:2022 A.8.32*；IEC 62443-4-1 SM；OpenSSF Scorecard；GitHub SHA-pinning 政策",
    "G-7": "ISO/IEC 27001:2022 A.5.21*；IEC 62443-4-1 SM-9；EU CRA Annex I Part II (1)；CycloneDX 1.6+",
    "G-8": "IEC 62443-4-1 SVV；NIST AI 600-1（Information Security）；OWASP Agentic Top 10",
    "G-9": "ISO/IEC 27001:2022 A.8.29；IEC 62443-4-1 SVV；ISO/IEC 23894",
    "G-10": "ISO/IEC 27001:2022 A.8.25；IEC 62443-4-1 SM",
    "G-11": "ISO/IEC 27001:2022 A.8.29；IEC 62443-4-1 DM；NIST SSDF RV.1",
    "G-12": "IEC 62443-4-1 DM, SUM；EU CRA Art. 14",
    "G-13": "EU AI Act Art. 4",
}
TITLES = {
    "G-1": "自動審查定義為安全測試的一部分，而非取代",
    "G-2": "家族數不低於三、反序 pass 不關閉、judge 不見分數",
    "G-3": "資料主權規則寫進設定檔驗證",
    "G-4": "模型可抽換性作為採購條件（冷備家族）",
    "G-5": "L0 工具固定版本並簽章驗證",
    "G-6": "審查 workflow 套用 SHA pinning 與 pull_request 限制",
    "G-7": "模型權重納入 SBOM（ML-BOM）並簽章",
    "G-8": "每季 garak 與 CyberSecEval 測試",
    "G-9": "校準迴圈每季重跑（真實家族）",
    "G-10": "三階段導入：影子、建議、門檻阻擋",
    "G-11": "人工佇列接工單、裁決回寫校準集",
    "G-12": "A 級 Critical 接入 PSIRT 的 CRA 第 14 條通報",
    "G-13": "AI 素養訓練",
}


@dataclass
class CheckResult:
    id: str
    status: str
    evidence: str

    @property
    def title(self) -> str:
        return TITLES[self.id]

    @property
    def standards(self) -> str:
        return STANDARDS[self.id]


# ----------------------------------------------------------------------------- helpers


def _dated_files(directory: Path, patterns: list[str], today: dt.date) -> list[tuple[Path, dt.date, int]]:
    """Files whose name matches one of the glob patterns and carries a YYYY-MM-DD; with age in days."""
    out = []
    for pat in patterns:
        for p in directory.glob(pat):
            m = DATE_RE.search(p.name)
            if not m:
                continue
            try:
                d = dt.date.fromisoformat(m.group(1))
            except ValueError:
                continue
            out.append((p, d, (today - d).days))
    return sorted(out, key=lambda x: x[1], reverse=True)


def _raw_config(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


# ----------------------------------------------------------------------------- checks


def check_g1(root: Path, today: dt.date | None = None) -> CheckResult:
    from mara.govdocs import POLICY_STATEMENTS, policy_status

    today = today or dt.date.today()
    path = root / "docs" / "policy" / "mara-review-policy.md"
    st = policy_status(path, today)
    if st.state == "missing":
        return CheckResult("G-1", FAIL, "沒有政策文件 `docs/policy/mara-review-policy.md`。需要：以樣板建立，六條條文（S1 審查是 A.8.29 安全測試的一部分、"
                           "S2 通過不等於免除人工測試、S3 處理義務、S4 人工裁決、S5 資料駐留、S6 例外）有內容，PSO 核定後填 status/approved_by/approved_on")
    have = "、".join(f"{k} {POLICY_STATEMENTS[k]}" for k, ok in st.statements.items() if ok)
    if st.ok:
        return CheckResult("G-1", PASS, f"`docs/policy/mara-review-policy.md` v{st.meta.get('version', '?')} 由 {st.meta.get('approved_by')} 於 "
                           f"{st.meta.get('approved_on')} 核定（複審 {st.meta.get('review_by') or '未定'}）；條文 {have}")
    return CheckResult("G-1", FAIL, f"政策文件存在但{'（草案）' if st.state == 'draft' else ''}未達標：{'；'.join(st.problems)}。已有條文：{have or '無'}。"
                       "需要：PSO 核定後在 front matter 填 `status: approved`、`approved_by`、`approved_on`、`review_by`")


def check_g2(root: Path, config_path: Path) -> CheckResult:
    from mara.bias.blinding import blind_finding
    from mara.config import load_config
    from mara.policy import evaluate_policies
    from mara.schemas import Finding, ModelFamily, Provenance

    problems, evidence = [], []
    cfg = load_config(config_path)
    rev = {cfg.model_by_name(n).family.value for n in cfg.roles.reviewers}
    jud = {cfg.model_by_name(n).family.value for n in cfg.roles.judges}
    evidence.append(f"`{config_path.relative_to(root)}`：reviewer 家族 {sorted(rev)}，judge 家族 {sorted(jud)}")
    if len(rev) < 3:
        problems.append(f"reviewer 家族數 {len(rev)} < 3")
    if len(jud) < 3:
        problems.append(f"judge 家族數 {len(jud)} < 3")
    pipeline = (root / "src/mara/pipeline.py").read_text(encoding="utf-8")
    config_src = (root / "src/mara/config.py").read_text(encoding="utf-8")
    if 'run_judge(prov, rev, "reverse"' in pipeline:
        evidence.append("`src/mara/pipeline.py` 對每個 judge 執行 forward 與 reverse 兩個 pass")
    else:
        problems.append("pipeline.py 找不到 reverse pass 的呼叫")
    flags = re.findall(r"(skip_reverse|reverse_pass|single_pass|disable_reverse)\w*", pipeline + config_src)
    if flags:
        problems.append(f"存在可關閉反序 pass 的旗標：{sorted(set(flags))}")
    else:
        evidence.append("pipeline.py 與 config.py 無任何可關閉反序 pass 的旗標")
    f = Finding(id="F-0001", dimension="xss", title="t", cwe="CWE-79", provenance=[Provenance(file="a.py", line=1, quote="abc")],
                reachability_argument="r", exploit_sketch="e", cvss4_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                model_confidence=0.9, source_family=ModelFamily("anthropic"), source_model="m")
    view = blind_finding(f, None)
    leaked = [k for k in ("source_family", "source_model", "model_confidence", "cvss4_vector", "cvss4_score", "weight") if k in json.dumps(view)]
    if leaked:
        problems.append(f"judge 視圖洩漏欄位 {leaked}")
    else:
        evidence.append(f"`bias/blinding.py::blind_finding` 輸出鍵 {sorted(view)}，不含身分、信心、CVSS")
    pol = {r.id: r for r in evaluate_policies(cfg)}
    for pid in ("P3", "P4"):
        if pid in pol:
            evidence.append(f"政策 {pid} {pol[pid].name}：{'PASS' if pol[pid].passed else 'FAIL'}（{pol[pid].reason}）")
            if not pol[pid].passed:
                problems.append(f"政策 {pid} 失敗")
    return CheckResult("G-2", FAIL if problems else PASS, ("；".join(problems) + "。" if problems else "") + "；".join(evidence))


def check_g3(root: Path, config_path: Path) -> CheckResult:
    from mara.config import load_config

    cfg = load_config(config_path)
    problems, rows = [], []
    for m in cfg.models:
        res = getattr(m, "data_residency", None)
        res = getattr(res, "value", res)
        rows.append(f"{m.name}={m.provider}/{m.model}/{res}")
        if m.provider != "mock" and res not in ALLOWED_RESIDENCY:
            problems.append(f"{m.name} 的 data_residency={res} 不在 {sorted(ALLOWED_RESIDENCY)}")
        if any(k in m.model.lower() for k in COVERED_MARKERS):
            problems.append(f"{m.name} 使用 Fable/Mythos 級模型 {m.model}")
    ev = f"`{config_path.relative_to(root)}` 模型：{', '.join(rows)}；`src/mara/policy.py` P1/P2/P5 在載入時強制"
    return CheckResult("G-3", FAIL if problems else PASS, ("；".join(problems) + "。" if problems else "") + ev)


def check_g4(root: Path, config_path: Path | None = None, today: dt.date | None = None) -> CheckResult:
    from mara.config import load_config
    from mara.govdocs import DRILL_MAX_HOURS, drill_status

    today = today or dt.date.today()
    cfg = load_config(config_path or root / "config" / "mara.yaml")
    statuses = drill_status(cfg, root, today)
    if not statuses:
        return CheckResult("G-4", PASS, "設定中沒有非 mock 的模型家族")
    ev, problems = [], []
    for st in statuses:
        if st.config_ok:
            ev.append(f"{st.family}→{st.standby_family} `{st.standby_config}` 可載入")
        else:
            problems.append(f"{st.family}：冷備設定{st.config_problem}")
        if st.drill_ok and st.drill:
            ev.append(f"{st.family} 換模演練 {st.drill.date} {st.drill.duration_hours:g} h 通過（{st.drill.performed_by}，{st.drill.evidence}）")
        else:
            problems.append(f"{st.family}：{st.drill_problem}")
    need = (f"需要：每個生產家族一份 `config/examples/standby-for-<family>.yaml`（通過 `mara check-config`）與一年內完成、"
            f"{DRILL_MAX_HOURS} 小時內通過的實地換模演練，以 `scripts/model_swap_drill.py record` 寫入 `ops/model-swap-drills.yaml`")
    if problems:
        return CheckResult("G-4", FAIL, "；".join(problems) + "。已有：" + ("；".join(ev) or "無") + "。" + need)
    return CheckResult("G-4", PASS, "；".join(ev))


def check_g5(root: Path) -> CheckResult:
    lock_path = root / "tools" / "versions.lock"
    if not lock_path.is_file():
        return CheckResult("G-5", FAIL, "`tools/versions.lock` 不存在。需要：每個 L0 工具的版本、URL、SHA-256 與簽章驗證方式（見 prompt 7）")
    lock = yaml.safe_load(lock_path.read_text(encoding="utf-8")) or {}
    problems, ev = [], []
    for name, t in (lock.get("tools") or {}).items():
        if t.get("kind") == "pip":
            req = root / t.get("requirements", "")
            n = req.read_text(encoding="utf-8").count("--hash=sha256:") if req.is_file() else 0
            (ev if n else problems).append(f"{name} pip 鎖定 {n} 個 wheel hash" if n else f"{name} 的 requirements 無 hash")
            continue
        sha = str(t.get("sha256", ""))
        method = (t.get("verify") or {}).get("method", "")
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            problems.append(f"{name} 無合法 SHA-256")
        elif not method:
            problems.append(f"{name} 無 verify.method")
        else:
            ev.append(f"{name} {t.get('version')} sha256 {sha[:12]}… {method}")
    manifest = root / ".mara-tools" / "manifest.json"
    if manifest.is_file():
        m = json.loads(manifest.read_text(encoding="utf-8")).get("tools", {})
        ev.append("manifest：" + ", ".join(f"{k}={'signed' if v.get('signature_verified') else 'hash-only'}" for k, v in m.items()))
    ev.append("CI `deterministic-tools` job 以 `scripts/install_tools.py` 安裝並驗證")
    return CheckResult("G-5", FAIL if problems else PASS, ("；".join(problems) + "。" if problems else "") + "；".join(ev))


def _perm_readonly(value) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return value in ("read-all",)
    if isinstance(value, dict):
        return all(v in ("read", "none") for v in value.values())
    return False


def check_g6(root: Path, workflows_dir: Path | None = None) -> CheckResult:
    wdir = workflows_dir or (root / ".github" / "workflows")
    files = sorted(p for p in wdir.glob("*.y*ml")) if wdir.is_dir() else []
    if not files:
        return CheckResult("G-6", FAIL, f"`{wdir}` 下沒有 workflow")
    problems, ev = [], []
    for p in files:
        inv = inventory_workflow(p, root if p.is_relative_to(root) else p.parents[2])
        rel = inv.path
        non_sha = [f"第 {u.line} 行 `{u.raw}`" for u in inv.uses if u.kind in ("tag", "branch", "unknown")]
        if non_sha:
            problems.append(f"`{rel}` 非 SHA 引用：{'，'.join(non_sha)}")
        if inv.pull_request_target:
            problems.append(f"`{rel}` 使用 pull_request_target")
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as e:
            problems.append(f"`{rel}` 不是合法 YAML：{str(e).splitlines()[0]}")
            continue
        top = doc.get("permissions", None)
        if "permissions" not in doc:
            problems.append(f"`{rel}` 缺頂層 permissions")
        elif not (top == {} or _perm_readonly(top)):
            problems.append(f"`{rel}` 頂層 permissions 非空也非只讀：{top}")
        writes = []
        for job, spec in (doc.get("jobs") or {}).items():
            jp = (spec or {}).get("permissions")
            if jp == "write-all" or (isinstance(jp, dict) and any(jp.get(k) == "write" for k in ("contents", "packages", "actions", "id-token"))):
                problems.append(f"`{rel}` job {job} 的 permissions 過寬：{jp}")
            elif isinstance(jp, dict) and any(v == "write" for v in jp.values()):
                writes.append(f"{job}:{','.join(k for k, v in jp.items() if v == 'write')}")
        ev.append(f"`{rel}`：{len(inv.uses)} 個 uses 全為 SHA" if not non_sha else f"`{rel}`：{len(inv.uses)} 個 uses")
        if writes:
            ev.append(f"`{rel}` job 層 write 權限（允許）：{'; '.join(writes)}")
    return CheckResult("G-6", FAIL if problems else PASS, ("；".join(problems) + "。" if problems else "") + "；".join(ev))


def check_g7(root: Path, config_path: Path) -> CheckResult:
    from mara.mlbom import component_problems, load_bom, ml_components, props

    raw = _raw_config(config_path)
    self_hosted = [(m.get("name", "?"), m.get("model", "?")) for m in raw.get("models", []) if m.get("provider") == "openai_compatible"]
    cands = sorted((root / "sbom").glob("*.cdx.json")) + ([root / "bom.json"] if (root / "bom.json").exists() else [])
    comps: dict[str, dict] = {}
    boms = []
    for p in cands:
        try:
            comps.update(ml_components(load_bom(p)))
            boms.append(p)
        except (OSError, ValueError):
            continue
    if not self_hosted:
        return CheckResult("G-7", PASS, "設定中沒有自架模型，ML-BOM 無需列出權重")
    need = ("需要：平台團隊只從官方來源下載權重，在下載主機執行 `scripts/ml_bom.py hash-dir … --write-manifest sbom/models.yaml`（或貼上 registry 的 sha256），"
            "`ml_bom.py build` 產生 BOM，以 `cosign sign-blob --bundle` 簽章後提交，並把 `ml_bom.required` 設為 true 讓政策 P7 強制")
    if not boms:
        return CheckResult("G-7", FAIL, f"找不到 CycloneDX ML-BOM（`sbom/*.cdx.json`、`bom.json`）。自架模型 {[m for _, m in self_hosted]} 的權重未列冊。{need}")
    ev = [f"`{p.relative_to(root)}`" for p in boms]
    if (root / "sbom" / "models.yaml").exists():
        ev.append("manifest `sbom/models.yaml`")
    problems = []
    for name, model_id in self_hosted:
        c = comps.get(model_id)
        if c is None:
            problems.append(f"`{model_id}`（{name}）在 ML-BOM 中沒有 machine-learning-model 元件")
            continue
        pr = component_problems(c)
        if pr:
            problems.append(f"`{model_id}`（{name}）元件不完整：{'；'.join(pr)}")
        else:
            digest = next((h["content"] for h in c.get("hashes", []) if h.get("alg") == "SHA-256"), "")
            ev.append(f"`{model_id}` {c.get('name')}@{c.get('version')} SHA-256 {digest[:12]}… {props(c).get('file-count', '?')} 檔，簽章 {props(c).get('signature')}")
    ml = raw.get("ml_bom") or {}
    if ml.get("required"):
        ev.append("`ml_bom.required: true`（政策 P7 強制）")
        if ml.get("require_signature") and not (root / str(ml.get("bundle", ""))).exists():
            problems.append(f"`ml_bom.require_signature` 已開但簽章 bundle `{ml.get('bundle')}` 不存在")
    else:
        ev.append("`ml_bom.required: false`（P7 尚未強制）")
    if problems:
        return CheckResult("G-7", FAIL, "；".join(problems) + "。已有：" + "；".join(ev) + "。" + need)
    return CheckResult("G-7", PASS, "；".join(ev))


def check_g8(root: Path, today: dt.date) -> CheckResult:
    files = _dated_files(root / "docs", ["garak-*", "cyberseceval-*", "cybersec-eval-*"], today)
    fresh = [(p, d, age) for p, d, age in files if age <= FRESH_DAYS]
    if fresh:
        return CheckResult("G-8", PASS, "；".join(f"`docs/{p.name}`（{d}，{age} 天前）" for p, d, age in fresh))
    stale = "；".join(f"`docs/{p.name}`（{age} 天前）" for p, d, age in files) or "無任何 garak／CyberSecEval 報告"
    return CheckResult("G-8", FAIL, f"{stale}。需要：{FRESH_DAYS} 天內對三個家族執行 garak 與 CyberSecEval 4（Prompt Injection、False Refusal Rate）的報告，檔名含日期")


def check_g9(root: Path, today: dt.date) -> CheckResult:
    files = _dated_files(root / "docs", ["calibration-*.md"], today)
    fresh, mock_only = [], []
    for p, d, age in files:
        if age > FRESH_DAYS:
            continue
        head = p.read_text(encoding="utf-8")[:600]
        if re.search(r"執行模式[:：]\s*\**mock", head) or "mode `mock`" in head:
            mock_only.append(f"`docs/{p.name}`（{d}，mock 模式）")
        else:
            fresh.append(f"`docs/{p.name}`（{d}，{age} 天前）")
    if fresh:
        return CheckResult("G-9", PASS, "；".join(fresh))
    detail = "；".join(mock_only) if mock_only else (f"最新校準報告 {files[0][2]} 天前" if files else "無校準報告")
    return CheckResult("G-9", FAIL, f"{detail}。需要：{FRESH_DAYS} 天內以真實三家族執行的校準報告（`python scripts/calibrate.py --mode live`），含每家族每 CWE 的精確度與召回率、更新後的權重")


def check_g10(root: Path, config_path: Path, today: dt.date | None = None) -> CheckResult:
    from mara.config import load_config
    from mara.govdocs import rollout_status

    today = today or dt.date.today()
    cfg = load_config(config_path)
    st = rollout_status(cfg, root, today)
    ev = [f"`rollout.phase: {st.phase}`"]
    if st.days_in_phase is not None:
        ev.append(f"自 {cfg.rollout.started_on} 起 {st.days_in_phase} 天" + (f"（預定 {st.due} 前進入下一階段）" if st.due else ""))
    if cfg.rollout.baseline_report:
        ev.append(f"基線報告 `{cfg.rollout.baseline_report}`")
    ev += list(st.notes)
    if st.ok:
        return CheckResult("G-10", PASS, "；".join(ev))
    return CheckResult("G-10", FAIL, "；".join(st.problems) + "。已有：" + "；".join(ev)
                       + "。需要：`rollout.phase`（shadow→advisory→blocking）、`started_on`、影子期結束時的基線報告（`scripts/rollout_phase.py baseline`）")


def check_g11(root: Path, config_path: Path) -> CheckResult:
    raw = _raw_config(config_path)
    ev = []
    if (root / "calib" / "decisions").is_dir():
        ev.append("`calib/decisions/` 存在")
    if raw.get("human_queue"):
        ev.append("設定有 `human_queue` 區塊")
    for p in (root / ".github" / "workflows").glob("*.y*ml"):
        text = p.read_text(encoding="utf-8")
        # only a workflow that names the human queue counts; the governance tracking issue is not one
        if re.search(r"human[_-]queue", text):
            ev.append(f"`{p.relative_to(root)}` 含人工佇列的工單整合")
    if len(ev) >= 2:
        return CheckResult("G-11", PASS, "；".join(ev))
    return CheckResult("G-11", FAIL, (("已有：" + "；".join(ev) + "。") if ev else "") + "人工佇列未接工單、裁決未回寫。需要：workflow 把 needs_human finding 建成帶標籤的 issue、`calib/decisions/` 的裁決格式與 `calibrate.py` 讀取、佇列超量時收緊門檻的規則")


def check_g12(root: Path, config_path: Path) -> CheckResult:
    raw = _raw_config(config_path)
    ps = raw.get("psirt")
    if not isinstance(ps, dict):
        return CheckResult("G-12", FAIL, "設定無 `psirt:` 區塊。需要：PSIRT 接入端點（https）、產品識別、只對 A 級 Critical 觸發的規則（政策 P6），對應 CRA 第 14 條 24 小時預警（2026-09-11 起適用）；見 `docs/psirt-integration.md`")
    if not ps.get("enabled"):
        return CheckResult("G-12", FAIL, "`psirt:` 區塊存在但 `enabled: false`。需要：填入 https 的 `webhook_url`、`product`，把 `enabled` 與 `shipped` 設為 true，token 放在 `token_env` 指定的環境變數；範例 `config/examples/psirt-enabled.yaml`")
    problems = []
    if not str(ps.get("webhook_url", "")).lower().startswith("https://"):
        problems.append("webhook_url 非 https")
    if not str(ps.get("product", "")).strip():
        problems.append("product 為空")
    tiers, sevs = ps.get("trigger_tiers", ["A"]), ps.get("trigger_severities", ["Critical"])
    if not set(tiers) <= {"A", "B"} or not set(sevs) <= {"Critical", "High"}:
        problems.append(f"觸發範圍過寬：tiers={tiers} severities={sevs}（G-12 只限 A 級 Critical，P6 允許到 B/High）")
    if problems:
        return CheckResult("G-12", FAIL, "；".join(problems))
    return CheckResult("G-12", PASS, f"`psirt.enabled: true`，產品 {ps.get('product')!r}，webhook {ps.get('webhook_url')}，觸發 tiers={tiers} severities={sevs}，"
                       f"{ps.get('early_warning_hours', 24)} h 預警；`src/mara/report/psirt_out.py` 在每次 review 產出 `out/psirt-notifications.json`")


def check_g13(root: Path, today: dt.date, config_path: Path | None = None) -> CheckResult:
    from mara.training import ROLES, load_register

    need = ("需要：每個角色（developer、security、adjudicator）至少一人在一年內完成 `training/curriculum.md` 的訓練並以 "
            "`scripts/training_register.py assess`／`add` 寫入 `training/records.yaml`；人工裁決者必須有有效的 adjudicator 紀錄，否則其裁決不進校準")
    curriculum = root / "training" / "curriculum.md"
    register_path = root / "training" / "records.yaml"
    raw = _raw_config(config_path) if config_path else {}
    roles = tuple((raw.get("training") or {}).get("required_roles") or ROLES)
    if not curriculum.exists():
        return CheckResult("G-13", FAIL, f"沒有課程 `training/curriculum.md`（證據層級、偏誤稽核、「通過不等於安全」、人工裁決）。{need}")
    if not register_path.exists():
        return CheckResult("G-13", FAIL, f"有課程但沒有訓練登錄簿 `training/records.yaml`。{need}")
    try:
        reg = load_register(register_path)
    except (OSError, ValueError) as e:
        return CheckResult("G-13", FAIL, f"`training/records.yaml` 無法讀取：{e}。{need}")
    ev = [f"課程 `training/curriculum.md` 版本 {reg.curriculum_version}，紀錄有效 {reg.validity_days} 天，共 {len(reg.records)} 筆"]
    missing = []
    for role in roles:
        recs = reg.valid(today, role)
        if recs:
            ev.append(f"{role}：{len(recs)} 筆有效（{', '.join(sorted({r.person for r in recs}))}）")
        else:
            missing.append(role)
    expiring = reg.expiring(today)
    if expiring:
        ev.append("30 天內到期：" + ", ".join(f"{r.person}/{r.role} {r.expires}" for r in expiring))
    if (raw.get("training") or {}).get("require_trained_adjudicator", True):
        ev.append("`training.require_trained_adjudicator: true`（未受訓者的裁決不進校準）")
    if missing:
        return CheckResult("G-13", FAIL, f"以下角色沒有有效的訓練紀錄：{', '.join(missing)}。已有：{'；'.join(ev)}。{need}")
    return CheckResult("G-13", PASS, "；".join(ev))


def run_all(root: Path, config_path: Path, today: dt.date | None = None) -> list[CheckResult]:
    today = today or dt.date.today()
    return [
        check_g1(root, today), check_g2(root, config_path), check_g3(root, config_path), check_g4(root, config_path, today), check_g5(root), check_g6(root),
        check_g7(root, config_path), check_g8(root, today), check_g9(root, today), check_g10(root, config_path, today),
        check_g11(root, config_path), check_g12(root, config_path), check_g13(root, today, config_path),
    ]


# ----------------------------------------------------------------------------- output


def render(results: list[CheckResult], *, root: Path, config_path: Path, date: str) -> str:
    counts = {s: sum(r.status == s for r in results) for s in (PASS, FAIL, MANUAL)}
    L = [f"# 治理合規檢查（{date}）", "",
         "依附錄 E 的 prompt 8，對報告第十部治理建議 G-1 到 G-13 做可自動判定的檢查。本檔由 `scripts/governance_check.py` 產生；"
         "「需人工」表示無法從檔案判定，該列的證據欄寫明需要什麼證據。任一「失敗」使腳本以非零結束。", "",
         f"- 掃描根目錄：`{root.name}/`；設定檔：`{config_path.relative_to(root) if config_path.is_relative_to(root) else config_path}`；報告與紀錄的新鮮度門檻：{FRESH_DAYS} 天。",
         "- 標準條文取自報告第 25.4 節對應總表；標 * 者的 ISO 控制項標題尚未對照正本（附錄 B）。", "",
         "| 建議 | 內容 | 狀態 | 證據 | 對應標準條文 |", "|---|---|---|---|---|"]
    for r in results:
        evidence = r.evidence.replace("|", "\\|")
        L.append(f"| {r.id} | {r.title} | **{STATUS_ZH[r.status]}** | {evidence} | {r.standards} |")
    L += ["", f"**摘要**：通過 {counts[PASS]}、失敗 {counts[FAIL]}、需人工 {counts[MANUAL]}；結束碼 {1 if counts[FAIL] else 0}。", ""]
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=ROOT)
    ap.add_argument("--config", type=Path, default=None, help="default: <root>/config/mara.yaml")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--date", default=dt.date.today().isoformat())
    args = ap.parse_args()
    root = args.root.resolve()
    config_path = (args.config or root / "config" / "mara.yaml").resolve()
    results = run_all(root, config_path, dt.date.fromisoformat(args.date))
    if args.json:
        text = json.dumps([{"id": r.id, "title": r.title, "status": r.status, "evidence": r.evidence, "standards": r.standards} for r in results],
                          ensure_ascii=False, indent=1)
    else:
        text = render(results, root=root, config_path=config_path, date=args.date)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.out}")
    print(text if not args.out else "\n".join(f"{r.id:5s} {STATUS_ZH[r.status]}" for r in results))
    return 1 if any(r.status == FAIL for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
