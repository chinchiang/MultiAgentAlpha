"""First-calibration analysis (Appendix E, prompt 4).

Reads calib-out/<sample>/report.json produced by `mara review` together with
calib/samples/<sample>/labels.json and produces docs/calibration-<date>.md with:

  - per family, per CWE precision and recall (match = same file and |line diff| <= 3)
  - per family, recall against the deterministic tools' own findings used as a second reference
    label set (assessment #10; SARIF under calib-out/<sample>/tools/, written by calibration_run.py)
  - per family refusal rate, provider error rate, canary echo rate, unverified-quote rate
  - judge family pairwise agreement (from the pipeline's bias audit) and global alpha,
    appended to calib/history.json on live runs with the delta to the previous period (assessment #49)
  - Dawid-Skene EM estimate of each judge family's reliability from the votes alone
  - the Alternative Annotator Test of the unsupervised label against human adjudications
    (assessment #60); every live result is written to calib/latest.json, and policy P8 allows
    gate.unsupervised_reject_allowed only while that result is a pass - a failing run withdraws an
    earlier pass instead of leaving it in force
  - suggested family weights, clamped to [0.2, 2.0], with the sample sizes behind them

It never edits config/mara.yaml: the suggested weights are for a human to adopt. Live runs append calib/history.json and write calib/latest.json, passing or not; commit both together with the report, since policy P8 verifies calib/latest.json from the repository.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mara.audit import by_family  # noqa: E402
from mara.decisions import Decision, TrainingRequirement, binding, select  # noqa: E402
from mara.decisions import load as load_decision_dir  # noqa: E402
from mara.identity import NEAR_LINES, norm_path, same_place  # noqa: E402
from mara.schemas import ConsensusResult  # noqa: E402
from mara.workspace import resolve  # noqa: E402


def anchor_paths() -> dict[str, Path]:
    """Where this script reads and writes MARA's own state: the workspace (MARA_HOME, else the working directory),
    the same place policy P8 and the pipeline read it. ROOT, the checkout this script lives in, used to be written
    instead, so with MARA_HOME set P8 never saw the calibration evidence written for it."""
    return {"decisions": resolve("calib/decisions"), "history": resolve("calib/history.json"), "latest": resolve("calib/latest.json")}

VERDICT_IDX = {"true_positive": 0, "false_positive": 1, "needs_human": 2}
TOOL_LABEL_TOOLS = ("semgrep", "osv-scanner", "gitleaks")


def load_decisions(decisions_dir: Path) -> list[Decision]:
    """G-11: the well-formed human decisions in calib/decisions/; damaged records are named and left out."""
    loaded = load_decision_dir(decisions_dir)
    for path, why in loaded.malformed:
        print(f"decision record {path.name} is not well-formed ({why}); not used", file=sys.stderr)
    return loaded.decisions


def apply_decisions(usable: list[Decision], labels: list[dict]) -> tuple[list[dict], int]:
    """Usable decisions (mara.decisions.select) on one sample become extra labels: a true positive adds
    the location as a label, a false positive keeps the finding counting as a false positive. Returns
    (labels, applied)."""
    applied = 0
    labels = list(labels)
    for d in usable:
        if d.decision == "true_positive" and not any(_match({"provenance": [{"file": d.file, "line": d.line}], "cwe": d.cwe}, lab) for lab in labels):
            labels.append({"dimension": "", "cwe": d.cwe, "file": d.file, "line": d.line, "quote": "",
                           "title": f"human decision on ticket #{d.issue}", "source": "human_decision"})
            applied += 1
        elif d.decision == "false_positive":
            applied += 1  # confirmed false positive: no label, the finding keeps counting as fp
    return labels, applied


def training_requirement(config: Path | None = None) -> TrainingRequirement:
    """G-13 from the MARA config (`training`), the register resolved against the workspace."""
    req = TrainingRequirement.from_config_file(config or resolve("config/mara.yaml"))
    if req.problem:
        print(f"G-13: {req.problem}; no decision counts as trained", file=sys.stderr)
    return req


def load_runs(out_dir: Path, samples_dir: Path, decisions_dir: Path | None = None,
              training: TrainingRequirement | None = None) -> list[tuple[str, dict, list[dict]]]:
    runs = []
    decisions = load_decisions(decisions_dir or anchor_paths()["decisions"])
    training = training or training_requirement()
    untrained: list[str] = []
    for rep in sorted(out_dir.glob("*/report.json")):
        sample = rep.parent.name
        labels_path = samples_dir / sample / "labels.json"
        if not labels_path.exists():
            # never score a run against someone else's labels (or none): every finding would count as a
            # false positive and every family's precision would collapse. A stale calib-out directory or
            # an unlabelled corpus (calib/corpora/* before its labels.json is written) is skipped, loudly.
            print(f"{sample}: SKIPPED, no {labels_path}; the run is not scored", file=sys.stderr)
            continue
        labels = json.loads(labels_path.read_text(encoding="utf-8"))["labels"]
        report = json.loads(rep.read_text(encoding="utf-8"))
        sel = select(decisions, report, training)
        labels, applied = apply_decisions(sel.usable, labels)
        if applied:
            print(f"{sample}: {applied} human decision(s) applied")
        untrained += [f"{sample}: ticket #{d.issue} by {d.decided_by}" for d, why in sel.excluded if why == "untrained"]
        contradicted = sel.by_reason().get("contradictory")
        if contradicted:
            print(f"{sample}: {contradicted} key(s) with contradicting decisions not applied")
        runs.append((sample, report, labels))
    if untrained:
        print(f"G-13: {len(untrained)} decision(s) by untrained adjudicators not applied: {'; '.join(untrained)}")
    return runs


def _match(f: dict, lab: dict) -> bool:
    p = f["provenance"][0]
    return same_place(p["file"], p["line"], f["cwe"], lab["file"], lab["line"], lab["cwe"])  # mara.identity: same file and weakness, lines within NEAR_LINES


def _pair_labels(findings: list[dict], labels: list[dict]) -> tuple[set[int], list[int]]:
    """Maximise one-to-one finding/label pairs; return paired label indices and findings with no candidate."""
    candidates = [[i for i, label in enumerate(labels) if _match(finding, label)] for finding in findings]
    label_to_finding: dict[int, int] = {}
    finding_to_label: dict[int, int] = {}
    for start, edges in enumerate(candidates):
        if not edges:
            continue
        # An alternating path can move an earlier finding to another label, freeing one for this finding.
        pending = [start]
        seen_findings = {start}
        parent: dict[int, int] = {}
        free_label = None
        for finding in pending:
            for label in candidates[finding]:
                if label in parent:
                    continue
                parent[label] = finding
                owner = label_to_finding.get(label)
                if owner is None:
                    free_label = label
                    break
                if owner not in seen_findings:
                    seen_findings.add(owner)
                    pending.append(owner)
            if free_label is not None:
                break
        while free_label is not None:
            finding = parent[free_label]
            previous = finding_to_label.get(finding)
            label_to_finding[free_label] = finding
            finding_to_label[finding] = free_label
            free_label = previous
    return set(label_to_finding), [i for i, edges in enumerate(candidates) if not edges]


def family_metrics(runs):
    """Per family, per CWE: tp, fp, fn (a label counts as found by a family if that family is among finder_families)."""
    stats = defaultdict(lambda: defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0}))
    # the families whose reviewers were called in each run (mara.audit reads the per-family counters back)
    reviewed = [{fam for fam, counters in by_family(rep.get("bias_audit", {})).items() if counters.get("reviewer_calls", 0) > 0}
                for _, rep, _labels in runs]
    families = set().union(*reviewed)
    for _, rep, _labels in runs:
        families |= {f for fnd in rep["findings"] for f in fnd["finder_families"]}
    for (_, rep, labels), called in zip(runs, reviewed, strict=True):
        for fam in families:
            if fam not in called and not any(fam in f.get("finder_families", []) for f in rep["findings"]):
                continue
            found = [f for f in rep["findings"] if fam in f["finder_families"]]
            matched_labels, unmatched_findings = _pair_labels(found, labels)
            for i in unmatched_findings:
                stats[fam][found[i]["cwe"]]["fp"] += 1
            for i, lab in enumerate(labels):
                stats[fam][lab["cwe"]]["tp" if i in matched_labels else "fn"] += 1
    return stats, sorted(families)


def audit_rates(runs, families):
    agg = defaultdict(lambda: defaultdict(int))
    for _, rep, _ in runs:
        for fam, counters in by_family(rep["bias_audit"]).items():
            for key, v in counters.items():
                agg[fam][key] += v
    rows = {}
    for fam in families:
        calls = agg[fam]["reviewer_calls"] or 1
        r = {
            "calls": agg[fam]["reviewer_calls"],
            "refusal_rate": agg[fam]["reviewer_refusals"] / calls,
            "error_rate": agg[fam]["reviewer_errors"] / calls,  # provider failures, kept out of the refusal rate
            "canary_rate": agg[fam]["canary_echoes"] / calls,
            "unverified_quotes": agg[fam]["findings_with_unverified_quotes"],
            "invalid": agg[fam]["invalid_findings_dropped"],
            "invalid_rate": agg[fam]["invalid_findings_dropped"] / calls,
        }
        # L3/L4 roles run per finding, not per call; report each role's refusals and invalid
        # output per family (assessment #30/#38) instead of hiding them in pipeline totals
        for role in ("skeptic", "redteam", "judge"):
            role_calls = agg[fam][f"{role}_calls"] or 1
            r[f"{role}_calls"] = agg[fam][f"{role}_calls"]
            r[f"{role}_refusal_rate"] = agg[fam][f"{role}_refusals"] / role_calls
            r[f"{role}_invalid_rate"] = agg[fam][f"{role}_invalid_items"] / role_calls
        r["skeptic_refuted"] = agg[fam]["skeptic_refuted"]
        r["skeptic_unverified_controls"] = agg[fam]["skeptic_unverified_controls"]
        rows[fam] = r
    return rows


def refutation_rates(runs, families):
    """Per family: the share of its findings the skeptic refuted (assessment #38). A family
    the skeptic keeps refuting over-reports; its suggested weight is discounted."""
    finder_count: defaultdict[str, int] = defaultdict(int)
    refuted_count: defaultdict[str, int] = defaultdict(int)
    for _, rep, _ in runs:
        refuted_ids = {v.get("finding_id") for v in rep.get("skeptic", []) if v.get("verdict") == "refuted"}
        for f in rep.get("findings", []):
            for fam in f.get("finder_families", []):
                finder_count[fam] += 1
                if f.get("id") in refuted_ids:
                    refuted_count[fam] += 1
    return {fam: (refuted_count[fam] / finder_count[fam]) if finder_count[fam] else 0.0 for fam in families}


def judge_agreement(runs):
    pair = defaultdict(list)
    alphas = []
    for _, rep, _ in runs:
        for k, v in rep["bias_audit"].items():
            if k.startswith("judge_agreement["):
                pair[k[len("judge_agreement["):-1]].append(v)
        a = rep["bias_audit"].get("global_krippendorff_alpha")
        if isinstance(a, (int, float)):
            alphas.append(a)
    return {k: sum(v) / len(v) for k, v in pair.items()}, (sum(alphas) / len(alphas) if alphas else None)


def dawid_skene(runs, iters: int = 30):
    """Unsupervised reliability of each judge family from votes only (3 classes).

    Also returns the posterior per (sample, finding_id); the Alternative Annotator Test uses its
    argmax as the pipeline's unsupervised label."""
    items = {}  # (sample, finding_id) -> {family: [verdict idx...]}
    for sample, rep, _ in runs:
        for v in rep["votes"]:
            items.setdefault((sample, v["finding_id"]), defaultdict(list))[v["judge_family"]].append(VERDICT_IDX[v["verdict"]])
    fams = sorted({f for votes in items.values() for f in votes})
    if not items or not fams:
        return {}, 0, {}
    # init: majority vote
    post = {}
    for key, votes in items.items():
        counts = [0.0, 0.0, 0.0]
        for vs in votes.values():
            for v in vs:
                counts[v] += 1
        s = sum(counts) or 1
        post[key] = [c / s for c in counts]
    conf = {f: [[1.0 / 3] * 3 for _ in range(3)] for f in fams}
    prior = [1 / 3] * 3
    for _ in range(iters):
        # M-step
        for f in fams:
            m = [[0.1] * 3 for _ in range(3)]  # smoothing
            for key, votes in items.items():
                for v in votes.get(f, []):
                    for t in range(3):
                        m[t][v] += post[key][t]
            conf[f] = [[x / sum(row) for x in row] for row in m]
        tot = [sum(post[k][t] for k in items) for t in range(3)]
        prior = [t / sum(tot) for t in tot]
        # E-step
        for key, votes in items.items():
            p = list(prior)
            for f, vs in votes.items():
                for v in vs:
                    for t in range(3):
                        p[t] *= conf[f][t][v]
            s = sum(p) or 1
            post[key] = [x / s for x in p]
    # reliability = P(vote TP | truth TP) * P(vote FP | truth FP), a simple diagonal summary
    rel = {f: round((conf[f][0][0] + conf[f][1][1]) / 2, 3) for f in fams}
    return rel, len(items), post


def _binomial_pmf(i: int, n: int, p: float) -> float:
    from math import comb

    return comb(n, i) * p**i * (1 - p) ** (n - i)


def binomial_upper_tail(k: int, n: int, p: float) -> float:
    """P(X >= k) for X ~ Binomial(n, p): the exact one-sided test of agreement above chance."""
    return min(1.0, sum(_binomial_pmf(i, n, p) for i in range(k, n + 1)))


def clopper_pearson_upper(k: int, n: int, confidence: float = 0.95) -> float:
    """Exact one-sided upper confidence bound of a binomial proportion with k events in n trials:
    the p at which P(X <= k) falls to 1 - confidence (bisection; 1 - (1-confidence)**(1/n) for k = 0)."""
    if n <= 0 or k >= n:
        return 1.0
    lo, hi = k / n, 1.0
    for _ in range(80):
        mid = (lo + hi) / 2
        if sum(_binomial_pmf(i, n, mid) for i in range(k + 1)) > 1 - confidence:
            lo = mid
        else:
            hi = mid
    return hi


def alternative_annotator_test(runs, decisions: list[Decision], post, training: TrainingRequirement, *,
                               min_items: int = 10, min_agreement: float = 0.8,
                               max_miss_rate: float = 0.05, confidence: float = 0.95) -> dict:
    """Assessment #60: the evidence policy P8 needs before the pipeline may reject a non-D finding
    without a human. Both parts must pass.

    1. Agreement beyond chance. The unsupervised label (Dawid-Skene posterior argmax) against the
       human decision on every bound item where the pipeline did not abstain: agreement >=
       min_agreement on >= min_items items, and the exact one-sided binomial test against the chance
       agreement of the two label distributions (as in Cohen's kappa; not a fixed 0.5) at p < 0.05.
       A labeller that always gives the same answer agrees exactly at chance and never passes, however
       lopsided the human decisions are.
    2. Rejection safety, the decision P8 actually unlocks. Among bound items whose jury outcome is
       rejected (docs/adr/0005-jury-outcome.md: evidence enough to stand, but the jury did not carry
       them; dropped tier D findings are out on the evidence and not counted), a human true_positive
       is a vulnerability the pipeline would have rejected unsupervised. The exact one-sided Clopper-Pearson upper bound of that miss
       rate at `confidence` must be <= max_miss_rate; with no miss at all that takes
       ceil(ln(1 - confidence) / ln(1 - max_miss_rate)) decided rejections (59 at 0.95 / 0.05).

    A single-adjudicator variant: each finding carries one human decision, so the published
    leave-one-annotator-out procedure (several annotators per item) does not apply. Decisions bind
    to findings by their v2 queue key (primary location, CWE, target, revision, context hash), one
    decision per finding, never by line proximity; only usable decisions count (mara.decisions:
    contradicted keys and, under G-13, untrained adjudicators are excluded, with the reason in
    `excluded_by_reason`). Every live result goes to calib/latest.json; policy P8
    accepts only a passing result tagged with this method (mara.policy.AAT_METHOD)."""
    from mara.human_queue import queue_key
    from mara.policy import AAT_METHOD

    pairs: list[tuple[bool, bool]] = []  # (pipeline says true_positive, human says true_positive)
    rejected = misses = 0
    left_out: Counter[str] = Counter()
    for sample, rep, _labels in runs:
        ident = binding(rep)
        if ident is None:
            continue
        target_id, revision, ctx = ident
        sel = select(decisions, rep, training)
        left_out.update({why: n for why, n in sel.by_reason().items() if why != "unbound"})
        verdict_by_key = {d.key: d.decision for d in sel.usable}
        # every row is validated before anything is counted (docs/adr/0005-jury-outcome.md): a row that does not
        # validate stops the test rather than being guessed into, or silently left out of, the count (fail closed)
        consensus = {c.finding_id: c for c in map(ConsensusResult.model_validate, rep.get("consensus", []))}
        for f in rep.get("findings", []):
            p = f["provenance"][0]
            verdict = verdict_by_key.get(queue_key(p["file"], int(p["line"]), f["cwe"], target_id=target_id,
                                                   revision=revision, context_hash=ctx))
            if verdict is None:
                continue
            human_tp = verdict == "true_positive"
            c = consensus.get(f["id"])
            if c is not None and c.jury_outcome == "rejected":
                rejected += 1
                misses += int(human_tp)
            posterior = post.get((sample, f["id"]))
            argmax = max(range(3), key=lambda t: posterior[t]) if posterior else None
            if argmax is None or argmax == VERDICT_IDX["needs_human"]:
                left_out["pipeline_abstained"] += 1  # there is no unsupervised label to test
                continue
            pairs.append((argmax == VERDICT_IDX["true_positive"], human_tp))
    upper = clopper_pearson_upper(misses, rejected, confidence) if rejected else None
    rejection = {"n": rejected, "misses": misses, "miss_rate_upper": round(upper, 4) if upper is not None else None,
                 "max_miss_rate": max_miss_rate, "confidence": confidence,
                 "passed": bool(upper is not None and upper <= max_miss_rate)}
    out = {"method": AAT_METHOD, "excluded": sum(left_out.values()), "excluded_by_reason": dict(sorted(left_out.items())),
           "min_items": min_items, "min_agreement": min_agreement,
           "rejection": rejection}
    n = len(pairs)
    if n == 0:
        return {**out, "n": 0, "agreement": None, "chance_agreement": None, "kappa": None, "p_value": None,
                "agreement_passed": False, "passed": False,
                "why": "沒有可對照的人工裁決（calib/decisions/ 為空，或沒有裁決綁定到本次樣本）"}
    agree = sum(a == b for a, b in pairs)
    q_pipe, q_human = sum(a for a, _ in pairs) / n, sum(b for _, b in pairs) / n
    chance = q_pipe * q_human + (1 - q_pipe) * (1 - q_human)
    observed = agree / n
    kappa = (observed - chance) / (1 - chance) if chance < 1 else 0.0
    p_value = binomial_upper_tail(agree, n, chance)
    agreement_passed = bool(n >= min_items and observed >= min_agreement and p_value < 0.05)
    why = []
    if not agreement_passed:
        why.append(f"一致性未達（n={n}、一致率 {observed:.4f}、機遇一致率 {chance:.4f}、單尾 p={p_value:.4f}）")
    if not rejection["passed"]:
        why.append(f"不採納安全性未達（{rejected} 筆無監督不採納經人工裁決，其中 {misses} 筆為真陽性；"
                   f"漏放率 {confidence:.0%} 上界 {rejection['miss_rate_upper']} 須 ≤ {max_miss_rate}）")
    return {**out, "n": n, "agreement": round(observed, 4), "chance_agreement": round(chance, 4), "kappa": round(kappa, 4),
            "p_value": round(p_value, 4), "agreement_passed": agreement_passed,
            "passed": bool(agreement_passed and rejection["passed"]), **({"why": "；".join(why)} if why else {})}


def load_history(path: Path) -> list[dict]:
    try:
        hist = json.loads(path.read_text(encoding="utf-8"))
        return hist if isinstance(hist, list) else []
    except (OSError, ValueError):
        return []


def exchange_version(runs) -> int:
    """The reply accounting the runs were made with (mara.exchange.EXCHANGE_VERSION; reports without it are
    version 1). Refusal, invalid and truncation counts of different versions are not comparable
    (docs/adr/0001-reply-outcome-accounting.md), so one calibration never mixes them."""
    versions = {int(rep.get("bias_audit", {}).get("exchange_version", 1)) for _, rep, _ in runs}
    if len(versions) > 1:
        raise SystemExit(f"the reviews were made with different exchange versions {sorted(versions)}: re-run them with one MARA version")
    return versions.pop() if versions else 1


def comparable_history(history: list[dict], version: int) -> list[dict]:
    """The earlier periods recorded with the same exchange version (rows without one are version 1)."""
    return [h for h in history if int(h.get("exchange_version", 1)) == version]


def append_history(path: Path, date: str, mode: str, alpha, pair: dict, version: int = 1) -> None:
    """Assessment #49: keep alpha and judge agreement comparable across quarters. Live runs only —
    mock numbers verify the method, they are not a quality time series. Each row records its exchange
    version; the trend compares only rows of one version."""
    if mode != "live" or alpha is None:
        return
    hist = load_history(path)
    hist = [h for h in hist if not (h.get("date") == date and h.get("mode") == mode)]
    hist.append({"date": date, "mode": mode, "exchange_version": version, "global_alpha": round(alpha, 4),
                 "judge_agreement": {k: round(v, 4) for k, v in sorted(pair.items())}})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(hist, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_tool_labels(out_dir: Path, tools: tuple[str, ...] = TOOL_LABEL_TOOLS) -> dict[str, dict[str, list]]:
    """Assessment #10: per-sample deterministic-tool SARIF, written by calibration_run.py under
    calib-out/<sample>/tools/ — deliberately outside the sample directory, so the reference labels
    can never leak into a later review's bundle."""
    from mara.tools.sarif import read_sarif

    out: dict[str, dict[str, list]] = {}
    if not out_dir.is_dir():
        return out
    for sample_dir in sorted(p for p in out_dir.iterdir() if p.is_dir()):
        tools_dir = sample_dir / "tools"
        if not tools_dir.is_dir():
            continue
        per: dict[str, list] = {}
        for tool in tools:
            sarif = tools_dir / f"{tool}.sarif"
            if sarif.is_file():
                try:
                    per[tool] = read_sarif(sarif, tool_hint=tool)
                except (OSError, ValueError):
                    per[tool] = []
        if per:
            out[sample_dir.name] = per
    return out


def tool_recall(runs, tool_labels):
    """Assessment #10: per family recall against the tools' findings. A tool finding counts as
    covered by a family when some finding of that family sits on the same file within 3 lines
    (tool SARIF names no CWE, so the match is location-only). Returns {family: {tool: {found, total}}}."""
    fams = sorted({f for _, rep, _ in runs for fnd in rep.get("findings", []) for f in fnd.get("finder_families", [])})
    tools = sorted({t for per in tool_labels.values() for t in per})
    rows = {fam: {t: {"found": 0, "total": 0} for t in tools} for fam in fams}
    for sample, rep, _ in runs:
        per_tool = tool_labels.get(sample, {})
        if not per_tool:
            continue
        by_fam: dict[str, list[tuple[str, int]]] = defaultdict(list)
        for f in rep.get("findings", []):
            p = f["provenance"][0]
            for fam in f.get("finder_families", []):
                by_fam[fam].append((norm_path(p["file"]), int(p["line"])))
        for fam in fams:
            locs = by_fam.get(fam, [])
            for tool, results in per_tool.items():
                for r in results:
                    rows[fam][tool]["total"] += 1
                    if any(x[0] == norm_path(r.file) and abs(x[1] - r.line) <= NEAR_LINES for x in locs):
                        rows[fam][tool]["found"] += 1
    return rows


def load_model_eval() -> dict | None:
    """G-8: latest calib/model-eval-<date>.json (garak / CyberSecEval verdicts per family), in the workspace
    where scripts/model_eval.py writes it and the pipeline reads it into the report's model_eval."""
    from mara.model_eval import latest_summary
    from mara.workspace import root as workspace_root

    return latest_summary(workspace_root())


def _penalty() -> float:
    try:
        import yaml

        raw = yaml.safe_load((ROOT / "config" / "mara.yaml").read_text(encoding="utf-8")) or {}
        return float((raw.get("model_eval") or {}).get("weight_penalty_on_fail", 0.8))
    except (OSError, ValueError):
        return 0.8


def suggest_weights(stats, rel, families, model_eval: dict | None = None, penalty: float | None = None,
                    rates: dict | None = None, refuted_rates: dict | None = None):
    penalty = _penalty() if penalty is None else penalty
    out = {}
    for fam in families:
        tp = sum(c["tp"] for c in stats[fam].values())
        fp = sum(c["fp"] for c in stats[fam].values())
        fn = sum(c["fn"] for c in stats[fam].values())
        prec = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * recall / (prec + recall) if prec + recall else 0.0
        supervised = 0.5 + f1  # 0.5..1.5
        unsup = rel.get(fam, 0.5) * 2  # 0..2
        w = max(0.2, min(2.0, round(0.6 * supervised + 0.4 * unsup, 2)))
        # skeptic refutations discount an over-reporting family before any other factor (#38)
        refuted = (refuted_rates or {}).get(fam, 0.0)
        if refuted:
            w = round(w * (1 - refuted), 2)
        # chronically unusable output (invalid shapes, dropped findings) discounts the family too
        r = (rates or {}).get(fam, {})
        invalid_rate = max([r.get(k, 0.0) for k in ("invalid_rate", "skeptic_invalid_rate", "judge_invalid_rate", "redteam_invalid_rate")] or [0.0])
        if invalid_rate > 0.10:
            w = round(w * 0.8, 2)
        verdict = ((model_eval or {}).get("families", {}).get(fam) or {}).get("verdict", {}).get("overall", "none")
        penalised = verdict == "fail"
        if penalised:
            w = round(w * penalty, 2)
        w = max(0.2, min(2.0, w))
        out[fam] = {"precision": prec, "recall": recall, "f1": f1, "n_labels": tp + fn, "ds_reliability": rel.get(fam), "weight": w,
                    "model_eval": verdict, "penalised": penalised, "skeptic_refuted_rate": round(refuted, 3),
                    "invalid_output_rate": round(invalid_rate, 3), "invalid_discounted": invalid_rate > 0.10}
    return out


def front_matter(mode: str, date: str, families, runs, model_eval: dict | None, tool_labels: int = 0) -> str:
    import yaml

    meta = {"report": "calibration", "date": date, "mode": mode, "families": list(families),
            "samples": [s for s, _, _ in runs], "labels": sum(len(labs) for _, _, labs in runs),
            "tool_labels": tool_labels,
            "provider_modes": sorted({rep.get("provider_mode", "?") for _, rep, _ in runs}),
            "model_eval": (model_eval or {}).get("date"), "governance": "G-9"}
    return "---\n" + yaml.safe_dump(meta, sort_keys=False, allow_unicode=True) + "---\n"


_EXCLUDED_REASONS = {"pipeline_abstained": "無監督標籤為 needs_human", "contradictory": "人工裁決互相矛盾",
                     "untrained": "裁決者未受訓（G-13）"}


def _excluded_reasons(aat: dict) -> str:
    by = aat.get("excluded_by_reason") or {}
    return "：" + "、".join(f"{_EXCLUDED_REASONS.get(k, k)} {n}" for k, n in by.items()) if by else ""


def render(runs, stats, families, rates, pair, alpha, rel, n_items, weights, mode: str, date: str | None = None,
           model_eval: dict | None = None, aat: dict | None = None, history: list[dict] | None = None,
           tool_recall_rows: dict | None = None, tool_labels: int = 0, version: int = 1) -> str:
    today = date or dt.date.today().isoformat()
    L = [front_matter(mode, today, families, runs, model_eval, tool_labels),
         f"# 校準報告（{today}）", "",
         f"執行模式：**{mode}**。" + (" 本次以 mock 家族跑通校準迴圈，數字只驗證方法，不代表任何真實模型。" if mode == "mock" else ""),
         f"樣本：{', '.join(s for s, _, _ in runs)}（共 {sum(len(labs) for _, _, labs in runs)} 個標籤）。", "",
         "## 1. 每家族每 CWE 的精確度與召回率", ""]
    for fam in families:
        L += [f"### {fam}", "", "| CWE | TP | FP | FN | Precision | Recall |", "|---|---:|---:|---:|---:|---:|"]
        for cwe in sorted(stats[fam]):
            c = stats[fam][cwe]
            p = c["tp"] / (c["tp"] + c["fp"]) if c["tp"] + c["fp"] else 0.0
            r = c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else 0.0
            L.append(f"| {cwe} | {c['tp']} | {c['fp']} | {c['fn']} | {p:.2f} | {r:.2f} |")
        w = weights[fam]
        L += ["", f"合計：precision {w['precision']:.2f}、recall {w['recall']:.2f}、F1 {w['f1']:.2f}（標籤數 {w['n_labels']}）", ""]
    tools = sorted({t for per in (tool_recall_rows or {}).values() for t in per})
    if tools:
        def _cell(fam: str, tool: str) -> str:
            c = (tool_recall_rows.get(fam) or {}).get(tool) or {"found": 0, "total": 0}
            if not c["total"]:
                return "n/a"
            return f"{c['found']}/{c['total']}（{c['found'] / c['total']:.2f}）"

        L += ["## 1a. 工具結果作為第二組參考標籤（assessment #10）", "",
              "calibration_run.py 對每個樣本以鎖定的 semgrep／osv-scanner／gitleaks 掃描，SARIF 存在 `calib-out/<sample>/tools/`",
              "（刻意不放在樣本目錄內，避免參考標籤洩漏進下一次審查的 bundle）。下表是每個家族對工具 finding 的召回率：",
              "工具 finding 被視為「該家族也報告了」當該家族的某個 finding 落在同一檔案 ±3 行內（工具 SARIF 不帶 CWE，僅以位置比對）。",
              "工具結果不是真值，只是第二組參考；離線主機上 osv-scanner 可能缺席。", "",
              "| 家族 | " + " | ".join(tools) + " |", "|---" + "|---:" * len(tools) + "|"]
        for fam in families:
            L.append(f"| {fam} | " + " | ".join(_cell(fam, t) for t in tools) + " |")
        L.append("")
    L += ["## 2. 拒答率、canary 回應率、無效輸出", "", "| 家族 | 呼叫數 | 拒答率 | provider 錯誤率 | canary 回應率 | 未驗證引用 | 無效 finding |", "|---|---:|---:|---:|---:|---:|---:|"]
    for fam in families:
        r = rates.get(fam, {})
        L.append(f"| {fam} | {r.get('calls', 0)} | {r.get('refusal_rate', 0):.2f} | {r.get('error_rate', 0):.2f} | {r.get('canary_rate', 0):.2f} | {r.get('unverified_quotes', 0)} | {r.get('invalid', 0)} |")
    L += ["", "### 2.1 L3/L4 每角色拒答與無效輸出（每家族）", "",
          "L3/L4 以 finding 為單位呼叫；拒答（模型拒絕輸出）與無效輸出（格式或引用不可用）分開計數，",
          "refuted 但控制項引用無法在 bundle 中定位的 skeptic 裁決已降級為 weakened 並計入「未驗證控制」。", "",
          "| 家族 | skeptic 呼叫 | skeptic 拒答率 | skeptic 無效率 | 未驗證控制 | skeptic 否證數 | redteam 呼叫 | redteam 拒答率 | redteam 無效率 | judge 呼叫 | judge 拒答率 | judge 無效率 |",
          "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for fam in families:
        r = rates.get(fam, {})
        L.append(
            f"| {fam} | {r.get('skeptic_calls', 0)} | {r.get('skeptic_refusal_rate', 0):.2f} | {r.get('skeptic_invalid_rate', 0):.2f} | "
            f"{r.get('skeptic_unverified_controls', 0)} | {r.get('skeptic_refuted', 0)} | {r.get('redteam_calls', 0)} | "
            f"{r.get('redteam_refusal_rate', 0):.2f} | {r.get('redteam_invalid_rate', 0):.2f} | {r.get('judge_calls', 0)} | "
            f"{r.get('judge_refusal_rate', 0):.2f} | {r.get('judge_invalid_rate', 0):.2f} |"
        )
    L += ["", "## 3. judge 家族兩兩一致率與全域 α", "", "| 家族對 | 一致率（樣本平均） | 相關錯誤風險 |", "|---|---:|---|"]
    for k, v in sorted(pair.items()):
        L.append(f"| {k} | {v:.3f} | {'**高（>0.9）**' if v > 0.9 else '可接受'} |")
    L += ["", f"全域 Krippendorff's α（樣本平均）：{alpha:.3f}" if alpha is not None else "全域 α：n/a", "",
          "## 4. Dawid-Skene 無監督可靠度（僅用投票，不看標籤）", "", f"項目數 {n_items}", "", "| 家族 | 可靠度 |", "|---|---:|"]
    for fam, v in sorted(rel.items()):
        L.append(f"| {fam} | {v:.3f} |")
    L += ["", "## 5. 建議家族權重（0.2–2.0；0.6×監督 F1 + 0.4×DS 可靠度；先按被否證率折抵，無效率>10% 再 ×0.8，G-8 未達門檻者再乘以懲罰係數）", "",
          "| 家族 | precision | recall | F1 | DS 可靠度 | 被否證率 | 無效率 | G-8 評測 | 建議權重 | 標籤數 |", "|---|---:|---:|---:|---:|---:|---:|---|---:|---:|"]
    for fam in families:
        w = weights[fam]
        ev = w.get("model_eval", "none")
        if w.get("penalised"):
            ev += "（已懲罰）"
        if w.get("invalid_discounted"):
            ev += "（無效率懲罰）"
        L.append(f"| {fam} | {w['precision']:.2f} | {w['recall']:.2f} | {w['f1']:.2f} | "
                 f"{w['ds_reliability'] if w['ds_reliability'] is not None else 'n/a'} | {w.get('skeptic_refuted_rate', 0):.2f} | "
                 f"{w.get('invalid_output_rate', 0):.2f} | {ev} | **{w['weight']}** | {w['n_labels']} |")
    L += ["", "權重未自動寫入 `config/mara.yaml`；採用與否由人決定。標籤數低於 30 的家族權重只能視為方向，不能視為量測。", ""]
    L += ["## 6. 模型紅隊評測（G-8：garak 與 CyberSecEval 4）", ""]
    if model_eval:
        th = model_eval.get("thresholds", {})
        L += [f"最近一次：{model_eval['date']}（mode {model_eval['mode']}，garak {model_eval.get('garak_version')}，"
              f"CyberSecEval {model_eval.get('cyberseceval_ref')}）。門檻：garak pass rate ≥ {th.get('garak_pass_rate_min')}、"
              f"注入成功率 ≤ {th.get('prompt_injection_success_max')}、FRR ≤ {th.get('false_refusal_max')}。", "",
              "| 家族 | garak pass rate | 注入成功率 | FRR | 判定 |", "|---|---:|---:|---:|---|"]
        for fam, f in model_eval.get("families", {}).items():
            v = f.get("verdict", {})
            cells = ["n/a" if v.get(k, {}).get("value") is None else f"{v[k]['value']:.3f}"
                     for k in ("garak_pass_rate", "prompt_injection_success", "false_refusal")]
            L.append(f"| {fam} | {cells[0]} | {cells[1]} | {cells[2]} | {v.get('overall', 'missing')} |")
        if model_eval.get("mode") != "live":
            L += ["", "**該評測不是對真實端點的執行結果（mode ≠ live），不滿足 G-8；權重懲罰仍依其判定套用以示範機制。**"]
    else:
        L.append("尚無 `calib/model-eval-<date>.json`：G-8 從未執行，權重未受評測結果調整。")
    L += ["", "## 7. Alternative Annotator Test（無監督「不採納」的驗收門檻，assessment #60）", "",
          "報告第 15.3 節與 G-9 要求：在允許管線無監督地「不採納」之前，須以 `calib/decisions/` 的人工裁決為對照，兩項都要通過：",
          "",
          "1. **一致性**：管線的無監督標籤（Dawid-Skene 後驗 argmax）與人工裁決的一致率 ≥ 0.8、n ≥ 10，且以兩邊標籤分布算出的"
          "機遇一致率（同 Cohen's kappa）為基準的單尾二項檢定 p < 0.05；永遠給同一個答案的標註者只會剛好等於機遇值，不會通過。",
          "2. **不採納安全性**：在管線本身會無監督不採納的 finding（共識不採納、沒有其他送人工的理由、非 D 級，也就是 P8 實際放行的那批）中，"
          "人工判為真陽性者即為漏放；漏放率的 Clopper-Pearson 單尾 95% 上界須 ≤ 0.05，零漏放也至少要 59 筆裁決。",
          "",
          "裁決以 v2 key 一對一綁定 finding（不以行號鄰近比對）。每個 finding 只有一位裁決者，因此這是單一裁決者版本，"
          "不是需要多位標註者的 leave-one-annotator-out 原版。每次 live 校準都把結果（含方法標記）寫入 `calib/latest.json`，未通過的結果會撤銷先前的通過；"
          "只有通過的結果，政策 P8 才允許 `gate.unsupervised_reject_allowed: true`；在此之前，非 D 級的「不採納」一律進人工佇列。", ""]
    if aat is None or not aat.get("n"):
        why = (aat or {}).get("why") or "本次沒有可對照的人工裁決。"
        L += [f"本次結果：**未通過**（{why}）管線的所有「不採納」繼續由人工抽查。", ""]
    else:
        verdict = "**通過**" if aat.get("passed") else "**未通過**"
        rej = aat.get("rejection") or {}
        L += [f"本次結果：{verdict}。", "",
              f"- 一致性{'通過' if aat.get('agreement_passed') else '未通過'}：n={aat['n']}、一致率 {aat['agreement']}、"
              f"機遇一致率 {aat.get('chance_agreement')}、kappa {aat.get('kappa')}、單尾 p 值 {aat['p_value']}"
              f"（門檻：n ≥ {aat.get('min_items', 10)}、一致率 ≥ {aat.get('min_agreement', 0.8)}、p < 0.05；"
              f"{aat.get('excluded', 0)} 個項目未納入{_excluded_reasons(aat)}）。",
              f"- 不採納安全性{'通過' if rej.get('passed') else '未通過'}：{rej.get('n', 0)} 筆無監督不採納經人工裁決，"
              f"其中 {rej.get('misses', 0)} 筆為真陽性；漏放率上界 {rej.get('miss_rate_upper')}"
              f"（門檻 ≤ {rej.get('max_miss_rate', 0.05)}，信賴水準 {rej.get('confidence', 0.95)}）。", ""]
    L += ["## 8. α 跨期追蹤（assessment #49）", ""]
    if mode != "live":
        L += ["僅 live 校準寫入 `calib/history.json`；本次為 mock，數字只驗證方法，不追加、不比較。", ""]
    elif not comparable_history(history or [], version) or alpha is None:
        other = len(history or []) - len(comparable_history(history or [], version))
        L += ["尚無跨期紀錄：這是第一次 live 校準（或本次缺 α），`calib/history.json` 從下次起可比較。"
              if not other else
              f"沒有同一 exchange 版本（v{version}）的前期紀錄：`calib/history.json` 的 {other} 筆前期紀錄以另一版的回覆計數方式產生"
              "（docs/adr/0001-reply-outcome-accounting.md），拒答、無效與截斷的數字不可比較，本次為此版本的第一期。", ""]
    else:
        history = comparable_history(history or [], version)
        prev = history[-1]
        delta = round(alpha - prev["global_alpha"], 4)
        L += ["| 日期 | 全域 α |", "|---|---:|"]
        for h in history[-5:]:
            L.append(f"| {h['date']} | {h['global_alpha']:.4f} |")
        L += [f"| {today}（本次） | {alpha:.4f} |", "",
              f"與前期（{prev['date']}）差值：**{delta:+.4f}**。"]
        if delta <= -0.1:
            L += ["", "**α 較上次 live 校準下降超過 0.1 — 採用本次建議權重前，先調查 panel 組成、模型版本或提示詞的變更。**"]
        prev_pair = prev.get("judge_agreement") or {}
        if prev_pair:
            L += ["", "| 家族對 | 本次一致率 | 前期 | 差值 |", "|---|---:|---:|---:|"]
            for k in sorted(pair):
                pv = prev_pair.get(k)
                L.append(f"| {k} | {pair[k]:.3f} | {pv:.3f} | {pair[k] - pv:+.3f} |" if pv is not None
                         else f"| {k} | {pair[k]:.3f} | n/a | n/a |")
        L.append("")
    L += ["## 9. 如何重跑（真實模型）", "", "```bash",
          "python3 scripts/calibration_run.py --mode live --config config/mara.yaml   # check-config → mara review 每個樣本 → calibrate --mode live",
          "```", ""]
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="calib-out")
    ap.add_argument("--samples-dir", default="calib/samples")
    ap.add_argument("--mode", default="mock", choices=["mock", "live"])
    ap.add_argument("--report", default=None)
    ap.add_argument("--date", default=None, help="YYYY-MM-DD (default: today)")
    ap.add_argument("--config", default=None, help="MARA config whose `training` block applies G-13 (default: <workspace>/config/mara.yaml)")
    args = ap.parse_args()
    try:
        when = dt.date.fromisoformat(args.date) if args.date else dt.date.today()
    except ValueError:
        raise SystemExit(f"--date must be YYYY-MM-DD, got {args.date!r}") from None
    if when > dt.date.today():
        # the date names the report, calib/latest.json and the history row; policy P8 and governance
        # checks G-8/G-9 measure freshness from it, so a future date would keep stale evidence "fresh"
        raise SystemExit(f"--date {when.isoformat()} is in the future; a calibration records a run that happened")
    date = when.isoformat()
    out_dir = Path(args.out_dir) if Path(args.out_dir).is_absolute() else ROOT / args.out_dir
    samples_dir = Path(args.samples_dir) if Path(args.samples_dir).is_absolute() else ROOT / args.samples_dir
    training = training_requirement(Path(args.config) if args.config else None)
    runs = load_runs(out_dir, samples_dir, training=training)
    if not runs:
        raise SystemExit("no calib-out/*/report.json found; run `mara review` on the samples first")
    modes = sorted({rep.get("provider_mode", "?") for _, rep, _ in runs})
    if args.mode == "live" and modes != ["live"]:
        raise SystemExit(f"--mode live refused: the runs under {out_dir} were produced in provider mode(s) {modes}; a mock run cannot be labelled live")
    if args.mode == "live":
        for _, rep, _ in runs:
            manifest = rep.get("provider_manifest", [])
            if (not manifest or any(p.get("type") not in {"anthropic", "bedrock", "gemini", "openai_compatible"} for p in manifest)
                    or not rep.get("config_hash") or not rep.get("revision")):
                raise SystemExit("--mode live refused: missing or non-live provider provenance")
        leaked = sorted(s for s, rep, _ in runs if "labels.json" in (rep.get("coverage") or {}).get("included", []))
        if leaked:
            # defence in depth behind repo_map's calibration_answer_key exclusion: a run made before it
            # (or by a build without it) showed the models the answer key, so its numbers are worthless
            raise SystemExit(f"--mode live refused: the answer key labels.json was in the reviewed bundle of {leaked}; "
                             "re-run the reviews with this version (scripts/calibration_run.py)")
    stats, families = family_metrics(runs)
    rates = audit_rates(runs, families)
    refuted = refutation_rates(runs, families)
    pair, alpha = judge_agreement(runs)
    rel, n_items, post = dawid_skene(runs)
    model_eval = load_model_eval()
    weights = suggest_weights(stats, rel, families, model_eval, rates=rates, refuted_rates=refuted)
    anchors = anchor_paths()
    aat = alternative_annotator_test(runs, load_decisions(anchors["decisions"]), post, training)
    tool_labels = load_tool_labels(out_dir)
    recall_rows = tool_recall(runs, tool_labels)
    history_path = anchors["history"]
    history = load_history(history_path)
    version = exchange_version(runs)
    n_tool_labels = sum(len(rs) for per in tool_labels.values() for rs in per.values())
    text = render(runs, stats, families, rates, pair, alpha, rel, n_items, weights, args.mode, date, model_eval,
                  aat=aat, history=history, tool_recall_rows=recall_rows, tool_labels=n_tool_labels,
                  version=version)
    out = Path(args.report) if args.report else ROOT / "docs" / f"calibration-{date}.md"
    out.write_text(text, encoding="utf-8")
    append_history(history_path, date, args.mode, alpha, pair, version)
    if args.mode == "live":
        latest = anchors["latest"]
        latest.write_text(
            json.dumps({"date": date, "mode": args.mode, "aat": aat, "global_alpha": alpha}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    print(f"wrote {out}")
    print(f"AAT: n={aat['n']} agreement={aat.get('agreement')} chance={aat.get('chance_agreement')} p={aat.get('p_value')} "
          f"rejections={aat['rejection']['n']} misses={aat['rejection']['misses']} miss_upper={aat['rejection']['miss_rate_upper']} "
          f"passed={aat['passed']}"
          + (f"（{aat['why']}）" if aat.get("why") else ""))
    print(f"tool reference labels: {n_tool_labels} finding(s) from {len(tool_labels)} sample(s)")
    for fam in families:
        w = weights[fam]
        print(f"{fam:10s} P={w['precision']:.2f} R={w['recall']:.2f} F1={w['f1']:.2f} DS={w['ds_reliability']} weight={w['weight']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
