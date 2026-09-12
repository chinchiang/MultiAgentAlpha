"""First-calibration analysis (Appendix E, prompt 4).

Reads calib-out/<sample>/report.json produced by `mara review` together with
calib/samples/<sample>/labels.json and produces docs/calibration-<date>.md with:

  - per family, per CWE precision and recall (match = same file and |line diff| <= 3)
  - per family refusal rate, canary echo rate, unverified-quote rate
  - judge family pairwise agreement (from the pipeline's bias audit) and global alpha
  - Dawid-Skene EM estimate of each judge family's reliability from the votes alone
  - suggested family weights, clamped to [0.2, 2.0], with the sample sizes behind them

It never edits config/mara.yaml: the suggested weights are for a human to adopt.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERDICT_IDX = {"true_positive": 0, "false_positive": 1, "needs_human": 2}


def load_decisions(decisions_dir: Path) -> list[dict]:
    """G-11: human decisions written back from closed queue tickets (calib/decisions/<key>.json)."""
    out = []
    if not decisions_dir.is_dir():
        return out
    for p in sorted(decisions_dir.glob("*.json")):
        if p.name == "backlog.json":
            continue
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if d.get("decision") in ("true_positive", "false_positive") and d.get("file") and d.get("cwe"):
            out.append(d)
    return out


def apply_decisions(sample: str, report: dict, labels: list[dict], decisions: list[dict],
                    require_trained: bool = True) -> tuple[list[dict], int]:
    """true_positive decisions on this sample's target become extra labels; returns (labels, applied).
    With require_trained (G-13), a decision whose adjudicator held no valid training record when it
    was synced is skipped and counted in SKIPPED_UNTRAINED."""
    target = report.get("target", "")
    applied = 0
    labels = list(labels)
    for d in decisions:
        d_target = str(d.get("target", "")).rstrip("/")
        if not (d_target == target.rstrip("/") or d_target.endswith("/" + sample)):
            continue
        if require_trained and not d.get("adjudicator_trained"):
            SKIPPED_UNTRAINED.append(f"{sample}: ticket #{d.get('issue')} by {d.get('decided_by') or 'unknown'}")
            continue
        if d["decision"] == "true_positive" and not any(_match({"provenance": [{"file": d["file"], "line": d["line"]}], "cwe": d["cwe"]}, lab) for lab in labels):
            labels.append({"dimension": "", "cwe": d["cwe"], "file": d["file"], "line": int(d["line"]), "quote": "",
                           "title": f"human decision on ticket #{d.get('issue')}", "source": "human_decision"})
            applied += 1
        elif d["decision"] == "false_positive":
            applied += 1  # confirmed false positive: no label, the finding keeps counting as fp
    return labels, applied


SKIPPED_UNTRAINED: list[str] = []


def _require_trained() -> bool:
    try:
        import yaml

        raw = yaml.safe_load((ROOT / "config" / "mara.yaml").read_text(encoding="utf-8")) or {}
        return bool((raw.get("training") or {}).get("require_trained_adjudicator", True))
    except (OSError, ValueError):
        return True


def load_runs(out_dir: Path, samples_dir: Path, decisions_dir: Path | None = None, require_trained: bool | None = None) -> list[tuple[str, dict, list[dict]]]:
    runs = []
    decisions = load_decisions(decisions_dir or (ROOT / "calib" / "decisions"))
    require_trained = _require_trained() if require_trained is None else require_trained
    for rep in sorted(out_dir.glob("*/report.json")):
        sample = rep.parent.name
        labels_path = samples_dir / sample / "labels.json"
        if not labels_path.exists():
            labels_path = ROOT / "fixtures" / "vuln-sample" / "labels.json"
        labels = json.loads(labels_path.read_text(encoding="utf-8"))["labels"] if labels_path.exists() else []
        report = json.loads(rep.read_text(encoding="utf-8"))
        labels, applied = apply_decisions(sample, report, labels, decisions, require_trained)
        if applied:
            print(f"{sample}: {applied} human decision(s) applied")
        runs.append((sample, report, labels))
    if SKIPPED_UNTRAINED:
        print(f"G-13: {len(SKIPPED_UNTRAINED)} decision(s) by untrained adjudicators not applied: {'; '.join(SKIPPED_UNTRAINED)}")
    return runs


def _match(f: dict, lab: dict) -> bool:
    p = f["provenance"][0]
    return p["file"].lstrip("./") == lab["file"].lstrip("./") and abs(int(p["line"]) - int(lab["line"])) <= 3 and f["cwe"] == lab["cwe"]


def family_metrics(runs):
    """Per family, per CWE: tp, fp, fn (a label counts as found by a family if that family is among finder_families)."""
    stats = defaultdict(lambda: defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0}))
    families = set()
    for _, rep, _labels in runs:
        families |= {f for fnd in rep["findings"] for f in fnd["finder_families"]}
    for _, rep, labels in runs:
        for fam in families:
            found = [f for f in rep["findings"] if fam in f["finder_families"]]
            matched_labels = set()
            for f in found:
                hit = next((i for i, lab in enumerate(labels) if _match(f, lab)), None)
                if hit is None:
                    stats[fam][f["cwe"]]["fp"] += 1
                elif hit not in matched_labels:  # a label counts once even if two findings land on it
                    matched_labels.add(hit)
                    stats[fam][f["cwe"]]["tp"] += 1
            for i, lab in enumerate(labels):
                if i not in matched_labels:
                    stats[fam][lab["cwe"]]["fn"] += 1
    return stats, sorted(families)


def audit_rates(runs, families):
    agg = defaultdict(lambda: defaultdict(int))
    for _, rep, _ in runs:
        for k, v in rep["bias_audit"].items():
            if "[" in k and k.endswith("]") and isinstance(v, (int, float)) and "~" not in k:
                key, fam = k[:-1].split("[")
                agg[fam][key] += v
    rows = {}
    for fam in families:
        calls = agg[fam]["reviewer_calls"] or 1
        rows[fam] = {
            "calls": agg[fam]["reviewer_calls"],
            "refusal_rate": agg[fam]["reviewer_refusals"] / calls,
            "canary_rate": agg[fam]["canary_echoes"] / calls,
            "unverified_quotes": agg[fam]["findings_with_unverified_quotes"],
            "invalid": agg[fam]["invalid_findings_dropped"],
        }
    return rows


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
    """Unsupervised reliability of each judge family from votes only (3 classes)."""
    items = {}  # (sample, finding_id) -> {family: [verdict idx...]}
    for sample, rep, _ in runs:
        for v in rep["votes"]:
            items.setdefault((sample, v["finding_id"]), defaultdict(list))[v["judge_family"]].append(VERDICT_IDX[v["verdict"]])
    fams = sorted({f for votes in items.values() for f in votes})
    if not items or not fams:
        return {}, 0
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
    return rel, len(items)


def suggest_weights(stats, rel, families):
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
        out[fam] = {"precision": prec, "recall": recall, "f1": f1, "n_labels": tp + fn, "ds_reliability": rel.get(fam), "weight": w}
    return out


def render(runs, stats, families, rates, pair, alpha, rel, n_items, weights, mode: str) -> str:
    today = dt.date.today().isoformat()
    L = [f"# 第一次校準報告（{today}）", "",
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
    L += ["## 2. 拒答率、canary 回應率、無效輸出", "", "| 家族 | 呼叫數 | 拒答率 | canary 回應率 | 未驗證引用 | 無效 finding |", "|---|---:|---:|---:|---:|---:|"]
    for fam in families:
        r = rates.get(fam, {})
        L.append(f"| {fam} | {r.get('calls', 0)} | {r.get('refusal_rate', 0):.2f} | {r.get('canary_rate', 0):.2f} | {r.get('unverified_quotes', 0)} | {r.get('invalid', 0)} |")
    L += ["", "## 3. judge 家族兩兩一致率與全域 α", "", "| 家族對 | 一致率（樣本平均） | 相關錯誤風險 |", "|---|---:|---|"]
    for k, v in sorted(pair.items()):
        L.append(f"| {k} | {v:.3f} | {'**高（>0.9）**' if v > 0.9 else '可接受'} |")
    L += ["", f"全域 Krippendorff's α（樣本平均）：{alpha:.3f}" if alpha is not None else "全域 α：n/a", "",
          "## 4. Dawid-Skene 無監督可靠度（僅用投票，不看標籤）", "", f"項目數 {n_items}", "", "| 家族 | 可靠度 |", "|---|---:|"]
    for fam, v in sorted(rel.items()):
        L.append(f"| {fam} | {v:.3f} |")
    L += ["", "## 5. 建議家族權重（0.2–2.0；0.6×監督 F1 + 0.4×DS 可靠度）", "",
          "| 家族 | precision | recall | F1 | DS 可靠度 | 建議權重 | 標籤數 |", "|---|---:|---:|---:|---:|---:|---:|"]
    for fam in families:
        w = weights[fam]
        L.append(f"| {fam} | {w['precision']:.2f} | {w['recall']:.2f} | {w['f1']:.2f} | {w['ds_reliability'] if w['ds_reliability'] is not None else 'n/a'} | **{w['weight']}** | {w['n_labels']} |")
    L += ["", "權重未自動寫入 `config/mara.yaml`；採用與否由人決定。標籤數低於 30 的家族權重只能視為方向，不能視為量測。", "",
          "## 6. 如何重跑（真實模型）", "", "```bash",
          "mara check-config config/mara.yaml   # 三個家族端點可達、ZDR 已啟用",
          "for s in calib/samples/*/; do mara review \"$s\" --config config/mara.yaml --out calib-out/$(basename $s); done",
          "python scripts/calibrate.py --mode live", "```", ""]
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="calib-out")
    ap.add_argument("--samples-dir", default="calib/samples")
    ap.add_argument("--mode", default="mock", choices=["mock", "live"])
    ap.add_argument("--report", default=None)
    args = ap.parse_args()
    runs = load_runs(ROOT / args.out_dir, ROOT / args.samples_dir)
    if not runs:
        raise SystemExit("no calib-out/*/report.json found; run `mara review` on the samples first")
    stats, families = family_metrics(runs)
    rates = audit_rates(runs, families)
    pair, alpha = judge_agreement(runs)
    rel, n_items = dawid_skene(runs)
    weights = suggest_weights(stats, rel, families)
    text = render(runs, stats, families, rates, pair, alpha, rel, n_items, weights, args.mode)
    out = Path(args.report) if args.report else ROOT / "docs" / f"calibration-{dt.date.today().isoformat()}.md"
    out.write_text(text, encoding="utf-8")
    print(f"wrote {out}")
    for fam in families:
        w = weights[fam]
        print(f"{fam:10s} P={w['precision']:.2f} R={w['recall']:.2f} F1={w['f1']:.2f} DS={w['ds_reliability']} weight={w['weight']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
