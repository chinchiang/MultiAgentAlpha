"""Governance checks G-10, G-11 and G-13 read their evidence from the MARA workspace they are given, apart from the
root they scan: the baseline report (G-10), the backlog, the decision records and the Pilot poller's Sync record
(G-11), the training register (G-13). The curriculum, the config and the workflow files stay the root's."""

from __future__ import annotations

import datetime as dt
import shutil
import sys
from pathlib import Path

import pytest
import yaml

from mara.workspace import Workspace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import governance_check as gc  # noqa: E402

TODAY = dt.date(2026, 11, 26)


def _root(tmp_path: Path) -> Path:
    """A root with this repository's workflows and configs: the config files GitHub issues and a workflow step runs the
    ticket sync, so G-11 turns on whether the sync ran for real."""
    root = tmp_path / "root"
    shutil.copytree(ROOT / ".github", root / ".github")
    shutil.copytree(ROOT / "config", root / "config")
    return root


def _backlog(where: Path) -> None:
    (where / "calib" / "decisions").mkdir(parents=True, exist_ok=True)
    (where / "calib" / "decisions" / "backlog.json").write_text('{"open": 3}', encoding="utf-8")


# before the backlog test: a backlog in the root read as a decision record fails that test as well
def test_g11_reads_the_decision_records_in_the_workspace_and_not_the_ones_in_the_root(tmp_path):
    from tests.test_decisions import record, write

    root, ws = _root(tmp_path), tmp_path / "workspace"
    for where in (root, ws):
        (where / "calib" / "decisions").mkdir(parents=True)
    config = root / "config" / "mara.yaml"
    write(root / "calib" / "decisions", record(line=10))
    assert gc.check_g11(root, config, workspace=Workspace(ws)).status == gc.FAIL, "a decision only in the root"
    write(ws / "calib" / "decisions", record(line=20))
    r = gc.check_g11(root, config, workspace=Workspace(ws))
    assert r.status == gc.PASS and "1 筆裁決已回寫" in r.evidence, r.evidence


def test_g11_reads_the_backlog_in_the_workspace_and_not_the_one_in_the_root(tmp_path):
    root, ws = _root(tmp_path), tmp_path / "workspace"
    ws.mkdir()
    config = root / "config" / "mara.yaml"
    _backlog(root)
    r = gc.check_g11(root, config, workspace=Workspace(ws))
    assert r.status == gc.FAIL, "a backlog only in the root"
    assert "`calib/decisions/backlog.json`" in r.evidence and str(ws) not in r.evidence, "the workspace's path is not shown"
    _backlog(ws)
    assert gc.check_g11(root, config, workspace=Workspace(ws)).status == gc.PASS


def _without_sync_step(root: Path) -> None:
    """The root's workflows keep naming the human queue, but no step runs the sync."""
    for wf in (root / ".github" / "workflows").glob("*.yml"):
        wf.write_text(wf.read_text(encoding="utf-8").replace("--sync-decisions", ""), encoding="utf-8")


def _sync_record(ws: Path, text: str) -> None:
    (ws / "pilot").mkdir(parents=True, exist_ok=True)
    (ws / "pilot" / "sync.json").write_text(text, encoding="utf-8")


RECORD = '{"at": "2026-11-26T03:00:00+00:00", "repo": "org/tickets", "exit": 2}'


def test_g11_takes_the_pilot_pollers_sync_record_in_the_workspace_for_the_sync_step(tmp_path):
    root, ws = _root(tmp_path), tmp_path / "workspace"
    _without_sync_step(root)
    _backlog(ws)
    config = root / "config" / "mara.yaml"
    assert gc.check_g11(root, config, workspace=Workspace(ws)).status == gc.FAIL, "no step and no record"
    _sync_record(ws, RECORD)
    r = gc.check_g11(root, config, workspace=Workspace(ws))
    assert r.status == gc.PASS, r.evidence
    assert "`pilot/sync.json`" in r.evidence and "org/tickets" in r.evidence and "exit 2" in r.evidence, r.evidence
    assert "工單同步步驟" not in r.evidence, "the evidence names the record, not a step"


@pytest.mark.parametrize("text", [
    "not json",
    '["2026-11-26T03:00:00+00:00", "org/tickets", 0]',
    '{"at": "2026-11-26T03:00:00", "repo": "org/tickets", "exit": 0}',
    '{"at": "yesterday", "repo": "org/tickets", "exit": 0}',
    '{"at": "2026-11-26T03:00:00+00:00", "exit": 0}',
    '{"at": "2026-11-26T03:00:00+00:00", "repo": "tickets", "exit": 0}',
    '{"at": "2026-11-26T03:00:00+00:00", "repo": "org/tickets", "exit": "0"}',
    '{"at": "2026-11-26T03:00:00+00:00", "repo": "org/tickets", "exit": true}',
], ids=["not JSON", "not an object", "time with no time zone", "time not a time", "no repository",
        "repository not owner/repo", "exit not an integer", "exit a boolean"])
def test_g11_does_not_take_a_sync_record_not_of_the_shape_the_poller_writes(tmp_path, text):
    root, ws = _root(tmp_path), tmp_path / "workspace"
    _without_sync_step(root)
    _backlog(ws)
    _sync_record(ws, text)
    r = gc.check_g11(root, root / "config" / "mara.yaml", workspace=Workspace(ws))
    assert r.status == gc.FAIL and "`pilot/sync.json`" in r.evidence, r.evidence


def _register(where: Path, version: str, records: str = "") -> None:
    (where / "training").mkdir(parents=True, exist_ok=True)
    (where / "training" / "records.yaml").write_text(
        f"curriculum_version: '{version}'\nvalidity_days: 365\npass_mark: 0.8\nrecords:{records or ' []'}\n", encoding="utf-8")


def test_g13_reads_the_register_in_the_workspace_and_not_the_one_in_the_root(tmp_path):
    root, ws = tmp_path / "root", tmp_path / "workspace"
    (root / "training").mkdir(parents=True)
    (root / "training" / "curriculum.md").write_text("# curriculum\n", encoding="utf-8")
    _register(root, "2026-01")
    (ws / "training").mkdir(parents=True)
    (ws / "training" / "curriculum.md").write_text("# curriculum\n", encoding="utf-8")  # the curriculum's place aside
    r = gc.check_g13(root, TODAY, workspace=Workspace(ws))
    assert r.status == gc.FAIL and "沒有訓練登錄簿" in r.evidence, "a register only in the root"
    _register(ws, "2026-09")
    r = gc.check_g13(root, TODAY, workspace=Workspace(ws))
    assert "版本 2026-09" in r.evidence, r.evidence


def test_g13_reads_the_curriculum_in_the_root_and_not_the_one_in_the_workspace(tmp_path):
    root, ws = tmp_path / "root", tmp_path / "workspace"
    root.mkdir()
    _register(ws, "2026-09")
    (ws / "training" / "curriculum.md").write_text("# curriculum\n", encoding="utf-8")
    assert "沒有課程" in gc.check_g13(root, TODAY, workspace=Workspace(ws)).evidence, "a curriculum only in the workspace"


def test_g13_names_the_decisions_in_the_workspace_that_wait_for_a_trained_adjudicator(tmp_path):
    from tests.test_decisions import record, write

    root, ws = tmp_path / "root", tmp_path / "workspace"
    (root / "training").mkdir(parents=True)
    (root / "training" / "curriculum.md").write_text("# curriculum\n", encoding="utf-8")
    _register(ws, "2026-09")
    for where, line, by in ((ws, 20, "mallory"), (root, 30, "trudy")):
        (where / "calib" / "decisions").mkdir(parents=True, exist_ok=True)
        write(where / "calib" / "decisions", record(line=line, by=by, adjudicator_trained=True))
    r = gc.check_g13(root, TODAY, workspace=Workspace(ws))
    assert "#20 by mallory" in r.evidence and "trudy" not in r.evidence, r.evidence


def test_g10_finds_the_baseline_report_in_the_workspace_and_not_in_the_root(tmp_path):
    root, ws = tmp_path / "root", tmp_path / "workspace"
    raw = yaml.safe_load((ROOT / "config" / "mara.mock.yaml").read_text(encoding="utf-8"))
    raw["rollout"] = {"phase": "advisory", "started_on": "2026-11-01", "baseline_report": "pilot/baseline.md"}
    config = root / "config" / "mara.yaml"
    config.parent.mkdir(parents=True)
    config.write_text(yaml.safe_dump(raw), encoding="utf-8")
    for where in (root, ws):
        (where / "pilot").mkdir(parents=True)
    (root / "pilot" / "baseline.md").write_text("# baseline\n", encoding="utf-8")
    r = gc.check_g10(root, config, TODAY, workspace=Workspace(ws))
    assert r.status == gc.FAIL and "baseline report pilot/baseline.md not found" in r.evidence, "a baseline only in the root"
    (ws / "pilot" / "baseline.md").write_text("# baseline\n", encoding="utf-8")
    assert gc.check_g10(root, config, TODAY, workspace=Workspace(ws)).status == gc.PASS


def test_run_all_hands_g10_g11_and_g13_the_workspace_it_is_given_not_the_environments(tmp_path, monkeypatch):
    root, ws, bare = _root(tmp_path), tmp_path / "workspace", tmp_path / "bare"
    bare.mkdir()
    monkeypatch.setenv("MARA_HOME", str(bare))
    _without_sync_step(root)
    _backlog(ws)
    _sync_record(ws, RECORD)
    _register(ws, "2026-09")
    (root / "training").mkdir()
    (root / "training" / "curriculum.md").write_text("# curriculum\n", encoding="utf-8")
    raw = yaml.safe_load((root / "config" / "mara.yaml").read_text(encoding="utf-8"))
    raw["rollout"] = {"phase": "advisory", "started_on": "2026-11-01", "baseline_report": "pilot/baseline.md"}
    (root / "config" / "mara.yaml").write_text(yaml.safe_dump(raw), encoding="utf-8")
    (ws / "pilot" / "baseline.md").write_text("# baseline\n", encoding="utf-8")
    by_id = {r.id: r for r in gc.run_all(root, root / "config" / "mara.yaml", TODAY, Workspace(ws))}
    assert by_id["G-11"].status == gc.PASS, by_id["G-11"].evidence
    assert "版本 2026-09" in by_id["G-13"].evidence, by_id["G-13"].evidence
    assert "not found" not in by_id["G-10"].evidence, by_id["G-10"].evidence


def _every_kind_of_evidence(root: Path) -> Path:
    """A root holding each kind of evidence G-10, G-11 and G-13 read: a workflow step running the sync, a config (the
    mock config with its human queue, rollout and training blocks replaced), a baseline report, a backlog, a decision
    whose adjudicator held no record, the curriculum and a register; its config path."""
    from tests.test_decisions import record, write

    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "sync.yml").write_text(
        "on: workflow_dispatch\njobs:\n  sync:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: python scripts/human_queue_issues.py --sync-decisions\n", encoding="utf-8")
    raw = yaml.safe_load((ROOT / "config" / "mara.mock.yaml").read_text(encoding="utf-8"))
    raw.update(human_queue={"enabled": True, "ticketing": "github_issues"},
               rollout={"phase": "advisory", "started_on": "2026-11-01", "baseline_report": "pilot/baseline.md"},
               training={"required_roles": ["developer"]})
    (root / "config").mkdir()
    (root / "config" / "mara.yaml").write_text(yaml.safe_dump(raw), encoding="utf-8")
    (root / "pilot").mkdir()
    (root / "pilot" / "baseline.md").write_text("# baseline\n", encoding="utf-8")
    _backlog(root)
    write(root / "calib" / "decisions", record(line=20, by="mallory", adjudicator_trained=True))
    (root / "training").mkdir()
    (root / "training" / "curriculum.md").write_text("# curriculum\n", encoding="utf-8")
    _register(root, "2026-09", "\n  - {person: dana, role: developer, curriculum_version: '2026-09', date: 2026-09-20, "
                               "assessor: quiz, evidence: quiz}")
    return root / "config" / "mara.yaml"


# What scripts/governance_check.py printed for these roots before G-10, G-11 and G-13 read the workspace (origin/main
# f82fead, the workspace being the root): with every kind of evidence, and with the evidence gone.
BEFORE = [
    ("G-10", gc.PASS,
        '`rollout.phase: advisory`；自 2026-11-01 起 25 天（預定 2027-01-30 前進入下一階段）；基線報告 `pilot/baseline.'
        'md`；gate results are advisory; blocking findings are marked, not enforced'),
    ("G-11", gc.PASS,
        '設定以 GitHub issue 開單（`human_queue.ticketing: github_issues`）；工單同步步驟：`.github/workflows/sync'
        '.yml`；同步確實執行過：backlog 已寫入、1 筆裁決已回寫'),
    ("G-13", gc.PASS,
        '課程 `training/curriculum.md` 版本 2026-09，紀錄有效 365 天，共 1 筆；developer：1 筆有效（dana）；`training.re'
        'quire_trained_adjudicator: true`（未受訓者的裁決不進校準）；1 筆裁決因裁決者在裁決當天沒有有效的 adjudicator 紀錄而不進校準，需由受訓'
        '者重新裁決：#20 by mallory'),
]
BEFORE_BARE = [
    ("G-10", gc.FAIL,
        'baseline report pilot/baseline.md not found。已有：`rollout.phase: advisory`；自 2026-11-01 起 25'
        ' 天（預定 2027-01-30 前進入下一階段）；基線報告 `pilot/baseline.md`；gate results are advisory; blocking fin'
        'dings are marked, not enforced。需要：`rollout.phase`（shadow→advisory→blocking）、`started_on`、影'
        '子期結束時的基線報告（`scripts/rollout_phase.py baseline`）'),
    ("G-11", gc.FAIL,
        '已有：設定以 GitHub issue 開單（`human_queue.ticketing: github_issues`）；工單同步步驟：`.github/workflows/s'
        'ync.yml`。需要：同步要實際執行過（不是 dry-run）：`calib/decisions/backlog.json` 或 `calib/decisions/` 的裁決紀錄'
        '。CI 的 human-queue job 在儲存庫變數 `MARA_HUMAN_QUEUE_ISSUES=true` 前只 dry-run；裁決由負責人鏡像回 repo'),
    ("G-13", gc.FAIL,
        '有課程但沒有訓練登錄簿 `training/records.yaml`。需要：每個角色（developer、security、adjudicator）至少一人在一年內完成 `tra'
        'ining/curriculum.md` 的訓練並以 `scripts/training_register.py assess`／`add` 寫入 `training/record'
        's.yaml`；人工裁決者必須有有效的 adjudicator 紀錄，否則其裁決不進校準'),
]


def test_with_the_workspace_equal_to_the_root_g10_g11_and_g13_say_what_they_said_before(tmp_path):
    root = tmp_path / "root"
    config = _every_kind_of_evidence(root)
    ids = {"G-10", "G-11", "G-13"}
    after = [(r.id, r.status, r.evidence) for r in gc.run_all(root, config, TODAY, Workspace(root)) if r.id in ids]
    assert after == BEFORE
    shutil.rmtree(root / "calib")
    (root / "pilot" / "baseline.md").unlink()
    (root / "training" / "records.yaml").unlink()
    after = [(r.id, r.status, r.evidence) for r in gc.run_all(root, config, TODAY, Workspace(root)) if r.id in ids]
    assert after == BEFORE_BARE
