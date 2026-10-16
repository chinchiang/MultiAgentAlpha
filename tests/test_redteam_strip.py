"""Exploit-code stripping in the red team's preconditions (assessment L3 #35).

The prompt forbids exploit code, but prompt rules are not containment: the harness strips fenced
blocks, shell one-liners and payload strings from the free-text preconditions field, counts the
removals in the bias audit and marks such a run incomplete. The detector must be precise — a false
positive silently deletes a legitimate precondition AND blocks the report — so the prose cases that
must NOT match are tested next to the payload cases that must.
"""

from pathlib import Path
from types import SimpleNamespace

from mara.agents import redteam
from mara.config import load_config
from mara.context.repo_map import RepoContext
from mara.providers.base import STOP_END, Provider, RawReply


def test_fenced_blocks_and_shell_one_liners_are_stripped():
    text = "Requires network access to the admin panel.\n```\ncurl -H 'X: y' http://target/admin\n```\nAn account is not needed."
    clean, stripped = redteam.strip_exploit_code(text)
    assert stripped
    assert "curl" not in clean and "```" not in clean
    assert "Requires network access to the admin panel." in clean and "An account is not needed." in clean


def test_payload_strings_are_stripped_line_wise():
    for line in ("Inject <img src=x onerror=alert(1)> into the title field.",
                 "Read the file with ../../../../etc/passwd.",
                 "Send 1 UNION SELECT user, password FROM users.",
                 "Then run os.system('id') on the host.",
                 "Prefix the value with javascript: to escape the href.",
                 "The stored payload reaches document.cookie.",
                 "Run `cat /etc/shadow` as root.",
                 "$ curl -X POST http://target/upload --data @shell.sh",
                 "python3 -c \"import urllib.request; urllib.request.urlopen('http://x')\"",
                 "sqlmap -u http://target/item?id=1 --batch"):
        clean, stripped = redteam.strip_exploit_code("Keep this sentence.\n" + line)
        assert stripped, line
        assert clean == "Keep this sentence.", line


def test_legitimate_precondition_prose_is_never_touched():
    for prose in ("Requires an authenticated session with administrator privileges.",
                  "The debug flag must be enabled in the application config.",
                  "Only matters if the deployment exposes the metrics endpoint.",
                  "An attacker needs the ability to open a pull request from a fork.",
                  "sudo privileges on the build runner are required.",
                  "The mismatch raises an alert (browser dialog) only for admins.",
                  "The value is compared with the `debug` config key.",
                  "echo requests (ICMP) must be allowed between the pods.",
                  "Works when the catalog service is unreachable.",
                  "Needs `config.yaml` to contain the default secret.",
                  "The eval (evaluation) stage of the pipeline runs untrusted input.",
                  "exploitation of the race needs two concurrent sessions."):
        clean, stripped = redteam.strip_exploit_code(prose)
        assert not stripped, prose
        assert clean == prose, prose


def test_all_code_yields_the_placeholder():
    clean, stripped = redteam.strip_exploit_code("```\nrm -rf /\n```")
    assert stripped and clean == redteam.EXPLOIT_STRIP_PLACEHOLDER
    # the 500-char cap on preconditions is enforced by the pydantic schemas before this point;
    # stripping only removes characters, so it can never push a note over the limit


ROOT = Path(__file__).resolve().parents[1]


class _Items(Provider):
    """A red team whose reply holds `items`, classified and screened by mara.exchange like any other reply."""

    def __init__(self, items: list[dict]):
        super().__init__(load_config(ROOT / "config" / "mara.mock.yaml").models[0])
        self.items = items

    def complete(self, **kwargs):
        return RawReply(STOP_END, structured={"items": self.items})


def _run(items: list[dict], findings: list):
    provider = _Items(items)
    ctx = RepoContext(root=ROOT, content={"app.py": "def render(t):\n    return t\n"})
    return provider, *redteam.run_redteam(provider, ctx, findings)  # type: ignore[arg-type]


def test_run_redteam_strips_code_and_counts():
    payload = {
        "finding_id": "F1", "exploitable": "conditional",
        "preconditions": "Attacker must control the template.\n```\n{{ 7*7 }}\n```\nNo authentication needed.",
    }
    clean_item = {"finding_id": "F2", "exploitable": "yes", "preconditions": "No authentication needed."}
    findings = [SimpleNamespace(id="F1", title="t1", cwe="CWE-94", exploit_sketch=None, provenance=[]),
                SimpleNamespace(id="F2", title="t2", cwe="CWE-79", exploit_sketch=None, provenance=[])]
    _, notes, rec = _run([payload, clean_item], findings)
    assert not rec.voided and rec.counts["exploit_code_stripped"] == 1
    by_id = {n.finding_id: n for n in notes}
    assert by_id["F1"].preconditions == "Attacker must control the template.\nNo authentication needed."
    assert by_id["F2"].preconditions == "No authentication needed."


def test_run_redteam_all_code_preconditions_become_the_placeholder():
    item = {"finding_id": "F1", "exploitable": "conditional", "preconditions": "$ curl http://target/x"}
    f = SimpleNamespace(id="F1", title="t", cwe="CWE-94", exploit_sketch=None, provenance=[])
    provider, notes, rec = _run([item], [f])
    assert rec.counts["exploit_code_stripped"] == 1 and not rec.voided
    assert notes[0].preconditions == redteam.EXPLOIT_STRIP_PLACEHOLDER
    assert notes[0].source_family == provider.family


def test_pipeline_counts_stripping_and_marks_the_run_incomplete(tmp_path, monkeypatch):
    """Full mock run: one surviving finding, red team stripped code → bias audit counts it and the
    report is incomplete (the same fail-closed treatment as reviewer refusals or canary echoes)."""
    import json as jsonlib

    from mara.pipeline import Pipeline
    from mara.tools.runner import ToolRun
    from tests.fake_panel import Panel, items

    root = Path(__file__).resolve().parents[1]
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    review_data = {"findings": [{
        "title": "SQL finding", "cwe": "CWE-89", "standard_refs": [],
        "provenance": [{"file": "app.py", "line": 1, "quote": "unsafe()"}],
        "reachability": "reachable", "reachability_argument": "public", "exploit_sketch": "input",
        "cvss4_vector": vector, "model_confidence": 0.9,
    }]}

    class Reply(Provider):
        def __init__(self, spec):
            super().__init__(spec)

        def complete(self, **kwargs):
            return RawReply(STOP_END, answer_text=jsonlib.dumps(review_data))

    pipe = Pipeline(load_config(root / "config" / "mara.mock.yaml"), out_dir=tmp_path / "out")
    (tmp_path / "app.py").write_text("unsafe()\n")
    pipe.providers = {n: Reply(p.spec) for n, p in pipe.providers.items()}
    monkeypatch.setattr(pipe, "run_tools", lambda *_: [ToolRun(t, True) for t in ("semgrep", "gitleaks", "osv-scanner", "zizmor", "trivy")])
    # a note for every finding, the first one's preconditions a shell command
    Panel.seated_in(pipe).always("redteam", items(lambda i: {"exploitable": "conditional",
                                                             "preconditions": "$ curl http://target/x" if i == "F-0001" else "none"}))
    report = pipe.run(tmp_path, mode="mock")
    assert report.bias_audit["redteam_exploit_code_stripped"] == 1
    assert "redteam_exploit_code_stripped" in report.incomplete_reasons
    assert not report.gate_passed and report.review_status == "incomplete"
