# MultiAgentAlpha — MARA (Multi-Agent Review Architecture)

Heterogeneous-model, multi-agent **security and architecture review for vibe-coded software**,
anchored to deterministic tools and designed so that no single language model's bias can
decide the outcome.

This repository contains two things:

1. **The research report** (正體中文, GSMD series): `docs/GSMD-RPT-2026-0908-TBD_多模型多代理資安審查.md`
   with an online single-file HTML edition next to it. It covers the architecture, the scoring
   method, the data-credibility model, the bias catalogue and its mitigations, a comparison of
   commercial and academic alternatives, deployment for a multinational ODM/EMS (including the
   CSL/DSL/PIPL isolation rule for PRC sites), limitations, and governance recommendations mapped
   to ISO/IEC 27001:2022, IEC 62443-4-1, EU CRA, NIST SSDF and ISO/IEC 42001.
2. **A runnable prototype** (`src/mara`) that implements the six-layer architecture the report
   describes. It runs fully offline with mock providers, and against live models (Anthropic API
   plus self-hosted DeepSeek / Nemotron behind an OpenAI-compatible endpoint) when configured.

## The six layers

| Layer | What it does | Where |
|---|---|---|
| L0 deterministic anchors | semgrep, gitleaks, osv-scanner, zizmor, trivy → SARIF. Ground truth and calibration set. | `mara/tools` |
| L1 context | Repo map, entry points, workflows, manifests; strips authorship signals. Facts, not judgements. | `mara/context` |
| L2 reviewers | 11 dimensions × ≥2 model families, independent, structured JSON only. | `mara/agents/reviewer.py`, `mara/prompts` |
| L3 adversarial | Skeptic (must be a different family than the finder) tries to refute; red team states exploitability. | `mara/agents/skeptic.py`, `redteam.py` |
| L4 jury | Blinded findings (no identity, no scores, fixed width), forward + reverse order, a family never judges its own finding when enough independent judges exist. | `mara/agents/judge.py`, `mara/bias` |
| L5 scoring | CVSS 4.0 computed by code (FIRST-equivalent), SSVC decision, weighted consensus, Krippendorff's α, evidence tier A–D, dimension scores, gate, SARIF 2.1 + Markdown. | `mara/scoring`, `mara/report` |

Three rules are enforced by code, not by prompt:

- **Provenance**: every finding must quote a verbatim excerpt that exists in the file (±3 lines). Fabricated quotes are tier D and never accepted.
- **Pinned ground truth**: standard ids (ASVS 5.0 chapters, OWASP Top 10:2025, API Top 10 2023, LLM Top 10 2025, CWE subset) are validated against `mara/groundtruth/*.json`; unknown ids are stripped.
- **Data residency**: source code is only sent to models declared `on_prem` or `vendor_api_zdr`. The default config refuses anything else.

## Quick start (offline)

```bash
python -m pip install -e ".[dev]"
pytest -q
mara review fixtures/vuln-sample --provider mock --sarif-dir fixtures/vuln-sample-sarif --out out
```

`fixtures/vuln-sample` is a deliberately vulnerable "vibe-coded" Flask app (reflected and DOM XSS,
SQL injection, IDOR, forgeable session cookie, hard-coded tokens, password logging, verbose error
pages, a pwn-request workflow with title injection and unpinned actions, curl|sh in the Dockerfile,
a hallucinated-looking dependency, a hidden reviewer instruction in the README). The three mock
families behave differently on purpose (one fabricates a quote, one refuses a dimension, one flips
a vote between the forward and reverse pass) so the tests exercise every defence.

## Live mode

```bash
export ANTHROPIC_API_KEY=...        # or `ant auth login`
export DEEPSEEK_LOCAL_KEY=... NIM_LOCAL_KEY=...
mara check-config config/mara.yaml
mara review path/to/repo --config config/mara.yaml --out out
```

`config/mara.yaml` documents the intended topology: Claude Opus 5 through the Anthropic API under a
zero-data-retention agreement, DeepSeek weights self-hosted on vLLM, Nemotron on NVIDIA NIM. The
DeepSeek vendor API is never used for source code. See the report, Part VIII, for the site-by-site
deployment pattern and the separate handling of 上海／重慶.

## Other commands

```bash
mara cvss "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
python scripts/gen_mock_fixtures.py      # regenerate mock responses after editing the fixture app
python scripts/build_html.py             # rebuild the online edition of the report
python scripts/count_words.py            # 字數統計（正體中文計字，不含附錄A）
```

## Layout

```
config/            mara.yaml (live topology), mara.mock.yaml (offline)
src/mara/          the prototype (see table above)
fixtures/          vuln-sample app, mock-responses, pre-recorded SARIF
tests/             unit + end-to-end tests (no network)
docs/              the report (Markdown + HTML), Appendix E prompt kit, Appendix D questionnaire
scripts/           fixture generator, HTML builder, word counter
.github/workflows  hardened self-review workflow (SHA-pinned, read-only, no pull_request_target)
```

## Status

Prototype. The CVSS 4.0 calculator is verified against FIRST's reference implementation; the
consensus, tiering and blinding logic are unit-tested; the live providers are implemented but have
not been exercised against production models from this repository. Calibration weights in the
config are placeholders until a seeded-vulnerability benchmark run populates them (report, Part V).
