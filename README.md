# MultiAgentAlpha — MARA (Multi-Agent Review Architecture)

Heterogeneous-model, multi-agent **security and architecture review for vibe-coded software**,
anchored to deterministic tools and designed so that no single language model's bias can
decide the outcome.

This repository contains two things:

1. **The research report** (正體中文, GSMD series): `docs/GSMD-RPT-2026-0908-01_多模型多代理資安審查.md`
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

## Calibration (Appendix E, prompt 4)

`calib/samples/` holds five labelled vibe-coded samples (51 labels). The loop runs offline with
label-driven mock families and produces `docs/calibration-<date>.md` with per-family, per-CWE
precision and recall, refusal and canary rates, judge-family agreement, a Dawid-Skene reliability
estimate and suggested weights (never written to the config automatically):

```bash
for s in calib/samples/*/; do mara review "$s" --provider mock --out calib-out/$(basename "$s"); done
python scripts/calibrate.py --mode mock
```

For a live run point the same commands at `config/mara.yaml` (three reachable family endpoints,
ZDR enabled) and pass `--mode live`. `scripts/fetch_calib_corpora.sh` fetches OWASP Juice Shop
and WebGoat; they need human-authored `labels.json` files before they count.

## Policies enforced by the config

`mara check-config <yaml>` evaluates six policies and exits non-zero if any fails; `MaraConfig`
refuses to load a violating file, so the pipeline cannot run outside policy:

| Policy | Rule |
|---|---|
| P1 covered-models | Fable/Mythos-class Anthropic models (30-day retention, not ZDR-eligible) need `anthropic_covered_models_authorized: true` and an authorization reference |
| P2 deepseek-on-prem | DeepSeek only through an OpenAI-compatible endpoint on an RFC 1918, loopback or `.internal` host; any `*.deepseek.com` URL is rejected |
| P3 panel-size | reviewers and judges each span at least three model families; exactly two only with a stated `reduced_panel_reason` (see `config/examples/prc-site.yaml`) |
| P4 gate-bounds | `gate.self_judge_discount` at most 0.5, `gate.human_threshold_alpha` at least 0.3 |
| P5 data-residency | every non-mock model is `on_prem` or `vendor_api_zdr` unless `allow_source_code_to_non_on_prem` is set |
| P6 psirt-scope | when the PSIRT hand-off is enabled: HTTPS webhook, product set, token from the environment, trigger tiers within A/B and severities within Critical/High |

`config/examples/violating.yaml` breaks the first five and is what the tests run against.

## Gap assessment (Appendix E, prompt 3)

`docs/assessment-2026-09-12.md` scores this repository's review process against the 60-question
questionnaire in `docs/appendix-d-maturity.md`, with a file-level evidence cell on every row,
per-layer totals, the two lowest questions per layer mapped to governance items G-1 to G-13, and a
separate CN-1 to CN-4 table for the PRC sites. `scripts/score_assessment.py <file>` checks the
acceptance criteria (all 60 rows scored with evidence, layer sums consistent, CN rows present) and
`tests/test_assessment.py` runs the same check in CI.

## Actions inventory (Appendix E, prompt 5)

`scripts/actions_inventory.py [root] --out docs/actions-inventory-<date>.md` inventories every
`.github/workflows/*.yml` in the tree without modifying anything: triggers, `pull_request_target`,
PR-head checkouts, top-level and job-level permissions, every `uses:` by reference kind, `run:`
interpolation of attacker-controlled contexts, cache keys built from untrusted refs, a severity
per report section 10.7 (Critical rows first), suggested full SHAs for every non-SHA reference
(via `git ls-remote`; `--offline` to skip), a check that each SHA pin still matches its tag
comment, and zizmor's SARIF when zizmor is on the PATH. Files that are not valid YAML are still
inventoried line by line and flagged. `docs/actions-inventory-2026-09-12.md` is the first run;
its section 6 adds what the CI logs showed that the static inventory cannot, and the fixes that
followed: CI now runs zizmor strictly on the real workflows, checks that zizmor's findings on the
seeded fixture match `fixtures/vuln-sample-sarif/zizmor.sarif` (now produced by zizmor itself), and
no longer hides a crashed or leaking gitleaks run behind `continue-on-error` (`.gitleaks.toml`
allowlists the seeded secrets under `fixtures/` and `calib/samples/`).

## Pinned, verified L0 tools (Appendix E, prompt 7)

`tools/versions.lock` pins every deterministic tool (gitleaks, osv-scanner, zizmor, trivy, semgrep,
plus the verifiers cosign and slsa-verifier) by exact version, download URL and SHA-256, and names
the strongest verification the publisher offers. `python scripts/install_tools.py` downloads each
asset, checks the SHA-256 (never skippable), runs the publisher-side check — cosign keyless bundle,
SLSA provenance, GitHub attestation, publisher checksum file, or `pip --require-hashes` for semgrep —
and installs into `.mara-tools/bin`, writing `.mara-tools/manifest.json`. Any mismatch aborts.
`mara/tools/runner.py` executes tools only from that directory and reports "not installed" otherwise;
PATH is never consulted. `docs/tools-provenance.md` records source, licence, what each verification
proves and the remaining gaps (gitleaks and semgrep publish no signature). CI installs and verifies
the whole set on every run.

## Governance checks (Appendix E, prompt 8)

`python scripts/governance_check.py --out docs/governance-check-<date>.md` turns the report's
governance items G-1 to G-13 into checks against this repository and `config/mara.yaml`: each row
is PASS, FAIL or MANUAL (undecidable from files, with the evidence a human must produce), carries
the evidence it looked at and the standard clauses from the report's section 25.4, and any FAIL
makes the script exit non-zero. `.github/workflows/governance.yml` runs it every Monday and posts
the table to a `governance-check` tracking issue. `docs/governance-check-2026-09-12.md` is the
first run: G-2, G-3, G-5, G-6 pass; G-7 (ML-BOM), G-8 (garak/CyberSecEval), G-9 (a live
calibration), G-11 (human-queue ticketing), G-12 (PSIRT hook) and G-13 (AI-literacy records) failed
on that first run; G-1, G-4 and G-10 need human evidence. G-11 and G-12 have since been implemented:
G-11 passes, G-12 passes once `psirt.enabled` is set with a real endpoint.

## PSIRT hand-off (governance item G-12)

With `psirt.enabled: true` and `psirt.shipped: true` in the config, every accepted finding in the
configured tiers and severities (default: tier A, Critical) is written to
`out/psirt-notifications.json` as an EU CRA Article 14 early-warning payload carrying the evidence
chain and the 24 h / 72 h / 14 d deadlines counted from the review; `mara review --notify-psirt`
POSTs them to the PSIRT webhook with a bearer token from the environment. Policy P6 keeps the
trigger narrow (tiers within A/B, severities within Critical/High, HTTPS, no inline secret).
Whether a vulnerability is actively exploited, the legal trigger of Article 14, remains the
PSIRT's determination. See `docs/psirt-integration.md`; `config/examples/psirt-enabled.yaml` is a
complete example.

## Human queue (governance item G-11)

Findings the pipeline will not decide on its own (judge majority says `needs_human`, Krippendorff's
alpha below the threshold, or tier C at High or above) become `HumanQueueItem`s in
`out/human_queue.md/json` with the full un-blinded context: finder families, the skeptic's verdict,
the red team's call and every judge vote from both passes. `scripts/human_queue_issues.py` opens one
GitHub issue per item (deduplicated by a stable `file:line:cwe` key) and, with `--sync-decisions`,
turns closed tickets labelled `decision:true-positive` / `decision:false-positive` into
`calib/decisions/<key>.json`, which `scripts/calibrate.py` uses as labels. When
`calib/decisions/backlog.json` shows more open tickets than `human_queue.backlog_limit`, the pipeline
raises the alpha threshold and stops queuing tier C; it never loosens. The `human-queue` CI job runs
on push to `main` with `issues: write` only and stays in dry-run until the repository variable
`MARA_HUMAN_QUEUE_ISSUES` is `true`. See `docs/human-queue.md`.

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
