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

Found a security problem in this repository's own code? See [SECURITY.md](SECURITY.md)
(private vulnerability reporting; the seeded fixtures are out of scope by design).

## Quick start (offline)

```bash
python -m pip install --require-hashes --only-binary=:all: -r tools/dev-requirements.txt   # the resolved, hash-pinned closure
python -m pip install --no-deps -e .                                                          # this repository's own code only
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
| P7 ml-bom | when `ml_bom.required`: every self-hosted model has a complete CycloneDX ML-BOM component (safetensors hashes, licence, source, signature method), signed when `require_signature` |

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
allowlists the seeded secrets under `fixtures/` and `calib/samples/`). Since 2026-09-13 the scan
itself is `scripts/gitleaks_ci.py` with the gitleaks pinned in `tools/versions.lock` (PR: the PR's
commits; push: every new commit), not gitleaks-action, so no action downloads its own tool and the
L0 job needs no `pull-requests` permission.

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
the whole set on every run. The lock also has a `git` kind: `semgrep-rules` is a checkout of
`semgrep/semgrep-rules` at a pinned commit, verified by commit id, by a SHA-256 digest over every
file under the pinned security rulesets, and by the commit's GPG signature (GitHub's web-flow key);
the rules are read from `.mara-tools/semgrep-rules` at scan time and never copied into this
repository (Semgrep Rules License v1.0). `--digest-git semgrep-rules <checkout>` prints the two
values to paste into the lock when bumping the commit.

The Python side is pinned the same way since 2026-09-17: `tools/dev-requirements.txt` is the
complete closure of `pyproject.toml`'s dependencies plus the `dev` extra, every wheel with its
SHA-256, and `tools/model-eval-requirements.txt` is the closure of `garak==0.17.0` (194
distributions, two of them sdists because no wheel exists). Both are written by
`scripts/relock_requirements.py` from a `pip install --dry-run --report` resolution on CPython 3.11 /
Linux x86_64 and installed with `--require-hashes`; the workflows then add this repository's own
code with `pip install --no-deps -e .`, so no `pip install` in CI runs unpinned. A test fails if
one ever does.

## semgrep and osv-scanner in CI (L0 job)

Since 2026-09-13 the `deterministic-tools` job runs both scanners from the lock, through two
scripts that refuse anything not installed by `scripts/install_tools.py` and any version that
differs from the lock:

- `scripts/semgrep_ci.py --target fixtures/vuln-sample --expect fixtures/vuln-sample-sarif/semgrep.sarif`
  scans the seeded fixture with the pinned rulesets and fails on any drift from the recording
  (which is real semgrep 1.177.0 output, 15 findings, rule ids normalised to the registry form).
- `scripts/semgrep_ci.py --target . --triage tools/semgrep-triage.yaml` scans the repository
  (minus the seeded `fixtures/` and `calib/samples/`); every finding must be covered by a triage
  entry with a reason or the job fails, covered findings are uploaded with a SARIF `suppressions`
  record, and entries that no longer match anything are reported as stale.
- `scripts/osv_ci.py --target fixtures/vuln-sample --expect-package requests` must see the
  fixture's `requests==2.19.0` flagged, so a silent scanner or database regression is caught.
- `scripts/osv_ci.py --lockfile tools/*-requirements.txt --config tools/osv-scanner.toml` checks
  the hash-locked closures this repository installs; an advisory fails the job unless
  `tools/osv-scanner.toml` ignores it with a reason and an `ignoreUntil` date.

semgrep runs with `--metrics=off --disable-version-check` and explicit local rule directories
(never `--config auto`), so nothing is sent to semgrep.dev; osv-scanner runs `scan source
--no-resolve`, so only package names and versions go to api.osv.dev and nothing to deps.dev. All
SARIF files land in the `l0-sarif` artifact, and the five scans of the repository itself are also
uploaded to GitHub Code Scanning (see below). `mara review` uses the same pinned rulesets by default
(`MARA_SEMGREP_CONFIG` overrides). zizmor on the real workflows runs the same way since 2026-09-14:
`scripts/zizmor_ci.py` executes the locked zizmor (online audits with the workflow token), keeps the
SARIF and fails on any finding; zizmor-action is gone.

## trivy offline database

trivy used to download its vulnerability database at scan time, which hangs on isolated hosts and
turns every review into a network event. `python3 scripts/trivy_db.py download` fetches it once
(from the repositories in `tools/trivy-db.yaml`, `--pin-digest sha256:…` for a reproducible fetch)
into `.mara-tools/trivy-cache` and writes `mara-trivy-db.json`: OCI manifest and layer digests,
trivy's `UpdatedAt`/`NextUpdate`, the SHA-256 of `trivy.db`, the trivy version. `status` refuses a
missing, tampered or stale copy (default 48 h, `max_age_hours`); `export`/`import` carry the
database as a checked bundle to runners without egress. Both `mara review` and
`scripts/trivy_ci.py` then run trivy with `--skip-db-update --skip-java-db-update
--skip-check-update --offline-scan` and never download anything; without a database the runner
reports "no offline database" instead of reaching out. In CI the L0 job downloads and checks the
database, requires the fixture's `requests==2.19.0` to be flagged, and scans the hash-locked
closures under `tools/` (`--file-patterns pip:.*-requirements\.txt`), failing on any finding not
ignored with a statement and expiry in `tools/trivyignore.yaml`. Upstream publishes no signature
for the database; `docs/tools-provenance.md` section 3c records what is and is not verified.

## Code Scanning and Scorecard (public repository)

The repository is public since 2026-09-14, which makes GitHub Code Scanning free. The
`code-scanning` job of `mara-review.yml` takes the five SARIF files the L0 job produced for this
repository (semgrep, osv-scanner, trivy, gitleaks, zizmor) from the `l0-sarif` artifact, runs
`scripts/code_scanning_prep.py` (drops triaged findings and results without a location, makes
paths repository-relative, sets one Code Scanning category per tool) and uploads them with
`github/codeql-action/upload-sarif`. It is the only job with `security-events: write`, it runs no
repository code, and it is skipped for pull requests from forks or Dependabot (read-only token).
The fixture scans and the mock review report are never uploaded: they describe seeded material.

`.github/workflows/scorecard.yml` runs OpenSSF Scorecard on pushes to `main` and weekly with the
scorecard CLI pinned and SLSA-verified in `tools/versions.lock` (not `ossf/scorecard-action`, whose
docker image is referenced by a mutable tag and whose publishing needs `id-token: write`).
`scripts/scorecard_ci.py` converts the JSON to SARIF (category `scorecard`) and fails the job when
a check enforced in `tools/scorecard-policy.yaml` scores below its minimum. Enforced: Dangerous-Workflow,
Token-Permissions, Binary-Artifacts, Security-Policy (`SECURITY.md`) and Dependency-Update-Tool
(`.github/dependabot.yml`) at 10, and Pinned-Dependencies at 8, which is its ceiling while the
seeded material exists: the workflows themselves are fully pinned (every action by SHA, every pip install
by hash), but Scorecard matches `*Dockerfile*` anywhere in the repository and the two deliberately
unpinned Dockerfiles under `fixtures/` and `calib/samples/` cost the last two points. Vulnerabilities
scores 0 for the same reason (the deliberately old packages seeded there; the closures this repository
installs are checked clean by the L0 osv-scanner and trivy steps). The rest is reported. Do not pass
`--commit` to scorecard: naming a commit restricts it to commit-capable checks, which is why the
first run on main reported only 9 of them. `.github/dependabot.yml` keeps the SHA-pinned actions updated weekly; the Python closures
and tool binaries stay outside Dependabot on purpose (they are relocked by hand with hashes and
signatures re-verified, see `docs/tools-provenance.md`).

## Governance checks (Appendix E, prompt 8)

`python scripts/governance_check.py --out docs/governance-check-<date>.md` turns the report's
governance items G-1 to G-13 into checks against this repository and `config/mara.yaml`: each row
is PASS, FAIL or MANUAL (undecidable from files, with the evidence a human must produce), carries
the evidence it looked at and the standard clauses from the report's section 25.4, and any FAIL
makes the script exit non-zero. `.github/workflows/governance.yml` runs it every Monday and posts
the table to a `governance-check` tracking issue. `docs/governance-check-2026-09-12.md` is the
first run: G-2, G-3, G-5, G-6 pass; G-7 (ML-BOM), G-8 (garak/CyberSecEval), G-9 (a live
calibration), G-11 (human-queue ticketing), G-12 (PSIRT hook) and G-13 (AI-literacy records) failed
on that first run; G-1, G-4 and G-10 needed human evidence. Since then every item has a mechanism
and is machine-decidable: G-11 passes; G-12 passes once `psirt.enabled` is set with a real endpoint;
G-7 once the platform team has hashed and signed the weights (`docs/ml-bom.md`); G-13 once one
person per role holds a valid training record (`docs/ai-literacy-training.md`); G-1, G-4 and G-10
once the policy is approved, live swap drills are recorded and the rollout has started
(`docs/governance-templates.md`); G-8 and G-9 once the quarterly red-team evaluation and live
calibration have run on a host with the endpoints (`docs/model-eval-runbook.md`). Nothing is
marked passed before the fact.

## PSIRT hand-off (governance item G-12)

With `psirt.enabled: true` and `psirt.shipped: true` in the config, every accepted finding in the
configured tiers and severities (default: tier A, Critical) is written to
`out/psirt-notifications.json` as an EU CRA Article 14 early-warning payload carrying the evidence
chain and the 24 h / 72 h / 14 d deadlines counted from the review; `mara review --notify-psirt`
POSTs them to the PSIRT webhook with a bearer token from the environment, once per finding: a
send ledger (`ops/psirt/ledger.json`) skips findings whose early warning was already delivered,
records every attempt, and carries the PSIRT's references for the 72 h notification and 14 d final
report; `scripts/psirt_ops.py status` names any stage past its deadline. `scripts/psirt_ops.py
handshake` proves the endpoint accepts the payload with the real token and records it; governance
G-12 requires a fresh successful handshake and no overdue stage, not just `enabled: true`. Policy
P6 keeps the trigger narrow (tiers within A/B, severities within Critical/High, HTTPS, no inline
secret). Whether a vulnerability is actively exploited, the legal trigger of Article 14, remains
the PSIRT's determination. See `docs/psirt-integration.md`; `config/examples/psirt-enabled.yaml`
is a complete example.

## ML-BOM for the self-hosted weights (governance item G-7)

The weights served by the on-prem DeepSeek and Nemotron endpoints are inference dependencies, so
they are listed in a CycloneDX 1.6 ML-BOM. `sbom/models.yaml` is the manifest the platform team
fills (official source, licence, per-file SHA-256 of the safetensors weights, signature method);
`scripts/ml_bom.py` hashes a weights directory (pickle checkpoints are refused) or, with
`registry-hashes`, takes the same per-file SHA-256 straight from the official Hugging Face
repository at a pinned commit without downloading the weights, builds `sbom/ml-bom.cdx.json`, validates it against the vendored schema, re-verifies a directory on the
inference host and checks the cosign bundle with the locked cosign. Policy P7 refuses the config
once `ml_bom.required` is true and a self-hosted model has no complete component; until then
`mara check-config` and the review report show each model's BOM status. Both production entries
are pending in this repository: it hosts no weights and the registry hashes could not be fetched
from the authoring environment, so governance check G-7 stays red and says exactly what is missing.
See `docs/ml-bom.md`.

## Model red-team evaluation and live calibration (governance items G-8, G-9)

`scripts/model_eval.py` turns the config into the exact garak (`openai.OpenAICompatible` or
`anthropic` generator, probes from `model_eval.garak_probes`) and CyberSecEval 4
(`prompt-injection`, `mitre-frr`) commands for every non-mock family, runs them on a host that
reaches the endpoints (keys only from the environment), parses the tools' native outputs, applies
the thresholds in `model_eval.thresholds` and writes `docs/garak-<date>.md`,
`docs/cyberseceval-<date>.md` and `calib/model-eval-<date>.json`. Calibration multiplies a
failing family's suggested weight by `weight_penalty_on_fail` and the review's bias audit shows
the latest verdict per family. `scripts/calibration_run.py --mode live` runs the whole calibration
loop (check-config, every sample, `calibrate.py --mode live`) and both scripts refuse to label
mock or fixture-based output as live. Governance checks G-8 and G-9 read the reports' front
matter (`mode: live`, families covering the config, within 90 days). Nothing has run here: no
endpoint, no key, no garak; `fixtures/model-eval/` holds synthetic outputs for the parser tests.
See `docs/model-eval-runbook.md`.

## Policy, cold standby and rollout templates (governance items G-1, G-4, G-10)

The three items that needed a human now have machine-readable templates, so the weekly check
decides and says what is missing: `docs/policy/mara-review-policy.md` (front matter with
`status`/`approved_by`/`approved_on`/`review_by` and six marked mandatory statements; shipped as a
draft), `config/examples/standby-for-<family>.yaml` plus `ops/model-swap-drills.yaml` and
`scripts/model_swap_drill.py` (`rehearse` proves the process is unchanged on a mock panel, `record`
logs a live swap timed from decision to first real PR; shipped empty), and `rollout:` in
`config/mara.yaml` with `scripts/rollout_phase.py` (`status`, `baseline`, `advance`). The rollout
phase changes behaviour: `mara review` exits 2 on a blocked gate only in `blocking`. All three fail
today for the stated reasons: the policy awaits PSO approval, no live drill has run, the rollout
has not started. See `docs/governance-templates.md`.

## AI-literacy training (governance item G-13)

EU AI Act Article 4 requires the people operating the pipeline to be AI-literate.
`training/curriculum.md` is the half-day module (evidence tiers, the bias audit, "a pass is not a
proof of security", deciding tickets, prompt injection through code), `training/quiz.yaml` the
knowledge check, `training/records.yaml` the register written by `scripts/training_register.py`
(`assess` grades the quiz and records a pass; `add` records an instructor-led session; `check`
reports coverage per role and expiries). Records are keyed by GitHub login: the human-queue sync
records who applied each decision label and whether they hold a valid adjudicator record, and
calibration applies only trained adjudicators' decisions while
`training.require_trained_adjudicator` is true. The register is empty in this repository, so
governance check G-13 fails naming the three roles. See `docs/ai-literacy-training.md`.

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
