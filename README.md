# MultiAgentAlpha — MARA (Multi-Agent Review Architecture)

Heterogeneous-model, multi-agent **security and architecture review for vibe-coded software**,
anchored to deterministic tools and designed so that no single language model's bias can
decide the outcome.

This repository contains two things:

1. **The research report** (正體中文, GSMD series): `docs/GSMD-RPT-2026-0908-01_多模型多代理資安審查.md`
   with an online single-file HTML edition next to it, published at
   <https://chinchiang.github.io/MultiAgentAlpha/> (GitHub Pages, see below). It covers the architecture, the scoring
   method, the data-credibility model, the bias catalogue and its mitigations, a comparison of
   commercial and academic alternatives, deployment for a multinational ODM/EMS (including the
   CSL/DSL/PIPL isolation rule for PRC sites), limitations, and governance recommendations mapped
   to ISO/IEC 27001:2022, IEC 62443-4-1, EU CRA, NIST SSDF and ISO/IEC 42001.
2. **A runnable prototype** (`src/mara`) that implements the six-layer architecture the report
   describes. It runs fully offline with mock providers, and against live models (Anthropic API
   plus self-hosted DeepSeek / Nemotron behind an OpenAI-compatible endpoint) when configured.

## Online report (GitHub Pages)

The HTML edition of the report is served by GitHub Pages straight from the `docs/` folder of
`main` (Settings → Pages → Deploy from a branch → `main` / `/docs`), so no workflow and no
`pages: write` / `id-token: write` token are involved; the governance check G-6 and the Scorecard
Token-Permissions floor stay as they are. `docs/.nojekyll` makes GitHub serve the files as they
are (Jekyll would otherwise try to build the Markdown and mishandle the non-ASCII report file
name), and `docs/index.html` is a self-contained redirect to the report, so the public address is
just <https://chinchiang.github.io/MultiAgentAlpha/>. Pages has been live since 2026-09-17 (the "pages build and deployment" runs in the Actions tab are
the deployment record). **The site stays public while the repository is private**: after the
repository became private on 2026-09-21, Pages kept building on every push to `main`, and on
2026-09-24 the address, the report and the other `docs/` files still answered 200 to an anonymous
request (the Pages API reports `public: true`). Keeping it public is the owner's decision of
2026-09-24; to take the report offline instead, unpublish the site under Settings → Pages. The
private repository therefore protects the source tree, the fixtures and the history, not `docs/`.
Everything under `docs/` is reachable at that address, so it must contain only intended public documentation:
the report, its parts, the appendices, the dated assessment, calibration, inventory, governance and
ground-truth records, the runbooks and the changelog. Before the 2026-09-18 remediation, Pages served
the repository root; it now serves `/docs` only, and the deliberately vulnerable fixture URLs return
404. Two files at the repository root are defence in depth for the day someone switches the source
back to the root by mistake: `index.html` is a self-contained redirect to `docs/`, and `_config.yml`
tells Jekyll to exclude `fixtures/`, `calib/`, the source tree and the other non-documentation
directories, so the seeded vulnerable material is never published either way.
`tests/test_docs_site.py` checks that the redirect points at a file that exists and loads nothing off-site.
`.github/workflows/docs-check.yml` (Appendix E prompt 1) runs on every pull request that touches `docs/`:
it rebuilds the report from `docs/parts/` and requires the result to be byte-identical to the committed
file, fails when the body is under 20,000 characters, and fails when a citation marker has no row in
Appendix A. `docs/CHANGELOG.md` records each version with its verification status.

## Security remediation (2026-09-18)

See [the remediation record](docs/security-remediation-2026-09-18.md) for review IDs, changed controls,
validation and remaining operational requirements. The review gate now fails closed when coverage,
tool health, valid independent votes or human adjudication is missing. `overall_score` is `null`
for incomplete reviews; scores on completed reviews are prioritization heuristics, not probabilities
that the application is secure. Single-finding agreement is named `agreement_proxy`, distinct from
corpus-level Krippendorff alpha. The older alpha-named configuration keys remain for compatibility.

Git targets include tracked source only. Secret files, symlinks, unsafe paths and file/request-size
limits are visible in the coverage manifest; omitted required text prevents a complete result. Live
model calls require a current local secret preflight, even when other SARIF was pre-recorded. Use
HTTPS for self-hosted endpoints; HTTP is accepted only on loopback. The three-family example can
lack two independent judge families when several reviewers find the same issue; add independently
operated families or complete human review instead of weakening the quorum.

## The six layers

| Layer | What it does | Where |
|---|---|---|
| L0 deterministic anchors | semgrep, gitleaks, osv-scanner, zizmor, trivy, csp-evaluator → SARIF. Ground truth and calibration set. | `mara/tools` |
| L1 context | Repo map, entry points, workflows, manifests; strips authorship signals. Facts, not judgements. | `mara/context` |
| L2 reviewers | 11 dimensions × ≥2 model families, independent, structured JSON only. | `mara/agents/reviewer.py`, `mara/prompts` |
| L3 adversarial | Skeptic (must be a different family than the finder) tries to refute; red team states exploitability. | `mara/agents/skeptic.py`, `redteam.py` |
| L4 jury | Blinded findings (no identity, no scores, fixed width), forward + reverse order, a family never judges its own finding when enough independent judges exist. | `mara/agents/judge.py`, `mara/bias` |
| L5 scoring | CVSS 4.0 computed by code (FIRST-equivalent), SSVC decision, weighted consensus, Krippendorff's α, evidence tier A–D, dimension scores, gate, SARIF 2.1 + Markdown. | `mara/scoring`, `mara/report` |

Three rules are enforced by code, not by prompt:

- **Provenance**: every finding must quote a verbatim excerpt that exists in the file (±3 lines) and pins something: at least 8 non-whitespace characters including a letter or digit, unless the quote is the whole claimed line (so `flask` in a requirements file still counts, `}` or `if ` never does). Fabricated or trivial quotes are tier D and never accepted.
- **Pinned ground truth**: standard ids (ASVS 5.0 chapters, OWASP Top 10:2025, API Top 10 2023, LLM Top 10 2025, CWE subset) are validated against `mara/groundtruth/*.json`; unknown ids are stripped.
- **Data residency**: source code is only sent to models declared `on_prem` or `vendor_api_zdr`. The default config refuses anything else.

Found a security problem in this repository's own code? See [SECURITY.md](SECURITY.md)
(private vulnerability reporting; the seeded fixtures are out of scope by design).

## Quick start (offline)

Step-by-step installation (bilingual, 正體中文 / English), including how to obtain the private repository, the non-Linux fallback and the optional tool and live-model layers, is in [INSTALL.md](INSTALL.md).

```bash
python -m pip install --require-hashes --only-binary=:all: -r tools/dev-requirements.txt   # the resolved, hash-pinned closure
python -m pip install --require-hashes --only-binary=:all: -r tools/build-requirements.txt # build backend closure
python -m pip install --no-deps --no-build-isolation -e .                                    # use only the pinned backend
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

A failed provider call is recorded as a provider error (`reviewer_errors`, per family), not as a
refusal, so a rate limit or an outage is never charged to the model in the bias audit or the
calibration refusal rate; like refusals and truncations it makes the review incomplete and the gate
fails. The OpenAI-compatible provider retries timeouts, transport errors and 408/429/500/502/503/504/529
up to three calls in total, with exponential backoff and jitter or the server's `Retry-After`
(at most 30 s); other statuses fail at once. The Anthropic SDK retries on its own. A response that
stops at the output limit (`finish_reason: length`) is a truncation even when its content is empty, as
with a reasoning model that spent the whole budget thinking; only a content filter or an empty answer
that did not hit the limit counts as a refusal. The OpenAI-compatible provider never uses the
`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` environment variables: its endpoints are on-prem, and a proxy
would receive the source code (in cleartext for an `http://` loopback endpoint). `SSL_CERT_FILE` and
`SSL_CERT_DIR` still apply, for an internal CA.

### Incremental review

On a git repository, `--base <ref>` narrows the bundle to the files changed since that ref, the
files they import or that import them (Python and relative JS/TS specifiers), plus the manifests and
GitHub workflows. Everything else is excluded with the reason `out_of_increment` in the report's
coverage section — never silently kept; a changed file the bundle cannot show fails the run, and an
unresolvable ref is a usage error, not an empty "nothing changed":

```bash
mara review path/to/repo --config config/mara.yaml --base origin/main --out out
```

CI exercises the mode on every pull request and push: the `tests + mock review` job runs the seeded
fixture a second time with `--base` set to the merge-base commit (the report lands in the
`mara-report` artifact next to the full review; schedule and dispatch runs have no base commit and
skip that step).

Before the reviewers run, a separate context agent builds a C4-lite view of the architecture
(containers, external systems, trust boundaries, data stores) in one provider call. Every fact must
cite a bundle file:line with a verbatim quote and passes the same provenance check as findings;
unverifiable items are dropped and counted, and a refusal, an echoed canary or a view with no
verifiable fact leaves the reviewers without trusted facts and marks the run incomplete. The
architecture and authn_authz reviewers receive the verified facts as a `<trusted_context_facts>`
block that is explicitly not part of the untrusted data.

## Calibration (Appendix E, prompt 4)

`calib/samples/` holds five labelled vibe-coded samples (51 labels). The loop runs offline with
label-driven mock families and produces `docs/calibration-<date>.md` with per-family, per-CWE
precision and recall, refusal, provider-error and canary rates, per-role refusal and invalid-output
rates, skeptic refutation rates, judge-family agreement, a Dawid-Skene reliability
estimate and suggested weights (discounted by refutation and invalid-output rates; never written to
the config automatically):

```bash
for s in calib/samples/*/; do mara review "$s" --provider mock --out calib-out/$(basename "$s"); done
python scripts/calibrate.py --mode mock
```

For a live run point the same commands at `config/mara.yaml` (three reachable family endpoints,
ZDR enabled) and pass `--mode live`. `scripts/fetch_calib_corpora.sh` fetches OWASP Juice Shop
and WebGoat; they need human-authored `labels.json` files before they count. A sample's
`labels.json` is its answer key and never reaches a model: the bundle excludes it (coverage reason
`calibration_answer_key`; recognised by its content, so an unrelated `labels.json` is still reviewed),
the label-driven mocks read it from disk, and `calibrate.py --mode live` refuses any run whose bundle
included it. A `calib-out/<sample>` without its own `labels.json` is skipped with a message, never
scored against other labels.

The Alternative Annotator Test that policy P8 relies on has two parts, both required. Agreement: the
unsupervised label against the human decisions, at least 0.8 on at least 10 items and better than the
chance agreement of the two label distributions (one-sided exact binomial test, p < 0.05), so a
pipeline that always gives one answer never passes. Rejection safety: among the findings the pipeline
would itself reject unsupervised (the set P8 unlocks), the share humans confirmed as real must have a
95% Clopper-Pearson upper bound of at most 5%, which takes at least 59 decided rejections without a
miss. Decisions bind to findings one to one by their v2 key, and P8 only accepts results tagged with
the current method.

## Policies enforced by the config

`mara check-config <yaml>` evaluates eight policies and exits non-zero if any fails; `MaraConfig`
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
| P8 unsupervised-reject | `gate.unsupervised_reject_allowed` may be `true` only while `calib/latest.json` records a passing Alternative Annotator Test (current method: chance-corrected agreement and a bounded miss rate on the rejections themselves, see Calibration) on a live calibration within 90 days; while `false` every rejected non-D finding goes to the human queue |

`config/examples/violating.yaml` breaks the first five and is what the tests run against. Every
section of the config refuses unknown keys, not only the top level and `gate`: a misspelt
`psirt: {enable: true}`, `ml_bom: {requried: true}` or `rollout: {phse: blocking}` fails to load
instead of falling back to the weaker default.

## Gap assessment (Appendix E, prompt 3)

Four runs score this repository's review process against the 60-question questionnaire in
`docs/appendix-d-maturity.md`: `docs/assessment-2026-09-12.md` (134/240), `docs/assessment-2026-09-26.md`
(152/240, L0 up from 13 to 23 now that the scanners run blocking from the lock), `docs/assessment-2026-10-01.md`
(170/240, twelve questions up after v0.3.10–v0.3.12) and the current `docs/assessment-2026-10-03.md` (171/240,
incremental review now runs in CI; the v0.3.13–v0.3.15 hardening — gate validation, the semgrep relock that
removed thirteen expiring exceptions, corroboration dimension limits, content-ordered finding ids — strengthened
evidence without crossing a scoring line; L5 lowest at 24, L0 next at 27 — the recorded blocker is the first
real-family run, not code). Each run has a file-level
evidence cell on every row, per-layer totals, the two lowest questions per layer mapped to governance
items G-1 to G-13, and a separate CN-1 to CN-4 table for the PRC sites. `scripts/score_assessment.py <file>` checks the
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
inventoried line by line and flagged. `docs/actions-inventory-2026-09-12.md` is the first run
(`docs/actions-inventory-2026-10-03.md` is the current one: four real workflows, all rated None, with
the new job-level `timeout-minutes` detection — the seeded fixtures keep their deliberate gaps and
stay Critical); its section 6 adds what the CI logs showed that the static inventory cannot, and the fixes that
followed: CI now runs zizmor strictly on the real workflows, checks that zizmor's findings on the
seeded fixture match `fixtures/vuln-sample-sarif/zizmor.sarif` (now produced by zizmor itself), and
no longer hides a crashed or leaking gitleaks run behind `continue-on-error` (`.gitleaks.toml`
allowlists exact known synthetic values; all fixture paths remain scanned). Since 2026-09-13 the scan
itself is `scripts/gitleaks_ci.py` with the gitleaks pinned in `tools/versions.lock` (PR: the PR's
commits; push: every new commit), not gitleaks-action, so no action downloads its own tool and the
L0 job needs no `pull-requests` permission.

## Pinned, verified L0 tools (Appendix E, prompt 7)

`tools/versions.lock` pins every deterministic tool (gitleaks, osv-scanner, zizmor, trivy, semgrep,
csp-evaluator, plus the verifiers cosign and slsa-verifier) by exact version, download URL and SHA-256, and names
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
Linux x86_64 and installed with `--require-hashes`. `tools/dev-requirements-py312.txt` is the same
closure for CPython 3.12, resolved with `--same-versions-as tools/dev-requirements.txt` so only the
wheels and hashes differ; the `tests (CPython 3.12)` job installs it and runs the test suite, and runs
`mypy` (configured in `pyproject.toml`) from `tools/typecheck-requirements.txt`, a third closure pinned to the
same versions for every package it shares; the workflows then add this repository's own
code with `pip install --no-deps --no-build-isolation -e .` after installing the hashed
`tools/build-requirements.txt` closure. The runtime CI path does not let build isolation resolve
unpinned backends. The separate model-evaluation closure contains two source distributions;
the runbook also uses the hashed build closure with `--no-build-isolation`. Both sdists were
successfully built this way; a full live evaluation still requires the deployment environment.

## semgrep and osv-scanner in CI (L0 job)

Since 2026-09-13 the `deterministic-tools` job runs both scanners from the lock, through two
scripts that refuse anything not installed by `scripts/install_tools.py` and any version that
differs from the lock:

- `scripts/semgrep_ci.py --target fixtures/vuln-sample --expect fixtures/vuln-sample-sarif/semgrep.sarif`
  scans the seeded fixture with the pinned rulesets and fails on any drift from the recording
  (which is real semgrep 1.179.0 output, 15 findings — identical to the 1.177.0 recording it replaced,
  rule ids normalised to the registry form).
- `scripts/semgrep_ci.py --target . --triage tools/semgrep-triage.yaml` scans the repository
  (minus the seeded `fixtures/` and `calib/samples/`); every finding must be covered by a triage
  entry with a reason or the job fails, covered findings are uploaded with a SARIF `suppressions`
  record, and entries that no longer match anything are reported as stale.
- `scripts/osv_ci.py --target fixtures/vuln-sample --expect-package requests` must see the
  fixture's `requests==2.19.0` flagged, so a silent scanner or database regression is caught.
- The bootstrap, dev, typecheck and build closures use `tools/osv-scanner.toml` with no advisory
  exclusions. The model-evaluation closure is scanned separately with `tools/osv-model-eval.toml`
  (its dated exceptions cover garak's nltk/datasets pins); the semgrep tool closure is scanned with
  `tools/osv-semgrep.toml`, which has been exception-free since semgrep 1.179.0 relaxed the
  `pyjwt[crypto]~=2.13.0` pin and the closure relocked to pyjwt 2.15.1. These scans
  also run weekly and on manual workflow dispatch.

semgrep runs with `--metrics=off --disable-version-check` and explicit local rule directories
(never `--config auto`), so nothing is sent to semgrep.dev; osv-scanner runs `scan source
--no-resolve`, so only package names and versions go to api.osv.dev and nothing to deps.dev. All
SARIF files land in the `l0-sarif` artifact, and the eight scans of the repository itself (six tools; osv-scanner
twice more: the model-evaluation and semgrep tool closures) are also uploaded to GitHub Code Scanning (see below). `mara review` uses the same pinned rulesets by default
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

## Code Scanning and Scorecard

GitHub Code Scanning is free for public repositories and needs GitHub Advanced Security for private
ones. The repository was public from 2026-09-14 and has been private since 2026-09-21, so the upload
is now conditional: the read-only L0 job of `mara-review.yml` always runs `scripts/code_scanning_prep.py`
and publishes the `code-scanning` artifact (accepted suppressions and locationless results are
filtered, paths are repository-relative, and each tool has a category), and the separate
`code-scanning` job downloads that prepared artifact and uploads it with
`github/codeql-action/upload-sarif` only while `github.event.repository.private` is false. It is the
only job with `security-events: write`, it runs no repository code, and it is also skipped for pull
requests from forks or Dependabot (read-only token). While the repository is private the job shows as
skipped and the twelve SARIF files are still available in the `l0-sarif` artifact of every run. The
whole Scorecard job is gated the same way: the read-only token cannot run scorecard's GraphQL queries
on a private repository (the runs of 2026-09-21 and 2026-09-22 failed with "Resource not accessible by
integration"), so the job is skipped until the repository is public again. In its place the
`scorecard-local` job of the same workflow runs the same locked CLI with `scorecard_ci.py --local .`:
the committed tree (exported with `git archive`, so the tools installed into the workspace are not
scanned) is analysed offline without a token, and the six enforced checks, which are all file-based,
still fail the run below their minimums; the API-only checks (Branch-Protection, Code-Review,
Maintained, ...) are not run in that mode and the SARIF stays in the `scorecard-local` artifact. The fixture scans and the mock review report
are never uploaded: they describe seeded material.

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
the table to a `governance-check` tracking issue. The first run (2026-09-12) had G-2, G-3, G-5, G-6 pass; G-7 (ML-BOM), G-8 (garak/CyberSecEval), G-9 (a live
calibration), G-11 (human-queue ticketing), G-12 (PSIRT hook) and G-13 (AI-literacy records) failed
on that first run; G-1, G-4 and G-10 needed human evidence. Since then every item has a mechanism
and is machine-decidable: G-11 passes; G-12 requires a successful endpoint handshake and no overdue confirmed stage;
G-7 once the platform team has hashed and signed the weights (`docs/ml-bom.md`); G-13 once one
person per role holds a valid training record (`docs/ai-literacy-training.md`); G-1, G-4 and G-10
once the policy is approved, live swap drills are recorded and the rollout has started
(`docs/governance-templates.md`); G-8 and G-9 once the quarterly red-team evaluation and live
calibration have run on a host with the endpoints (`docs/model-eval-runbook.md`). Nothing is
marked passed before the fact. `docs/governance-check-2026-09-12.md` was regenerated in place as those
mechanisms landed (last on 2026-09-17), so it shows the later state rather than the first run;
`docs/governance-check-2026-09-26.md` is the current record: G-2, G-3, G-5, G-6 and G-11 pass, the
other eight fail for the reasons above, none is MANUAL.

## PSIRT hand-off (governance item G-12)

With `psirt.enabled: true` and `psirt.shipped: true` in the config, every accepted finding in the
configured tiers and severities (default: tier A, Critical) is written to
`out/psirt-notifications.json` as a `mara-psirt/2` internal hand-off carrying the evidence chain.
Review time anchors only internal service targets. Legal deadlines stay empty until PSIRT confirms
an event type and awareness timestamp; the final-report anchor depends on that event type.
`mara review --notify-psirt` POSTs the hand-off to the configured webhook with an environment token.
The send ledger (`ops/psirt/ledger.json`) deduplicates internal hand-offs. After confirmation, use
`scripts/psirt_ops.py confirm-event --key … --event event.json --reference …` to update the event
and deadlines without resetting delivery history; `record` records the PSIRT's legal-stage references.
`scripts/psirt_ops.py status` distinguishes unknown legal anchors from recorded overdue stages. `scripts/psirt_ops.py
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
logs a live swap timed from decision to first real PR; mock rehearsals for all three families are recorded, live drills are still missing), and `rollout:` in
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
raises the alpha threshold and — with `human_queue.tighten_exclude_tier_c`, the default — stops queuing
tier C at `human_queue.queue_tier_c_min_severity` (the jury's consensus then decides those findings); it
never loosens. The `human-queue` CI job runs
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
