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
   describes. It runs fully offline with mock providers, and against live models (Claude on Amazon
   Bedrock, Gemini through the Gemini API and a self-hosted GLM behind an OpenAI-compatible
   endpoint) when configured.

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
`.github/workflows/docs-check.yml` (Appendix E prompt 1) runs on every pull request and every push to `main`
that touches `docs/`, the three report scripts or the workflow itself:
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

Git targets include tracked source only: a repository root and any directory tracked in a
repository's HEAD (a subdirectory such as `fixtures/vuln-sample`) are read through `git ls-files`, and
if git cannot answer (dubious ownership, a broken index) the review fails closed with
`git_ls_files_failed` instead of walking the tree. Only a directory outside any committed history
(including one that merely sits inside a home-directory dotfiles repo) is walked.

MARA's own trust anchors live in the MARA workspace, never in the code under review: the pinned
tools (`.mara-tools`, or `MARA_TOOLS_DIR`), policy P8's evidence `calib/latest.json`, the human-queue
backlog, the ML-BOM and the PSIRT ledger resolve against `MARA_HOME` when set, the working directory
otherwise; so do the defaults of `mara review --config` (`config/mara.yaml`, `config/mara.mock.yaml`
with `--provider mock`), `--out` (`out`) and `mara check-config`. `mara review` refuses a target that
contains the workspace, the tool directory, the trivy database, the config file or the output directory
(`cd target && mara review .` would let the reviewed repository supply the binaries the runner
executes, the evidence the policies trust and the config itself, and the reports of one run would be
bundled into the next); run it from the workspace (`mara review path/to/target`) or set `MARA_HOME`
outside the target. Secret files, symlinks, unsafe paths and file/request-size
limits are visible in the coverage manifest; omitted required text prevents a complete result. Live
model calls require a current local secret preflight, even when other SARIF was pre-recorded; the only
exception is `--calibration-sample` (see Live mode). Use
HTTPS for self-hosted endpoints; HTTP is accepted only on loopback. The three-family example can
lack two independent judge families when several reviewers find the same issue; add independently
operated families or complete human review instead of weakening the quorum.

## The six layers

| Layer | What it does | Where |
|---|---|---|
| L0 deterministic anchors | semgrep, gitleaks, osv-scanner, zizmor, trivy, csp-evaluator → SARIF. Ground truth and calibration set. | `mara/tools` |
| L1 context | Repo map, entry points, workflows, manifests; strips authorship signals. Facts, not judgements. | `mara/context` |
| L2 reviewers | 11 dimensions × ≥2 model families, independent, structured JSON only. | `mara/agents/reviewer.py`, `mara/prompts` |
| L3 adversarial | Skeptic (must be a different family than the finder) tries to refute; red team states exploitability. Both read repository files and carry their own canary; a refutation must cite a non-blank line of a file the skeptic was shown; a reply that does not cover every finding exactly once counts one invalid item per gap, and its findings stay unchallenged (no tier B). | `mara/agents/skeptic.py`, `redteam.py` |
| L4 jury | Blinded findings (no identity, no scores, fixed width), forward + reverse order, a family never judges its own finding when enough independent judges exist. | `mara/agents/judge.py`, `mara/bias` |
| L5 scoring | CVSS 4.0 computed by code (identical to FIRST's `cvss_score.js` on all 419,904 base × E vectors, rounding halves up), SSVC decision, weighted consensus, Krippendorff's α (one label per judge family per finding), evidence tier A–D (tier A needs a tool result at level error or warning in the same file — the exact path, or the target's own path below the repository top level plus it — within ±3 lines), dimension scores, gate, SARIF 2.1 + Markdown. | `mara/scoring`, `mara/report` |

Three rules are enforced by code, not by prompt:

- **Provenance**: every finding must quote a verbatim excerpt that exists in the file (±3 lines) and pins something: at least 8 non-whitespace characters including a letter or digit, unless the quote is the whole claimed line (so `flask` in a requirements file still counts, `}` or `if ` never does). Fabricated or trivial quotes are tier D and never accepted.
- **Pinned ground truth**: standard ids (ASVS 5.0 chapters, OWASP Top 10:2025, API Top 10 2023, LLM Top 10 2025, CWE subset) are validated against `mara/groundtruth/*.json`; unknown ids are stripped.
- **Data residency**: source code is only sent to models declared `on_prem` or `vendor_api_zdr`, or `vendor_api_retained` with a recorded `retention_approval_ref` for that model. The default config refuses anything else.

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
export AWS_PROFILE=...              # Bedrock: the AWS default credential chain, e.g. after `aws sso login --profile ...`
export GEMINI_API_KEY=... GLM_LOCAL_KEY=...
mara check-config config/mara.yaml
mara review path/to/repo --config config/mara.yaml --out out
python3 scripts/live_smoke.py       # tests: one call per model of config/mara.test.yaml (Claude Haiku 4.5)
```

Tests against the real endpoints use `config/mara.test.yaml`: the production panel with Claude Haiku 4.5
(`global.anthropic.claude-haiku-4-5-20251001-v1:0`) in Claude's seat, cheaper and faster than Opus 5.5.
`AWS_MODEL`, when set, replaces that model (`model_env: AWS_MODEL`); the value is applied before validation,
so the policies judge the model actually called, and the production config never reads it.
`scripts/live_smoke.py` calls every model of a config once through MARA's own providers and exits 1 if any
fails to answer. Haiku 4.5 and Sonnet 4.5 accept neither adaptive thinking nor `effort` on Bedrock, so the
provider sends them extended thinking with a fixed budget instead; Opus 5.x keeps adaptive thinking at effort
high. Production reviews and calibration (G-9) keep `config/mara.yaml`.

`config/mara.yaml` is the production panel since v0.4.2 (2026-10-07): Claude Opus 5.5 on Amazon Bedrock
(`provider: bedrock`, the `global.` cross-region inference profile, `region` required, SigV4 through
boto3; declared `vendor_api_zdr` on Bedrock's terms that prompts and completions are neither stored nor
used for training: keep the account's model invocation logging off, or that log holds the source code; Bedrock refuses
structured outputs and a forced tool choice for Opus 5.x, so the answer comes back as the input of one `submit_result`
tool call), Gemini through the
Gemini API on the paid tier (`provider: gemini`, the key in the `x-goog-api-key` header, never the
URL; structured output through `responseJsonSchema`), and a GLM model self-hosted on the IEC network
behind an OpenAI-compatible endpoint (`on_prem`; the gateway serves it as `model: glm`, and the same endpoint and
key serve the standby DeepSeek as `model: deepseek`). The Gemini API keeps prompts for a limited period
and is not ZDR, so the model is declared `vendor_api_retained` and policy P5 admits it only with
the approval recorded in `retention_approval_ref`; any other retained model still fails. GLM is
PRC-affiliated: policy P2 holds it to on-prem endpoints and refuses its vendor APIs (bigmodel.cn,
z.ai) exactly like DeepSeek's. No model id in the file is provisional any more: the Gemini and GLM ids were
checked against their endpoints' model lists on 2026-10-07 (the comments next to them record it), and all three
models answered in the live calibration of 2026-10-08. Check a new id the same way before its first live run. G-8 runs garak against all three families
(Claude through garak's `bedrock` generator, Gemini and GLM through OpenAI-compatible endpoints) and
CyberSecEval against Gemini and GLM; CyberSecEval has no Bedrock provider (see G-8 below). See the report, Part VIII, for the
site-by-site deployment pattern and the separate handling of 上海／重慶.

The organisation's private DNS zones go in `private_dns_suffixes` (`.iec.inventec`), which P2 and P5
then treat like `.internal`; a zone needs two labels and lower case, so `.com` or a single label is
refused. An endpoint signed by an internal CA names its PEM chain in `ca_bundle` (`~` and
workspace-relative paths): it is added to the default trust store and never replaces or disables
verification. A gateway that expects the key in another header (`apikey`) sets `api_key_header`.
An `openai_compatible` model declared `vendor_api_zdr` or `vendor_api_retained` sends the code (and its
`api_key_env` value as the bearer token) to whatever `base_url` names, so P5 admits it only when that
host is listed, exactly, in `vendor_api_hosts` (the vendor endpoints the organisation's contract covers);
the SDK providers call a fixed vendor endpoint and need no list.
The cold standbys in `config/examples/standby-for-{anthropic,gemini,glm}.yaml` each replace one
family with the on-prem DeepSeek endpoint and leave everything else unchanged (G-4). A family may have
further standbys as `standby-for-<family>.<name>.yaml`; every one of them must load and swap exactly that
family, and a passing live drill on any one of them counts for the family.

What the first live reviews against these endpoints showed (2026-10-07), each fixed with a regression test:

- **Claude on Bedrock answered HTTP 400 on every call.** Bedrock refuses `output_config.format` and
  `tool_choice` tool/any for Opus 5 and 5.5; the schema is now the input_schema of one `submit_result` tool
  (tool_choice auto), and the agents' pydantic models validate the input. The direct-API path now sends
  `anthropic.transform_schema(schema)` (structured outputs reject minLength, pattern, maxItems...).
- **The gateway renamed its models.** The key may access only `glm` and `deepseek` on one endpoint;
  `GLM-5.3-Flash-FP8` answered 403 and the old DeepSeek endpoint 401.
- **Canary reports read as echoes.** Every model reported the planted canary file as a prompt-injection
  attempt and quoted it, token included, next to its real findings; the substring check dropped every
  finding of the call. Findings and context facts that cite the planted file are now set aside and counted
  (`canary_reports`, `[CANARY REPORTED]`); the token anywhere else, prose around a Bedrock tool call
  included, still drops the whole call.
- **Full-match patterns.** A grammar-constrained decoder (the gateway's strict `json_schema`) matches a
  `pattern` against the whole string, so the prefix-only `^CVSS:4\.0/` admitted nothing but `CVSS:4.0/` and
  every gateway finding failed validation. The CVSS pattern is anchored at both ends now.
- **Cut-off strings.** Those decoders enforce `maxLength` by ending the string mid-sentence, after which GLM
  closed the whole answer early; Claude, which sees bounds only as descriptions, overran them (a 671-character
  skeptic reason) and pydantic discarded the whole batch. String bounds now travel as descriptions to the
  gateway, and every provider clips the answer to them (`providers.base.clip_strings`).
- **Thinking budget.** Reasoning tokens count against `max_tokens`: GLM as skeptic ran out at 16000 and
  finished at 13861 with 32768, now the OpenAI-compatible default (the gateway's models accept a 1M-token
  context); Claude, with adaptive thinking at effort high, gets 64000 on a streamed request.
- **Constrained decoding and a reasoning model.** Even so, GLM as skeptic answered an empty list after ~15k
  reasoning tokens, three times out of three; with the schema as guidance only it answered every finding.
  `strict_schema: false` (openai_compatible) does that and is set for `glm-reviewer`; DeepSeek keeps strict
  decoding. Every answer is re-validated either way, and one ```json fence is tolerated.
- **Nondeterministic replies.** Even without strict decoding GLM sometimes answered four skeptic verdicts for three
  findings, and the next call exactly three. A skeptic, red-team or judge reply the agent rejects as malformed, cut off
  or not covering every finding exactly once is now asked once more (`<role>_retries` in the bias audit); refusals,
  canary echoes and provider failures are never retried, and only the answer used counts toward completeness.
- **zizmor on a repository without GitHub Actions** exits 3 (`no inputs collected`), which marked every such review
  incomplete. MARA now checks the target itself (no workflow, `action.yml` or dependabot file, symlinks not
  followed) and only then records zizmor as run with no results; any other exit 3 is still a failed scan.

The labelled calibration samples under `calib/samples/` carry planted credentials on purpose, so the
secret preflight would block every live calibration call. `mara review --calibration-sample`
(`scripts/calibration_run.py` sets it only for targets below `calib/samples/`) exempts exactly the
gitleaks findings whose file and line match a CWE-798 label in the sample's MARA answer key; any
other secret, a target elsewhere, or a sample without an answer key still blocks live egress, and
the exemption is written to the audit trail.

A failed provider call is recorded as a provider error (`reviewer_errors`, per family), not as a
refusal, so a rate limit or an outage is never charged to the model in the bias audit or the
calibration refusal rate; like refusals and truncations it makes the review incomplete and the gate
fails. The OpenAI-compatible provider retries timeouts, transport errors and 408/429/500/502/503/504/529
up to three calls in total, with exponential backoff and jitter or the server's `Retry-After`
(at most 30 s); other statuses fail at once. The Anthropic SDK retries on its own. Every reply is
classified once, for every family, by `mara/exchange.py` (the adapters only report the vendor's stop
reason and text; `CONTEXT.md`, `docs/adr/0001-reply-outcome-accounting.md`): a reply stopped at the
output limit (`finish_reason: length`, `max_tokens`, `MAX_TOKENS`) is a truncation even when its content
is empty, as with a reasoning model that spent the whole budget thinking, and is never charged to the
model (skeptic, red team and judge truncations have their own `*_truncations` counters, which make the
review incomplete); a reply that ended normally without the structured answer is an unparseable reply,
invalid output counted under `*_unparseable_replies` too; a refusal stop or content filter is a refusal;
an empty reply is an abstention for the reviewers and the context agent and invalid output for the
ballots. A single ```` ```json ```` code fence around the answer is accepted from any family. Reports
carry `exchange_version` in the bias audit, and the calibration trend compares only periods of one
version. The same module lays every role's prompt out (`build_prompt`): only MARA's own instructions
stand outside a fence; repository data - the files, and the repository summary, whose names and routes
come from the repository - is inside `<untrusted_repository_data>`, and derived data - the context facts
for the reviewers, the findings with their verbatim quotes for the skeptic, red team and judges - inside
`<derived_data kind="...">` with `<`, `>` and `&` escaped (`tests/test_prompt_fences.py` plants a sentinel in
every repository-derived field and checks every role's prompt). The OpenAI-compatible provider never uses the
`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` environment variables: its endpoints are on-prem, and a proxy
would receive the source code (in cleartext for an `http://` loopback endpoint). `SSL_CERT_FILE` and
`SSL_CERT_DIR` still apply, for an internal CA.

### Incremental review

On a git repository, `--base <ref>` narrows the bundle to the files changed since that ref, the
files they import or that import them (Python and relative JS/TS specifiers; `from app import models`
and `from . import models` count as importing `app.models`), plus the manifests and GitHub workflows.
Everything else is excluded with the reason `out_of_increment` in the report's coverage section —
never silently kept; a changed file the bundle cannot show fails the run, files the increment deletes
are listed under `deleted` (there is nothing left to show, so they do not make the run incomplete), and
an unresolvable ref is a usage error, not an empty "nothing changed":

```bash
mara review path/to/repo --config config/mara.yaml --base origin/main --out out
```

CI exercises the mode on every pull request and push: the `tests + mock review` job runs the seeded
fixture a second time with `--base` set to the pull request's base commit (`pull_request.base.sha`) or, on
a push, the previous head (`github.event.before`); MARA diffs `<base>...HEAD`, i.e. from their merge base (the report lands in the
`mara-report` artifact next to the full review; schedule and dispatch runs have no base commit and
skip that step).

Before the reviewers run, a separate context agent builds a C4-lite view of the architecture
(containers, external systems, trust boundaries, data stores), one provider call per bundle batch
(the same request bound as the reviewers; facts are merged, de-duplicated and capped at 12 per kind,
and any refused, echoed or unusable batch voids the view). Every fact must
cite a bundle file:line with a verbatim quote and passes the same provenance check as findings;
unverifiable items are dropped and counted, and a refusal, an echoed canary or a view with no
verifiable fact leaves the reviewers without context facts and marks the run incomplete. The
architecture and authn_authz reviewers receive the verified facts as a `<derived_data kind="context_facts">`
block that is labelled, like the bundle, as untrusted data: the quote check proves only that the quoted text
exists, and that text is repository content (the seeded README's "already passed security review"
note would pass it), so the block is never presented as trusted context or as an instruction.
`<`, `>` and `&` are escaped inside it, so a quote cannot close it early.

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
and WebGoat, each at the commit of a pinned release tag (`scripts/fetch_calib_corpora.py`: Juice Shop v20.3.0,
WebGoat v2026.4; a checkout at another commit is refused), so labels stay tied to the code they describe; they need human-authored `labels.json` files before they count. A sample's
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
| P1 covered-models | Fable/Mythos-class Anthropic models, direct or on Bedrock (30-day retention, not ZDR-eligible), need `anthropic_covered_models_authorized: true` and an authorization reference |
| P2 deepseek-on-prem | DeepSeek, Qwen and GLM only through an OpenAI-compatible endpoint on an RFC 1918, loopback, IPv6 unique-local, `.internal`/`.local`/`.lan` or declared `private_dns_suffixes` host; the DeepSeek, DashScope and Zhipu (bigmodel.cn, z.ai) vendor APIs are rejected, and so are link-local and documentation addresses. A model is PRC-affiliated by its family, its model id or its host, so a misdeclared `family: other` fails instead of switching P2 off |
| P3 panel-size | reviewers and judges each span at least three model families; exactly two only with a stated `reduced_panel_reason` (see `config/examples/prc-site.yaml`) |
| P4 gate-bounds | `gate.self_judge_discount` at most 0.5, `gate.human_threshold_alpha` at least 0.3 |
| P5 data-residency | every non-mock model is `on_prem` or `vendor_api_zdr`, or `vendor_api_retained` with its own `retention_approval_ref`, unless `allow_source_code_to_non_on_prem` is set; `on_prem` must match the endpoint (an OpenAI-compatible server on a private host, not a vendor API or a public URL); an OpenAI-compatible model may claim `vendor_api_zdr`/`vendor_api_retained` only for a host listed in `vendor_api_hosts` |
| P6 psirt-scope | when the PSIRT hand-off is enabled: HTTPS webhook, product set, token from the environment, trigger tiers within A/B and severities within Critical/High |
| P7 ml-bom | when `ml_bom.required`: every self-hosted model has a complete CycloneDX ML-BOM component (safetensors hashes, licence, source, signature method), signed when `require_signature` |
| P8 unsupervised-reject | `gate.unsupervised_reject_allowed` may be `true` only while `calib/latest.json` records a passing Alternative Annotator Test (current method: chance-corrected agreement and a bounded miss rate on the rejections themselves, see Calibration) on a live calibration within 90 days; while `false` every rejected non-D finding goes to the human queue |

`config/examples/violating.yaml` breaks the first five and is what the tests run against. Every
section of the config refuses unknown keys, not only the top level and `gate`: a misspelt
`psirt: {enable: true}`, `ml_bom: {requried: true}` or `rollout: {phse: blocking}` fails to load
instead of falling back to the weaker default.

## Gap assessment (Appendix E, prompt 3)

Five runs score this repository's review process against the 60-question questionnaire in
`docs/appendix-d-maturity.md`: `docs/assessment-2026-09-12.md` (134/240), `docs/assessment-2026-09-26.md`
(152/240, L0 up from 13 to 23 now that the scanners run blocking from the lock), `docs/assessment-2026-10-01.md`
(170/240, twelve questions up after v0.3.10–v0.3.12), `docs/assessment-2026-10-03.md` (171/240,
incremental review now runs in CI; the v0.3.13–v0.3.15 hardening — gate validation, the semgrep relock that
removed thirteen expiring exceptions, corroboration dimension limits, content-ordered finding ids — strengthened
evidence without crossing a scoring line; L5 lowest at 24, L0 next at 27 — the recorded blocker is the first
real-family run, not code) and the current `docs/assessment-2026-10-12.md` (171/240, drafted by Claude Code and
reviewed by the owner: the first live calibration and the v0.4.x fixes strengthen the evidence of fourteen questions
without crossing a scoring line; question 59 stays at 1 because the suggested weights have not been applied; L5 still
lowest at 24 — what is missing now is a second live calibration, human decisions and a live swap drill). Each run has a file-level
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
comment, and zizmor's SARIF when zizmor is on the PATH. Triggers, and so `pull_request_target`, are
read from the parsed YAML the way GitHub reads them (block, flow, list or scalar `on:`, any
indentation). Files that are not valid YAML are still inventoried line by line and flagged. `docs/actions-inventory-2026-09-12.md` is the first run, and its
section 6 adds what the CI logs showed that the static inventory cannot, and the fixes that
followed: CI now runs zizmor strictly on the real workflows, checks that zizmor's findings on the
seeded fixture match `fixtures/vuln-sample-sarif/zizmor.sarif` (now produced by zizmor itself), and
no longer hides a crashed or leaking gitleaks run behind `continue-on-error` (`.gitleaks.toml`
allowlists exact known synthetic values; all fixture paths remain scanned). Since 2026-09-13 the scan
itself is `scripts/gitleaks_ci.py` with the gitleaks pinned in `tools/versions.lock` (PR: the PR's
commits; push: every new commit), not gitleaks-action, so no action downloads its own tool and the
L0 job needs no `pull-requests` permission. `docs/actions-inventory-2026-10-12.md` is the current run: four real workflows, all rated None and every
`uses:` pinned to a SHA that still matches its tag comment (several actions have newer releases, listed in its
section 3, for Dependabot to bump), with no zizmor finding on them (the 2026-10-03 `bot-conditions` finding is gone
since the Dependabot guard); the seeded fixtures keep their deliberate gaps and stay Critical.

## Pinned, verified L0 tools (Appendix E, prompt 7)

`tools/versions.lock` pins every deterministic tool (gitleaks, osv-scanner, zizmor, trivy, scorecard, semgrep,
csp-evaluator, plus the verifiers cosign and slsa-verifier) by exact version, download URL and SHA-256, and names
the strongest verification the publisher offers. `python scripts/install_tools.py` downloads each
asset, checks the SHA-256 (never skippable), runs the publisher-side check — cosign keyless bundle,
SLSA provenance, GitHub attestation, publisher checksum file, the npm registry's `dist.integrity` for
csp-evaluator, or `pip --require-hashes` for semgrep —
and installs into `.mara-tools/bin`, writing `.mara-tools/manifest.json`. Any mismatch aborts.
`mara/tools/runner.py` executes tools only from that directory and reports "not installed" otherwise;
PATH is never consulted. `docs/tools-provenance.md` records source, licence, what each verification
proves and the remaining gaps (gitleaks, semgrep and csp-evaluator publish no signature). CI installs and verifies
the whole set on every run. The lock also has a `git` kind: `semgrep-rules` is a checkout of
`semgrep/semgrep-rules` at a pinned commit, verified by commit id, by a SHA-256 digest over every
file under the pinned security rulesets, and by the commit's GPG signature (GitHub's web-flow key);
the rules are read from `.mara-tools/semgrep-rules` at scan time (without them semgrep is recorded as
not run, which keeps the review incomplete; there is no fallback to the semgrep.dev registry) and never copied into this
repository (Semgrep Rules License v1.0). `--digest-git semgrep-rules <checkout>` prints the two
values to paste into the lock when bumping the commit.

In a review the reviewed repository is untrusted, so `runner.py` never lets a tool load the target's
own suppressions: semgrep runs with `--x-ignore-semgrepignore-files` (its `# nosemgrep` results stay in
the SARIF, marked `inSource`, and are kept), osv-scanner with `--config` pointing at an empty file
(no `osv-scanner.toml` overrides), zizmor with `--no-config --no-ignores --collect=all` (no
`zizmor.yml`, no inline `# zizmor: ignore[...]`, no `.gitignore` hiding workflows), trivy with an empty
`--ignorefile` and `--config` (no `.trivyignore`, no `trivy.yaml`), and gitleaks with an explicit
config and no allowlist. The empty files live in the run's output directory. Each of those
repository files suppresses results under the old arguments with the pinned versions (checked against
the real binaries); this repository's own CI scans (`scripts/*_ci.py`) keep their reviewed triage files.

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
  (its dated exceptions cover garak's nltk/datasets/fsspec pins); the semgrep tool closure is scanned with
  `tools/osv-semgrep.toml`, which has been exception-free since semgrep 1.179.0 relaxed the
  `pyjwt[crypto]~=2.13.0` pin and the closure relocked to pyjwt 2.15.1. These scans
  also run weekly and on manual workflow dispatch.

semgrep runs with `--metrics=off --disable-version-check` and explicit local rule directories
(never `--config auto`), so nothing is sent to semgrep.dev; osv-scanner runs `scan source
--no-resolve`, so only package names and versions go to api.osv.dev and nothing to deps.dev. All
SARIF files land in the `l0-sarif` artifact, and the eight scans of the repository itself (six tools; osv-scanner
twice more: the model-evaluation and semgrep tool closures) are also uploaded to GitHub Code Scanning (see below). `mara review` uses the same pinned rulesets by default
(`MARA_SEMGREP_CONFIG` overrides them, but such a run is labelled `UNPINNED rules` in the tool note, the
pipeline log and the report's `tool_health`, with a warning, and a registry config such as `p/default` or `auto`
is named as fetched from semgrep.dev). Every tool subprocess gets an allowlisted environment
(`runner.TOOL_ENV_ALLOWLIST`: search path, home, temp, locale, proxies, CA bundles, Windows system variables),
never the review's provider keys, AWS credentials or tokens; zizmor alone also gets `GH_TOKEN`/`GITHUB_TOKEN`,
and only for its online audits. zizmor on the real workflows runs the same way since 2026-09-14:
`scripts/zizmor_ci.py` executes the locked zizmor (online audits with the workflow token), keeps the
SARIF and fails on any finding; zizmor-action is gone.

## trivy offline database

trivy used to download its vulnerability database at scan time, which hangs on isolated hosts and
turns every review into a network event. `python3 scripts/trivy_db.py download` fetches it once
(from the repositories in `tools/trivy-db.yaml`, by the manifest digest the registry names for the tag, so the record
names exactly what was downloaded; a registry that names none is refused unless `--allow-unknown-provenance`;
`--pin-digest sha256:…` fetches a given digest, and only from a repository whose registry names exactly that digest)
into `.mara-tools/trivy-cache` and writes `mara-trivy-db.json`: OCI manifest and layer digests,
trivy's `UpdatedAt`/`NextUpdate`, the SHA-256 of `trivy.db`, the trivy version. `status` refuses a
missing, tampered or stale copy (default 48 h, `max_age_hours`); `export`/`import` carry the
database as a checked bundle to runners without egress (`import` requires the bundle's SHA-256 as `export`
printed it, sent separately from the bundle; `--trust-bundle` skips that). Both `mara review` and
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
(`docs/governance-templates.md`); G-8 once the quarterly red-team evaluation has run on a host with the
endpoints (`docs/model-eval-runbook.md`). G-9 passes since the first live calibration (2026-10-08,
`docs/calibration-2026-10-08.md`: Claude Opus 5.5 on Bedrock, Gemini 3.8 Flash and GLM on the five labelled
samples, 51 labels; its Alternative Annotator Test has no human decisions to compare yet, so P8 keeps every
rejected non-D finding in the human queue). Nothing is
marked passed before the fact. `docs/governance-check-2026-09-12.md` was regenerated in place as those
mechanisms landed (last on 2026-09-17), so it shows the later state rather than the first run;
`docs/governance-check-2026-09-26.md` was likewise regenerated in place on 2026-10-03 and still shows the
former Claude/DeepSeek/Nemotron panel. `docs/governance-check-2026-10-12.md` is the current record (the same
table the weekly run posted that day): G-2, G-3, G-5, G-6, G-9 and G-11 pass, the other seven fail for the
reasons above, none is MANUAL.

## PSIRT hand-off (governance item G-12)

With `psirt.enabled: true` and `psirt.shipped: true` in the config, every accepted finding in the
configured tiers and severities (default: tier A, Critical) is written to
`out/psirt-notifications.json` as a `mara-psirt/2` internal hand-off carrying the evidence chain.
Review time anchors only internal service targets. Legal deadlines stay empty until PSIRT confirms
an event type and awareness timestamp; the final-report anchor depends on that event type.
`mara review --notify-psirt` POSTs the hand-off to the configured webhook with an environment token;
`--psirt-resend` (with `--notify-psirt`) sends even findings the ledger records as delivered or the
PSIRT closed, and
`--psirt-event event.json` attaches a PSIRT-confirmed event so the legal deadlines are computed.
A hand-off that fails (an HTTP error or no response at all) is recorded in the ledger, does not stop the
other payloads, and makes `mara review` exit 3 after the reports are written, whatever the gate says.
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

The weights served by the on-prem endpoints (GLM in production; DeepSeek, Nemotron in the examples) are inference dependencies, so
they are listed in a CycloneDX 1.6 ML-BOM. `sbom/models.yaml` is the manifest the platform team
fills (official source, licence, per-file SHA-256 of the safetensors weights, signature method);
`scripts/ml_bom.py` hashes a weights directory (pickle checkpoints are refused) or, with
`registry-hashes`, takes the same per-file SHA-256 straight from the official Hugging Face
repository at a pinned commit without downloading the weights, builds `sbom/ml-bom.cdx.json`, validates it against the vendored schema, re-verifies a directory on the
inference host and checks the cosign bundle with the locked cosign. Policy P7 refuses the config
once `ml_bom.required` is true and a self-hosted model has no complete component; until then
`mara check-config` and the review report show each model's BOM status. Every entry, the production
GLM one included, is pending in this repository: it hosts no weights and the registry hashes could not be fetched
from the authoring environment, so governance check G-7 stays red and says exactly what is missing.
See `docs/ml-bom.md`.

## Model red-team evaluation and live calibration (governance items G-8, G-9)

`scripts/model_eval.py` turns the config into the exact garak (`openai.OpenAICompatible` or
`anthropic` generator, probes from `model_eval.garak_probes`) and CyberSecEval 4
(`prompt-injection`, `mitre-frr`) commands for every non-mock family on the direct Anthropic API or an
OpenAI-compatible endpoint, runs them on a host that
reaches the endpoints (keys only from the environment), parses the tools' native outputs, applies
the thresholds in `model_eval.thresholds` and writes `docs/garak-<date>.md`,
`docs/cyberseceval-<date>.md` and `calib/model-eval-<date>.json`. Calibration multiplies a
failing family's suggested weight by `weight_penalty_on_fail` and the review's bias audit shows
the latest verdict per family. `scripts/calibration_run.py --mode live` runs the whole calibration
loop (check-config, every sample, `calibrate.py --mode live`) and both scripts refuse to label
mock or fixture-based output as live. Governance checks G-8 and G-9 read the reports' front
matter (`mode: live`, families covering the config, within 90 days). garak reaches Claude through its
`bedrock` generator (AWS credential chain, `temperature` and `top_p` suppressed: Opus 5.5 refuses both) and
Gemini through its OpenAI-compatible endpoint; CyberSecEval reaches Gemini the same way (its own GOOGLEGENAI
provider would put the key in the URL) and GLM with `SSL_CERT_FILE` set to the public roots plus `ca_bundle`.
CyberSecEval at the pinned ref has no Bedrock provider: `plan` lists that as skipped, `run` exits 1 and the
anthropic family's two CyberSecEval metrics stay missing, so G-8 stays red for it until there is a route.
`fixtures/model-eval/` holds synthetic outputs for the parser tests. The first live calibration ran on
2026-10-08 (about four hours for the five samples); a truncation is never a canary echo, because three of
GLM's four echoes in that run were truncated calls quoting a canary report that never closed. A reply that
ended normally in plain text is read as prose: the token with the planted file is a canary report, the
token alone an echo (before v0.4.26 such a reply was filed as a truncation and an echo in it went unrecorded).
See `docs/model-eval-runbook.md`.

## Policy, cold standby and rollout templates (governance items G-1, G-4, G-10)

The three items that needed a human now have machine-readable templates, so the weekly check
decides and says what is missing: `docs/policy/mara-review-policy.md` (front matter with
`status`/`approved_by`/`approved_on`/`review_by` and six marked mandatory statements; shipped as a
draft), `config/examples/standby-for-<family>.yaml` plus `ops/model-swap-drills.yaml` and
`scripts/model_swap_drill.py` (`rehearse` proves the process is unchanged on a mock panel, `record`
logs a live swap timed from decision to first real PR; mock rehearsals for all three production families are recorded, live drills are still missing), and `rollout:` in
`config/mara.yaml` with `scripts/rollout_phase.py` (`status`, `baseline`, `advance`). The rollout
phase changes behaviour: `mara review` exits 2 on a blocked gate only in `blocking` (or with
`--fail-on-gate`); exit 3 is reserved for a failed PSIRT hand-off. All three fail
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

Findings the pipeline will not decide on its own (any L5 `human_reasons`: a judge majority of
`needs_human`, the per-finding `agreement_proxy` below `gate.human_threshold_alpha`, too few independent
judges, invalid or incomplete judge passes or CVSS vector, position inconsistency, a skeptic refutation
the jury overrode, tier C at High or above; and, while policy P8 is locked, every rejected non-D finding)
become `HumanQueueItem`s in
`out/human_queue.md/json` with the full un-blinded context: finder families, the skeptic's verdict,
the red team's call and every judge vote from both passes. `scripts/human_queue_issues.py` opens one
GitHub issue per item (deduplicated by its v2 key: a SHA-256 over the target identity, the reviewed tree's
revision, the context hash, file, line and CWE; legacy 12-hex keys are never auto-synced; a key with an open ticket, a closed
one that was not withdrawn as not planned, or a recorded decision is never filed again) and, with `--sync-decisions`,
turns closed tickets labelled `decision:true-positive` / `decision:false-positive` into
`calib/decisions/<key>.json` (several closed tickets for one key: a trained adjudicator's decision when they
agree, none and a failed sync when they disagree), which `scripts/calibrate.py` uses as labels. When
`calib/decisions/backlog.json` shows more open tickets than `human_queue.backlog_limit`, the pipeline
raises the alpha threshold and — with `human_queue.tighten_exclude_tier_c`, the default — stops queuing
tier C at `human_queue.queue_tier_c_min_severity`. Nobody then looks at those findings, so one the jury
accepts blocks the gate like tier A/B (`tier_c_blocked_while_tightened` in the bias audit) instead of
passing on a single family's word: tightening cuts human work, it never loosens. The `human-queue` CI job runs
on push to `main` with `issues: write` only and stays in dry-run until the repository variable
`MARA_HUMAN_QUEUE_ISSUES` is `true`. See `docs/human-queue.md`.

## Other commands

```bash
mara cvss "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
mara review <target> --provider mock --mock-fixtures <dir>   # replay another set of mock responses
python scripts/gen_mock_fixtures.py      # regenerate mock responses after editing the fixture app
python scripts/gen_mock_fixtures.py --check   # the committed mock responses are current (also a test)
python scripts/build_html.py             # rebuild the online edition of the report
python scripts/count_words.py            # 字數統計（正體中文計字，不含附錄A）
```

## Layout

```
config/            mara.yaml (live topology), mara.mock.yaml (offline), examples/ (standby, PRC site, policy cases)
src/mara/          the prototype (see table above)
fixtures/          vuln-sample app, mock-responses, pre-recorded SARIF, synthetic model-eval outputs
calib/             labelled calibration samples, human decisions (calib/decisions/)
tests/             unit + end-to-end tests (no network)
docs/              the report (Markdown + HTML), dated records, runbooks, Appendix E prompt kit, Appendix D questionnaire
scripts/           CI wrappers (*_ci.py), tool installer, governance, calibration, rollout and report scripts
tools/             versions.lock, hash-pinned Python closures, triage / ignore / policy files
sbom/              ML-BOM manifest (models.yaml) and the CycloneDX BOM
ops/               model-swap drill register, PSIRT records
training/          AI-literacy curriculum, quiz and register (G-13)
.github/workflows  four hardened workflows: mara-review, scorecard, governance, docs-check (SHA-pinned, least privilege)
```

## Status

Prototype. The CVSS 4.0 calculator is verified against FIRST's reference implementation; the
consensus, tiering and blinding logic are unit-tested; the live providers are implemented but have
not been exercised against production models from this repository. Calibration weights in the
config are placeholders until a seeded-vulnerability benchmark run populates them (report, Part V).
