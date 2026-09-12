# AI-literacy curriculum for MARA operators (version 2026-09)

Governance item G-13; EU AI Act Article 4 (applicable to every deployer since 2025-02-02). Half a
day per person. Report references are to the GSMD report in `docs/`; every claim below is also
verifiable in the code, and the knowledge check (`training/quiz.yaml`) only asks things the code
answers.

## 0. Who takes which part

| role | who | sections | pass records |
|---|---|---|---|
| `developer` | anyone whose pull requests the pipeline reviews | 1, 2, 3, 6 | quiz questions without a role restriction plus the developer ones |
| `security` | the team that tunes the config, reads calibration and runs the governance checks | all | all questions except the adjudicator-only ones |
| `adjudicator` | anyone who decides human-queue tickets (applies a `decision:*` label) | 1, 2, 3, 4 | quiz questions for adjudicators |

A person can hold several roles; each role is a separate record in `training/records.yaml`.
Records expire after `validity_days` (365) and are invalidated by a new curriculum version.

## 1. What the pipeline is, and what a pass means (all roles, 45 min)

- Six layers: deterministic tools (L0) anchor the language models; reviewers (L2) from at least
  three model families find; a skeptic and a red team (L3) from other families refute and exploit;
  a blinded jury (L4) votes forward and reverse; scoring (L5) is computed by code, never declared by
  a model. Report Part III; `src/mara/pipeline.py`.
- **A pass is not a proof of security.** The gate blocks only on accepted tier A/B findings at
  High or Critical severity and on dimension scores below the minimum (`gate` in
  `config/mara.yaml`). Everything the models did not find, everything below the threshold and
  everything the tools do not cover (runtime, DAST, business logic the reviewers could not reach)
  is untouched. Governance item G-1 defines the review as part of security testing, not a
  replacement. Report chapter 23 (limits).
- Models are not trusted with facts: CVE data, EPSS and KEV come from tools; provenance is checked
  by code; standard identifiers must exist in the pinned ground-truth files
  (`src/mara/scoring/idcheck.py`). Report chapter 12.

## 2. Reading a finding: evidence tiers and the bias audit (all roles, 60 min)

- Tiers, `src/mara/scoring/tiers.py`, report section 11.2:
  - **A** a deterministic tool and a model both reported it;
  - **B** several families agree and the path is reachable;
  - **C** a single family; accepted only above the consensus threshold and never counted as strong
    evidence (score coefficient 0.4);
  - **D** provenance unverified: the quote is not in the file at the line. Never accepted, scores 0.
- CVSS 4.0 vectors are proposed by models; the score is computed (`src/mara/scoring/cvss4.py`).
  SSVC gives the action (Track, Track*, Attend, Act). Report section 11.1.
- The bias audit at the end of every `report.md` is the integrity record of the run:
  `pairwise_family_agreement` (high agreement can mean correlated errors, not more evidence),
  `dropped_unverified_provenance`, canary hits (prompt-injection attempts through the code),
  `human_queue_*` and `human_alpha_threshold`, `psirt_notifications`, `ml_bom` status. Report
  chapter 13; `src/mara/bias/`.
- Exercise: open `out/report.md` from `mara review fixtures/vuln-sample --provider mock …` and
  explain three findings by tier, one rejected finding by reason, and every bias-audit line.

## 3. Prompt injection through the code under review (all roles, 30 min)

- Code, comments, commit messages and PR descriptions are untrusted input to the reviewers
  (`src/mara/agents/base.py`); the pipeline strips author and PR text, wraps content as data and
  plants canaries. Report section 12.4, OWASP LLM Top 10 LLM01.
- Developers: text that addresses "the AI reviewer" in code is an injection attempt and will be
  recorded, not obeyed. Security: a canary hit in the bias audit is an incident signal.

## 4. Deciding human-queue tickets (adjudicators and security, 60 min)

- What arrives: judge majority `needs_human`, Krippendorff's alpha below the threshold, or tier C at
  High or above. The ticket carries everything the judges were not allowed to see: finder families,
  the skeptic's verdict and named control, the red team's preconditions, every judge vote in both
  passes. Report section 15.1; `docs/human-queue.md`.
- How to decide: open the file at the quoted line; check whether the control the skeptic named
  actually applies on the path the red team described; decide `true_positive` or `false_positive`
  with exactly one label and close the ticket. A ticket closed without a label is ignored.
- What the decision does: it becomes a label in `calib/decisions/` and moves per-family, per-CWE
  weights at the next calibration. Wrong decisions miscalibrate the panel, which is why only
  trained adjudicators' decisions are applied (`training.require_trained_adjudicator`).
- Review fatigue: when the backlog exceeds the limit the pipeline tightens, never loosens
  (report section 15.2). Rubber-stamping is worse than a backlog.

## 5. Operating the pipeline (security, 60 min)

- Policies P1–P7 (`mara check-config`): covered models, DeepSeek on-prem only, panel size, gate
  bounds, data residency, PSIRT scope, ML-BOM. `docs/…` and report chapter 25.
- Calibration (`scripts/calibrate.py`, report section 15.3): quarterly and after any model upgrade;
  inputs are seeded samples and human decisions; outputs are weights and family agreement. Until
  the Alternative Annotator Test passes, sample every automated rejection.
- PSIRT hand-off (`docs/psirt-integration.md`): tier A Critical on a shipped product starts the
  EU CRA Article 14 clocks from the review; exploitation status remains the PSIRT's call.
- Supply chain of the pipeline itself: pinned, verified L0 tools (`docs/tools-provenance.md`),
  ML-BOM for the self-hosted weights (`docs/ml-bom.md`), hardened workflows
  (`docs/actions-inventory-*.md`). Governance checks (`scripts/governance_check.py`) run weekly.

## 6. Data residency (all roles, 15 min)

- Source code goes only to on-prem endpoints or vendor APIs under zero-data-retention terms;
  Fable/Mythos-class models are not ZDR-eligible; the PRC in-country pipeline is separate.
  Policies P1, P2, P5; report Part VIII.

## 7. Assessment and record

- Self-assessment: `python3 scripts/training_register.py show-quiz --role <role>` then
  `assess --person <github-login> --role <role> --answers T1=b,T2=a,…`. Pass mark 0.8; a pass
  appends a record with the score.
- Instructor-led session: `add --person <login> --role <role> --assessor <instructor-login>
  --evidence <ticket or attendance reference>`.
- `check` lists valid records per role and those expiring within 30 days; governance check G-13
  passes only when every required role has at least one valid record for this curriculum version.
