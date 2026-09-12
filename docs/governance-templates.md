# Templates that make G-1, G-4 and G-10 decidable

Three governance items were "needs a human" in the first governance check because their evidence
is organisational: a policy document, a cold-standby arrangement with drills, and a rollout
schedule. Each now has a template with machine-readable fields, so the weekly check decides PASS or
FAIL from the repository and says exactly what is missing. None of the templates ships with
evidence that does not exist: the policy is a draft, the drill register is empty, the rollout has
not started, so all three fail today with precise reasons.

## G-1: the review policy (`docs/policy/mara-review-policy.md`)

- YAML front matter: `status` (`draft` | `approved`), `approved_by`, `approved_on`, `review_by`,
  `version`, `applies_to`, `related`.
- Six mandatory statements, each introduced by a marker the check looks for:

  | marker | statement |
  |---|---|
  | `<!-- policy:S1 -->` | automated review is part of ISO/IEC 27001 A.8.29 security testing |
  | `<!-- policy:S2 -->` | a pass does not exempt human security testing |
  | `<!-- policy:S3 -->` | obligations on blocking-tier findings |
  | `<!-- policy:S4 -->` | human adjudication and adjudicator qualification (G-11, G-13) |
  | `<!-- policy:S5 -->` | data residency and model-use limits (P1, P2, P5) |
  | `<!-- policy:S6 -->` | exceptions and risk acceptance |

- `check_g1` passes when all six statements have text, `status: approved`, `approved_by` and
  `approved_on` are filled, `approved_on` is not in the future, `review_by` has not passed, and the
  approval is under a year old or has a future `review_by`. Otherwise it fails and lists what is
  wrong. The PSO approves by editing the front matter and the approval table.

## G-4: cold standby and model-swap drills

- `config/examples/standby-for-<family>.yaml`: one per production family, declaring `standby_for`
  and a full configuration in which exactly that family is replaced by a standby family (`llama`,
  `mistral`, `qwen`; Qwen is PRC-affiliated, so policy P2 holds it to self-hosted private endpoints
  like DeepSeek). Shipped: `standby-for-deepseek.yaml` (Llama), `standby-for-nemotron.yaml`
  (Mistral), `standby-for-anthropic.yaml` (Mistral, giving an all-on-prem panel). Each passes
  `mara check-config`. The served model ids are placeholders to confirm against the deployment.
- `ops/model-swap-drills.yaml`: the drill register.
- `scripts/model_swap_drill.py`:
  - `rehearse --standby <config>`: loads the standby config through the policies, confirms it swaps
    exactly one family, runs the pipeline on the seeded fixture with every model on the mock
    provider and records a `rehearsal`. It proves the process is unchanged; it does not satisfy G-4.
  - `record --replaced <family> --standby-config <config> --started <iso> --completed <iso> --outcome pass|fail --performed-by <login> --evidence <ref>`:
    a live drill on the real endpoints, timed from the swap decision to the first real PR reviewed on
    the standby.
  - `check`: what G-4 sees.
- `check_g4` passes when every production family has a loadable standby config and a live drill
  in the last 365 days that passed within 168 hours.

## G-10: rollout phase

- `rollout:` in `config/mara.yaml`: `phase` (`not_started` | `shadow` | `advisory` | `blocking`),
  `started_on`, `shadow_months` (2), `advisory_months` (3), `baseline_report`.
- The phase changes behaviour: `mara review` exits 2 on a blocked gate only in `blocking` (or with
  `--fail-on-gate`); in `shadow` and `advisory` the result is recorded, the report header says so,
  and merge is not enforced. The phase is written into the report's bias audit.
- `scripts/rollout_phase.py`:
  - `status`: phase, days in phase, due date, problems.
  - `baseline --runs <dirs> --out docs/rollout-baseline-<date>.md`: aggregates every `report.json`
    into the baseline the report requires at the end of the shadow phase (findings per review, tier
    mix, gate would-block rate, human-queue size, token cost, false-positive rate from decisions).
    A baseline that includes mock-mode reviews says so and cannot support advancing.
  - `advance --to advisory|blocking`: checks time in phase, the baseline report and (for blocking) a
    non-mock calibration report, then prints the config change; it never edits the config.
- `check_g10` fails while `not_started`; in `shadow` it fails once the phase is a month past its
  planned end without advancing; in `advisory` and `blocking` it requires the baseline report.

## What still needs a person

The PSO's approval, running a swap on real endpoints, and the day the pipeline first reviews real
pull requests. The templates only make sure those facts, once true, are recorded in a form the
check can read, and that nothing pretends they are true before then.
