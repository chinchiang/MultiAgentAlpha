# AI-literacy training for pipeline operators (governance item G-13)

EU AI Act Article 4 has required every deployer, since 2025-02-02 and regardless of the system's
risk class, to ensure that the people operating an AI system have sufficient AI literacy. The report
(Part X, G-13) applies that to the three groups who operate the review pipeline: developers whose
pull requests it reviews, the security team that runs it, and the adjudicators who decide
human-queue tickets. Half a day per person; owner: HR and the PSO.

## 1. Pieces

| piece | role |
|---|---|
| `training/curriculum.md` | the module (version `2026-09`): what a pass means, evidence tiers, the bias audit, prompt injection through code, deciding tickets, operating the pipeline, data residency. Every claim is verifiable in the code |
| `training/quiz.yaml` | knowledge check; each question carries a rationale pointing at the file or report section that answers it. Questions can be limited to roles |
| `training/records.yaml` | the register: one record per person (GitHub login), role and curriculum version, with score, assessor, evidence and expiry. Empty in this repository |
| `scripts/training_register.py` | `show-quiz`, `assess` (grade and record on a pass), `add` (instructor-led session), `check` (coverage per role, expiries), `status` (one person, one role) |
| `src/mara/training.py` | the library the script, the human-queue sync, calibration and governance check G-13 share |
| `training:` in `config/mara.yaml` | register path, `require_trained_adjudicator`, `required_roles` |

## 2. How a record comes to exist

Self-assessment:

```
python3 scripts/training_register.py show-quiz --role adjudicator
python3 scripts/training_register.py assess --person <github-login> --role adjudicator --answers T1=b,T2=a,...
```

A score at or above `pass_mark` (0.8) appends a record dated today, expiring after `validity_days`
(365). A failed attempt writes nothing. Instructor-led sessions are recorded with `add`, naming
the assessor and an evidence reference (ticket, attendance list). A new curriculum version
invalidates every older record, so a material change to the pipeline means re-training.

Records are keyed by GitHub login because that is the identity the human queue sees: the sync
reads, from each closed ticket's timeline, who applied the `decision:*` label.

## 3. What the register changes in the pipeline

- **Human-queue decisions.** `scripts/human_queue_issues.py --sync-decisions` records
  `decided_by` and `adjudicator_trained` on every decision it writes to `calib/decisions/`, and
  warns about decisions by people without a valid adjudicator record.
- **Calibration.** With `training.require_trained_adjudicator: true` (the default),
  `scripts/calibrate.py` applies only decisions marked trained; the rest are listed as skipped.
  A wrong human decision moves per-family weights, which is why the control sits here rather than
  on ticket creation.
- **Governance.** `check_g13` passes only when the curriculum and register exist and every role in
  `training.required_roles` has at least one valid record for the current curriculum version; it
  lists records expiring within 30 days. In this repository the register is empty, so G-13 fails
  naming all three roles. No record was invented.

## 4. What this does not do

It does not prove that a person understood the material beyond the quiz, and it does not replace
the organisation's own training records system; the register is the machine-readable mirror the
governance check can read. If HR keeps the master record elsewhere, `add --evidence` should
reference it.
