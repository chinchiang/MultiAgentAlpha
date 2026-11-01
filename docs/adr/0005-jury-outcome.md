# Jury outcome: one module decides it, tier D is dropped rather than rejected, and P8 is a rejection review

The rules that turn a finding's signals into its **jury outcome** were written in several places. `Pipeline.score()` held the human reasons and the acceptance rule. The human queue repeated the tier-C rule in a branch that could never run, since `score()` already sends such a finding to a human, and it alone added policy P8's `unsupervised_reject_unverified`. Calibration, the markdown report and the dimension scores each re-derived "rejected" from the `accepted` and `needs_human` booleans and the tier. The rules now live in one module, `mara.scoring.outcome`: `decide(signals, policy)` takes the signals `score()` has computed (evidence tier, weighted score, severity, provenance, skeptic, quorum, judge passes, agreement and position consistency) together with the policy in force (accept threshold, the alpha threshold and tier-C exclusion after tightening, the tier-C severity floor, P8), and returns the outcome, its reasons and the P8 flag. The signals are not computed there: tier assignment, weighted consensus and CVSS scoring are modules of their own with their own tests, and folding them in would widen the interface without moving any rule into one place.

The jury outcome has four values, not three: **accepted**, **rejected**, **dropped** and **needing a human**. A **dropped finding** is at tier D and needs no human; a **rejected finding** has evidence enough for tier A, B or C and the jury did not accept it. Calibration, P8 and the markdown report already treated the two apart (calibration counts only non-D rejections, and P8 queues only those), each through its own tier test; the module now makes the split once. A finding at tier D whose provenance is unverified is needing a human, not dropped, because of that reason.

P8 is a **rejection review**, not an undecided outcome. Until the Alternative Annotator Test passes, every rejected finding goes to the human queue, but its jury outcome stays rejected and it does not make the review incomplete. Making it needing a human would have emptied exactly the sample the AAT is computed on, since no finding would be rejected by the jury alone while P8 is in force (docs/adr/0003-human-resolution.md keeps the jury outcome for calibration for this reason), and it would have held every review incomplete on findings the jury had already decided. The dimension table therefore labels its third count **Awaiting decision**: it counts findings whose final outcome needs a human, and can be smaller than the human queue, which also lists rejections under review.

The persisted shape stays `ConsensusResult` in `report.json`, so retained reports, the score summary (docs/adr/0004-score-summary.md) and calibration read old and new reports alike. Its fields are unchanged, with one addition, `unsupervised_reject_unverified` (default false), recorded at review time because the P8 setting in force then cannot be recovered from a later config. A report written before this field reads it as false, although its human queue may list such rejections. The four values are derived, not stored: `jury_outcome` reads needing a human, then accepted, then dropped for tier D, else rejected, which matches the test calibration used before, so its numbers do not move; `final_outcome` gives the ruling of a usable decision (true positive accepted, false positive rejected) where one exists and the jury outcome otherwise. Calibration validates each consensus row as a `ConsensusResult` before reading it, and stops if one does not validate.

## Considered options

- **Rejection review as needing a human, so it keeps the review incomplete:** rejected for the reasons above.
- **Compute the signals inside the module too:** rejected. It widens the interface to raw votes, skeptic verdicts and tool results and moves no rule into one place.
- **Persist the outcome as a new string field in place of the booleans:** rejected. Every reader would need two paths, one for reports written before the change.
- **Derive the P8 flag from the config when a report is read:** rejected. The score summary and calibration read reports after the fact, and `gate.unsupervised_reject_allowed` may have changed since.

## Consequences

- The gate's per-finding blocking rule, which decides on the final outcome, was left in `Pipeline.blocking_reason` by this change. docs/adr/0007-review-status-and-gate.md has since moved it into `mara.review_status`, where it shares the tier-C severity rule of `mara.scoring.outcome` (`tier_c_needs_human`) instead of keeping a copy; no gate rule is left in the pipeline.
- `apply_decisions` still appends `decision_not_usable:*` to a finding's human reasons after the jury has decided. The outcome does not change, but those reasons are no longer only the jury's; this is left for the work on the final outcome.
- Amended 2026-10-16: the signals are no longer computed in `Pipeline.score`. `mara.scoring.jury.score` measures each finding's **jury signals** (GLOSSARY.md) from the ballot round's ballots, the finders, the tool results and the **jury** (`jury.Jury`: each judge family's weight, the self-family discount and the quorum), and hands them to `decide()`, whose interface does not change. The option rejected above, computing the signals inside `decide()`, stays rejected: they are computed in a module of their own beside it. Like `decide()` and `mara.review_status.assess`, it is pure, and the pipeline writes the position flips and the review's agreement it returns into the audit. Test rows that claimed to be what scoring writes now come from it (`tests/scored_rows.py`); the rejected ones need a fourth judge family, as the open question below explains.
- **Open question for the owner: rejected findings are structurally rare, so the AAT's rejection sample may never reach 59.** With the panel as configured (three judge families of weight 1, self-judge discount 0.5, accept threshold 0.6), a tier B finding cannot be rejected. A family whose votes differ between passes makes the finding need a human; a consistent family scores 1, 0.5 or 0; two agreeing families at 1 against a third at 0 score 2/3, or exactly 0.6 when one of the two is the finder's own discounted family, which is still accepted. Only tier A can be rejected: a finding a deterministic tool corroborates and the jury votes down. A live review of a deliberately vulnerable public application (DVPWA, 85 findings, 2026-10-14) had no tier A or B finding scored below 0.75 and no rejected finding at all. Rejection safety needs at least 59 decided rejections with no miss before P8 may allow unsupervised rejection, so at this rate P8 may never unlock (the first live calibration, 2026-10-08, had no decisions yet and says nothing either way). Related: what the pipeline drops without a human today are mostly dropped findings (tier D with verified provenance; two in that review), which neither the AAT nor P8 covers. This change keeps the tier rules and the AAT sample as they are; whether to accept that unsupervised rejection stays off, to widen what the AAT samples (dropped findings, or seeded rejections in the calibration samples), or to change the tier rules is the owner's decision.
- **The open question, sharpened (2026-10-15): with three judge families that also review, no finding can be rejected at all.** That is the mock panel and the production panel of `config/mara.yaml` (Claude, Gemini and GLM review and judge). The rejection is not rare there; it is unreachable, so the AAT's rejection sample stays empty and P8 can never unlock. The rules that combine to make this happen:
  - **Who judges.** The ballot round's judge pass (`mara.ballot_round`) keeps a family from judging a finding it found, unless fewer than `gate.min_independent_judges` (2) families remain independent of all its finders. In that case the finder's family votes at a discount, and the quorum fails.
  - **One finder.** Two judges remain.
    - If they split, agreement is 0.25 (the agreement proxy of `mara.scoring.jury`, chance-corrected for three verdicts). That is below any `gate.human_threshold_alpha` that P4 allows (at least 0.3), so a human decides.
    - If both call it a false positive, no model family agrees with it. `assign_tier` then gives tier D even when a tool corroborates it, so the finding is dropped.
  - **Two or three finders.** Too few independent judges remain for the quorum, so a human decides.

  **What a rejection needs.** At least three judge families independent of all the finding's finders, one voting for it and two against (agreement 0.5), at tier A, which takes tool corroboration. A panel needs a fourth judge family, or a judge family that does not review, before any finding can be rejected; `tests/test_sarif_final_outcome.py` shows this with a fourth mock judge (`tests/scored_rows.py`'s `FOUR_JUDGE_PANEL`).

  **For the owner, beside the choices above:**
  - add a fourth judge family, or a judge that is not a reviewer;
  - change how agreement is read with two judges;
  - accept that unsupervised rejection stays off for this panel.
- Amended 2026-11-01: who may judge and the quorum count differently, and deliberately (the owner's call). Nothing in
  the code changed; this records how the two counts relate.
  - **Who may judge** (`mara.ballot_round`) is planned before any reply, from the config's judge seats that are
    independent of a finding's finders.
  - **The quorum** (`mara.scoring.jury.score`) counts only the judge families that voted validly in both passes.
  - So when an independent judge's reply is voided, the plan still counted it and starts no fallback to the finder's
    own family. The quorum then falls short and a human decides
    (`tests/test_jury_quorum.py::test_a_voided_independent_judge_starts_no_fallback_so_the_quorum_fails_and_a_human_decides`).
    A plan cannot know which replies will be voided, and a finding short of valid independent votes going to a human
    is the safe outcome. Asking the finder's family afterwards would let a finding stand on its own finder's discounted
    vote.
  - The plan counts judge seats where the quorum counts families. The two agree because policy P3 refuses a config
    with two judges of one family (`mara.policy`, "each judge must come from a different model family"). The plan
    relies on P3 for that, and no config that loads can make them differ.
  - The "Who judges" rule of the open question above still stands: in a fallback, the finder's family votes at a
    discount and the quorum fails. Its "fewer than `gate.min_independent_judges` (2) families remain independent" is
    to be read as judge seats, one per family by P3. No test pinned that rule until now:
    `tests/test_jury_quorum.py::test_with_too_few_independent_seats_the_finders_families_judge_at_a_discount_and_the_quorum_still_fails`.
    No sentence of the decision is stale.
