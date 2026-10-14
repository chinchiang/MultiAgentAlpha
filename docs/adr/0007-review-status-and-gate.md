# Review status and gate: one pure module decides them, and the gate records why it blocks

The **review status**, its **incomplete reasons** and the **gate** were decided in the middle of `Pipeline.run()`. Each incomplete reason was a string literal appended there. The score summary kept a hand copy of those codes for its allowlist, and tests could check them only by reading `pipeline.py` as text. The gate was stored as one boolean: neither the report nor code scanning said why it blocked or which findings blocked it, although the rollout notes and report section 15.4 say blocking findings are marked. These rules now live in one module, `mara.review_status`. `assess(facts, consensus, tool_results, dimensions, outcome_policy, gate_policy)` takes the facts `run()` has gathered: whether the context was complete, egress blocked, every required tool ran, the ML-BOM signature verified, the context view missing, which audit counters make the review incomplete, the rollout phase, and whether `--fail-on-gate` was given. It returns the review status, the incomplete reasons in the order they have always been written, the gate, the gate reasons, whether a blocked gate is enforced, the overall score (null when the review is incomplete), the blocking reason of each **blocking finding**, and how many tier C findings blocked because the queue was tightened. The per-finding blocking rules move there from `Pipeline.blocking_reason`, so no gate rule is left in the pipeline. An empty list of dimensions is a `ValueError`: the config already requires at least one, and the old code's overall score of 0.0 for it made a review that scored nothing look like a score of zero. The module is pure: `run()` still verifies the ML-BOM signature with cosign and passes in only the result, and it writes the counts `assess` returns into the audit. Like `decide()` (docs/adr/0005-jury-outcome.md), this lets the new rules be checked against the old ones on every combination of facts. The comparison leaves out only what changes on purpose: an empty list of dimensions, which has a test of its own for the error, and whether the gate is enforced, which the old rules did not decide and which is tested on the four combinations of phase and flag.

The secret preflight is a second pure function in the same module. It takes the provider mode, the gitleaks runs (whether each ran, and its results) and the calibration answer key, and returns whether source egress is blocked and which results the answer key exempts. As before, only a live review blocks: when gitleaks did not run, failed to run, or found a secret the answer key does not declare. `run()` still runs gitleaks, re-runs it in a live review given pre-recorded SARIF, and uses the result to decide whether any provider is called. The decision is the source of the incomplete reason `source_egress_blocked_by_secret_preflight`. It belongs here rather than with the L0 tools, so a later rework of where tool evidence comes from does not move it again. Behaviour tests replace the test that asserted the line of `pipeline.py` holding it.

The gate has a policy of its own. `GatePolicy` holds only what the gate alone reads: `block_on_tiers`, `block_on_severity` and `min_dimension_score`. The tier C rule takes `exclude_tier_c` and `tier_c_min_severity` from the one `OutcomePolicy` the pipeline builds for `decide()`. The pipeline reads the human queue's tightening once, in `Pipeline.__init__`, so the jury outcome and the gate cannot see two different tightenings. The tightening itself stays in `human_queue_out` for now.

The module owns the codes it writes. Together with the audit's `INCOMPLETE_COUNTERS`, which stay in `mara.audit` until the reply-outcome accounting is reworked, they make up the set of every incomplete reason. The score summary's allowlist imports that set instead of copying it. It is still an allowlist (docs/adr/0004-score-summary.md): a code reaches the summary only by being in the set, and a report holding anything else is refused. `unresolved_human_review` is one of these codes and nothing else. The human queue also used it as a fallback reason for a finding needing a human with no reason of its own. That branch could never run, since `decide()` gives every such finding at least one reason, and a test now pins that. The fallback is removed. The markdown report's fallback text for such a row reads "no reason recorded". The workbench keeps its label for the old queue reason, which older reports may still hold.

The gate now records its reasons. The report gains `gate_reasons`, a list in fixed order without repeats: `review_incomplete`, `blocking_tier_and_severity`, `tier_c_while_tightened`, `dimension_below_minimum`. It holds no finding ids. Each consensus row gains `blocking_reason`, set only on a blocking finding, using the same two finding codes. Both fields default to empty, so a report written before them reads as having no gate reasons and no blocking finding even where its gate blocked; that gap stays with older reports. The reasons are shown in three places:

- `report.md`: next to the gate, and on each blocking finding;
- SARIF: as properties of the run and of each blocking result. A result's level does not change, because changing it would change the code-scanning alert;
- the CLI: next to the gate.

The score summary does not export them. `blocking_tier_and_severity` says that at least one accepted tier A or B finding of High or Critical severity exists, which is the kind of information ADR 0004 keeps from crossing the border; whether to export gate reasons is for the owner and legal to decide.

The gate also records whether it was enforced. The rule was derived three times: by the CLI for its exit code, by the markdown header, and by the workbench, which inferred it from an exit code of 2 that a usage error also gives. A blocked gate is enforced when the rollout phase is `blocking` or `--fail-on-gate` was given. `run()` takes `fail_on_gate` (default false) and passes it to `assess`. The report gains `gate_enforced`:

- true when the gate blocked and was enforced;
- false when it blocked without being enforced, and false when it passed, since nothing was held back;
- null in a report written before the field, meaning unknown rather than "not enforced".

The CLI's exit code and the markdown header read it, SARIF carries it as the run property `gateEnforced` beside `gatePassed`, and the workbench reads it, falling back to the exit code only when it is null. The score summary does not export it; ADR 0004 adds a field to the allowlist only on purpose, and nobody has asked for this one.

The final outcome has one encoding. `ConsensusResult.final_accepted` and `final_needs_human` are removed. Every reader now compares the four-valued `final_outcome`: the gate, the incomplete reason for unresolved human review, SARIF and the PSIRT hand-off. This amends docs/adr/0003-human-resolution.md only in how the final outcome is expressed; the jury outcome is still kept untouched beside it. SARIF decides from the final outcome which findings it emits:

- an accepted finding, at the level of its severity;
- a finding needing a human, as a note, whether or not it is queued;
- a rejected finding under rejection review, as a note;
- a human-resolved finding whose final outcome is rejected, as a dismissed alert.

Other rejected and dropped findings are not emitted. Before, a finding needing a human was emitted only once it was queued, so with `human_queue.enabled: false` it was missing from code scanning while the review was incomplete because of it. With the queue enabled, every such finding is queued, so the output does not change. A SARIF test pins both: such a finding is emitted as a note with the queue disabled, and a report with the queue enabled gives the same output as before.

The shadow-phase baseline (`govdocs.baseline_metrics`) counts the jury outcome's four values. It used to count every finding that was not accepted as rejected, so findings needing a human and dropped findings were counted as rejected. Now rejected counts only rejected findings, and dropped and needing-a-human findings get counts of their own. A report without `gate_passed` counts as blocked rather than passed (fail closed). The baseline measures the pipeline, so it reads the jury outcome, as ADR 0003 requires.

## Considered options

- **Keep `blocking_reason` in the pipeline:** rejected. The gate's rules would stay split between the pipeline and the module.
- **Keep the gate a boolean:** rejected. Whoever reads a blocked report would have to guess why, and the governance and report text would stay untrue.
- **Export the gate reasons in the score summary:** not done here; see above.
- **Keep `final_accepted` and `final_needs_human` as one-line aliases of `final_outcome`:** rejected. The readers would keep a second vocabulary for the same outcome.
- **Let the module verify the signature and write the audit itself:** rejected. With IO and side effects inside, the module could not be checked exhaustively against the old rules.
- **Move `INCOMPLETE_COUNTERS` into the module now:** left to the reply-outcome accounting work (docs/adr/0008-reply-accounting.md), which owns those counters.
- **Forbid disabling the human queue instead of changing what SARIF emits:** rejected. Code scanning should show a finding's state, not whether the queue is on; an incomplete review whose reason code scanning cannot see fails open.
- **Give the queue's fallback a code of its own, or keep `unresolved_human_review` shared and say who owns it:** rejected. A branch that cannot run does not need a code.
- **Decide enforcement in the module but keep it out of the report:** rejected. The workbench would keep guessing from an ambiguous exit code, and the glossary's "recorded but not enforced" would have nothing recorded.
- **Read a report without `gate_enforced` as not enforced:** rejected. It would assert what an older report never said.
- **Record on a passed gate whether it would have been enforced:** rejected. The same field would mean two things.
- **Export `gate_enforced` in the score summary:** not done here; see above.
- **Leave the secret preflight to the rework of the L0 tool evidence, or keep it in `run()`:** rejected. It decides one of this module's codes; left in `run()` it is testable only by reading the source.
- **Add the gate's settings to `OutcomePolicy`:** rejected. It would widen `decide()`'s interface with fields it never reads.
- **Let `GatePolicy` read the tightening from the config itself:** rejected. The jury outcome and the gate would each compute the tightening, which is the split this change removes.
- **Move the tightening out of `human_queue_out` now:** not done. It is tied to the queue and its backlog, and moving it belongs with the work on the queue's identity.
- **With no dimensions, give a null overall score, or keep 0.0:** rejected. Null would make a complete review without a score, a state the glossary does not define; 0.0 reads as a score of zero.
