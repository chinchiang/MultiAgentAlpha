# Review status and gate: one pure module decides them, and the gate records why it blocks

The **review status**, its **incomplete reasons** and the **gate** were decided in the middle of `Pipeline.run()`. Each incomplete reason was a string literal appended there. The score summary kept a hand copy of those codes for its allowlist, and tests could check them only by reading `pipeline.py` as text. The gate was stored as one boolean: neither the report nor code scanning said why it blocked or which findings blocked it, although the rollout notes and report section 15.4 say blocking findings are marked. These rules now live in one module, `mara.review_status`. `assess(facts, consensus, tool_results, dimensions, policy)` takes the facts `run()` has gathered: whether the context was complete, egress blocked, every required tool ran, the ML-BOM signature verified, the context view missing, and which audit counters make the review incomplete. It returns the review status, the incomplete reasons in the order they have always been written, the gate, the gate reasons, the overall score (null when the review is incomplete), the blocking reason of each **blocking finding**, and how many tier C findings blocked because the queue was tightened. The per-finding blocking rules move there from `Pipeline.blocking_reason`, so no gate rule is left in the pipeline. The module is pure: `run()` still verifies the ML-BOM signature with cosign and passes in only the result, and it writes the counts `assess` returns into the audit. Like `decide()` (docs/adr/0005-jury-outcome.md), this lets the new rules be checked against the old ones on every combination of facts.

The module owns the codes it writes. Together with the audit's `INCOMPLETE_COUNTERS`, which stay in `mara.audit` until the reply-outcome accounting is reworked, they make up the set of every incomplete reason. The score summary's allowlist imports that set instead of copying it. It is still an allowlist (docs/adr/0004-score-summary.md): a code reaches the summary only by being in the set, and a report holding anything else is refused.

The gate now records its reasons. The report gains `gate_reasons`, a list in fixed order without repeats: `review_incomplete`, `blocking_tier_and_severity`, `tier_c_while_tightened`, `dimension_below_minimum`. It holds no finding ids. Each consensus row gains `blocking_reason`, set only on a blocking finding, using the same two finding codes. Both fields default to empty, so a report written before them reads as having no gate reasons and no blocking finding even where its gate blocked; that gap stays with older reports. The reasons are shown in three places:

- `report.md`: next to the gate, and on each blocking finding;
- SARIF: as properties of the run and of each blocking result. A result's level does not change, because changing it would change the code-scanning alert;
- the CLI: next to the gate.

The score summary does not export them. `blocking_tier_and_severity` says that at least one accepted tier A or B finding of High or Critical severity exists, which is the kind of information ADR 0004 keeps from crossing the border; whether to export gate reasons is for the owner and legal to decide.

The final outcome has one encoding. `ConsensusResult.final_accepted` and `final_needs_human` are removed. Every reader now compares the four-valued `final_outcome`: the gate, the incomplete reason for unresolved human review, SARIF and the PSIRT hand-off. SARIF's dismissed alert is a human-resolved finding whose final outcome is rejected. This amends docs/adr/0003-human-resolution.md only in how the final outcome is expressed; the jury outcome is still kept untouched beside it.

The shadow-phase baseline (`govdocs.baseline_metrics`) counts the jury outcome's four values. It used to count every finding that was not accepted as rejected, so findings needing a human and dropped findings were counted as rejected. Now rejected counts only rejected findings, and dropped and needing-a-human findings get counts of their own. A report without `gate_passed` counts as blocked rather than passed (fail closed). The baseline measures the pipeline, so it reads the jury outcome, as ADR 0003 requires.

## Considered options

- **Keep `blocking_reason` in the pipeline:** rejected. The gate's rules would stay split between the pipeline and the module.
- **Keep the gate a boolean:** rejected. Whoever reads a blocked report would have to guess why, and the governance and report text would stay untrue.
- **Export the gate reasons in the score summary:** not done here; see above.
- **Keep `final_accepted` and `final_needs_human` as one-line aliases of `final_outcome`:** rejected. The readers would keep a second vocabulary for the same outcome.
- **Let the module verify the signature and write the audit itself:** rejected. With IO and side effects inside, the module could not be checked exhaustively against the old rules.
- **Move `INCOMPLETE_COUNTERS` into the module now:** left to the reply-outcome accounting work (architecture candidate 2), which owns those counters.
