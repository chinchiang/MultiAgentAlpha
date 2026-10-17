# Report metadata: fields of the report, the bias audit holds counts and statistics, and an old report is read into the fields

`report.bias_audit` began as the audit counters and became a grab-bag. After the pipeline snapshotted the audit into the report, it wrote eight more keys into both `self.audit` and `report.bias_audit`:
- the human queue's size, backlog, whether it was tightened and the agreement threshold that followed;
- the number of PSIRT payloads;
- the ML-BOM status per self-hosted model;
- the rollout phase;
- the latest model red-team evaluation per family.

Two more echoed what the report holds elsewhere, `tools_ran` and `tool_results_ingested`; and `ml_bom_signature` held the BOM signature check's result as text, of which the review status keeps only whether it verified. Nothing read the `self.audit` copies. The readers fished the report's copies out by string:
- the markdown header, its ML-BOM and model-evaluation sections, and the audit list, which printed every key and skipped only the two nested ones;
- the workbench's budget and run metadata;
- a template test that read the rollout phase from the raw JSON.

SARIF exported all of it as the run property `biasAudit`. GLOSSARY.md had no word for any of it.

The report now holds these as fields of its own, and the **bias audit** (GLOSSARY.md) holds counts and statistics only:
- the reply accounting (docs/adr/0008-reply-accounting.md) and the pipeline's own counts;
- `tier_c_blocked_while_tightened`, which `run()` writes from `assess` (docs/adr/0007-review-status-and-gate.md);
- the jury's agreement and position flips (docs/adr/0005-jury-outcome.md);
- `exchange_version`, which calibration compares within, reading a report without it as version 1 (docs/adr/0001-reply-outcome-accounting.md).

`ReviewReport` gains five fields, each with a small model:
- `rollout_phase`;
- `human_queue_tightening`: the backlog, null when none was known; whether the queue was tightened; the agreement threshold. Named after **queue tightening** (GLOSSARY.md);
- `ml_bom`: model id, status, component, version and digest per model;
- `ml_bom_signature`;
- `model_eval`: date, mode and verdict per family.

Each has a default: null or empty means "not recorded" in a report written before the value existed. The counts are not stored at all: the human queue's size, the PSIRT payloads and the tool results ingested are the lengths of the report's own lists, and the tools that ran are the `tool_health` entries that ran. A number kept twice can disagree with itself.

A report written before this change is read into the fields. A `ReviewReport` validator, run before the fields are read, moves each old key out of `bias_audit` into its field:
- it reads a backlog recorded as `"unknown"` as null;
- it builds the queue tightening only when all three of its keys are there, and guesses nothing from part of them;
- it reads an old value that does not have its field's shape, such as a rollout phase no config knows or an ML-BOM entry without a model id, as not recorded rather than failing the report, which the workbench and the score summary would then refuse altogether;
- it keeps a field the report already has over an old key beside it;
- it drops the counts and `tools_ran`.

An old report and a new one therefore read alike, and every reader has one path. The validator also runs when the pipeline builds the report, but finds nothing to move there: the pipeline writes no old key into its audit, and passes or sets the fields itself. Every reader that reads `report.json` through `ReviewReport` goes through it, the score summary and the workbench among them, and the markdown and SARIF writers are given a `ReviewReport`. `scripts/calibrate.py` and the shadow-phase baseline read the raw JSON, but only for counts, statistics, `exchange_version` and the human queue, none of which moves.

What the readers show:
- `report.md`: the header reads the rollout phase field, and the ML-BOM and model-evaluation sections read their fields, with the BOM signature on a line of its own. The human queue section gains a line with the queue tightening. The deterministic-tool section names the tools that ran and how many results they gave. The audit list prints the bias audit as it now is.
- SARIF: `biasAudit` carries the bias audit as it now is. No property is added for the moved values, since nobody has asked for one.
- The workbench: the page asks the same questions and the server answers them from the fields, with the API's shape unchanged. The read-only demo is captured again.
- The score summary exports none of the new fields: it is built from an allowlist (docs/adr/0004-score-summary.md).

## Considered options

- **Write both, the fields and the old keys, for a while:** rejected. Every reader would have two places to read the same value, and the old keys would never have a version at which they could be dropped.
- **Read the fields only, and an old report as not recorded:** rejected. The workbench shows every retained run, and would lose the rollout phase and the queue's tightening its older reports did record. ADR 0007 read a missing `gate_enforced` as unknown because no old report recorded it; these old reports did record their values.
- **Move the jury's statistics and `exchange_version` out too:** rejected. They are counts and statistics of the review, ADR 0005 and ADR 0007 have the pipeline write them into the audit, and calibration's rule that a report without `exchange_version` is version 1 reads the audit.
- **Keep the counts as fields:** rejected. They would be a second copy of the lengths of the report's own lists.
- **A report schema version:** not added. As with ADR 0004, 0005 and 0007, a field with a default that reads "not recorded" and the validator above are enough. `EXCHANGE_VERSION` versions the reply accounting, which this does not change.
- **Add the rollout phase to SARIF as a property, or remove the workbench payload the page never reads:** not done here; one change at a time.

## Consequences

- A report's `bias_audit` key set is smaller by the eleven keys above (ten in a review whose config does not require a signed BOM); `report.md` and SARIF change with it, and v0.13.0 records it.
- `human_decisions_not_usable[<why>]` is a count and stays, but it borrows the per-family encoding with a reason in place of a family, so `mara.audit.by_family` reads the reason as a family. Its readers ignore families without calls, so no number is wrong today. It is left for the counters' own rework, since ADR 0008 keeps persisted counter names.
