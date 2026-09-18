# Human decisions (G-11 write-back)

The ticket is the record; this directory mirrors decisions written by
`scripts/human_queue_issues.py --sync-decisions`. Each record must have:

- a v2 key computed from target ID, revision, context hash, file, line and CWE;
- the matching identity fields and finding ID;
- decision, issue URL/number and decision timestamp;
- the surviving unique decision label, its event ID and actor;
- adjudicator training status checked on the decision date.

Legacy 12-character keys, target-basename matches and decisions from another revision are not
applied automatically. Regenerate the review and ticket after migration. Do not fabricate or
manually relabel old records as current evidence. See [human-queue.md](../../docs/human-queue.md).

`backlog.json` records open ticket count. When it exceeds the configured limit the pipeline raises
the agreement threshold; unresolved findings remain visible and keep the gate blocked.
