# Human decisions (G-11 write-back)

The ticket is the record; this directory mirrors decisions written by
`scripts/human_queue_issues.py --sync-decisions`. Each record must have:

- a v2 key computed from target ID, revision, context hash, file, line and CWE (target ID: the
  normalised origin URL plus the path below the repository top level for a committed directory;
  revision: that directory's tree in HEAD plus the raw text snapshot, so commits elsewhere in the
  repository, including the one that adds these records, do not unbind them);
- the matching identity fields and finding ID;
- decision, issue URL/number and decision timestamp;
- the surviving unique decision label, its event ID and actor;
- adjudicator training status checked on the decision date.

A record counts only as `mara.decisions` defines it (docs/adr/0002-usable-decisions.md): a
well-formed record (its file name is its key, and the key is the v2 key of its own fields) answers its
ticket; it is ground truth only when it is also bound to the report, uncontradicted on its key and, by
default, made by an adjudicator trained on the decision day according to the register. A usable decision
also settles its finding when the same content is reviewed again (docs/adr/0003-human-resolution.md). Legacy
12-character keys, target-basename matches and decisions from another revision are not
applied automatically. Regenerate the review and ticket after migration. Do not fabricate or
manually relabel old records as current evidence. See [human-queue.md](../../docs/human-queue.md).

`backlog.json` records open ticket count. When it exceeds the configured limit the pipeline raises
the agreement threshold; unresolved findings remain visible and keep the gate blocked.
