# Human decisions (G-11 write-back)

One JSON file per decided human-queue ticket, written by `scripts/human_queue_issues.py --sync-decisions`
from closed issues that carry `decision:true-positive` or `decision:false-positive`:

```json
{
  "key": "<12 hex chars>",           # sha256(file:line:cwe)[:12], the same key the pipeline puts in human_queue.json
  "decision": "true_positive",      # or false_positive
  "issue": 42, "url": "https://github.com/.../issues/42", "decided_at": "2026-09-12T08:00:00Z",
  "target": "/path/reviewed", "finding_id": "F-0007", "cwe": "CWE-89", "file": "app.py", "line": 32
}
```

`scripts/calibrate.py` reads this directory: a `true_positive` decision becomes an extra label for the
matching sample (so a family that found it gets a true positive instead of a false positive), a
`false_positive` decision confirms a false positive. `backlog.json` records the open ticket count;
when it is above `human_queue.backlog_limit` the pipeline tightens (higher alpha threshold, tier C not
queued) instead of letting anything through faster.

Nothing in this directory is edited by hand: the ticket is the record, this is its mirror.
