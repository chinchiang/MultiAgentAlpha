# Tool triage: a person's dated ruling on a target's tool alert, kept in the workspace

A tool alert on the target under review kept the review incomplete (`unresolved_tool_findings`) and nothing could
clear it. A model's silence or rejection must not, and does not (docs/adr/0007-review-status-and-gate.md). The
target's own suppressions must not either, and every tool is handed neutral configuration instead of the target's. So
an alert a person had read and found to be a false positive, or a risk the organisation had accepted, blocked every
later review of that repository for good: one advisory with no fix was enough. MARA's scans of its own repository had
an answer, dated exceptions with a reason and a review (`tools/trivyignore.yaml`, `tools/osv-*.toml`,
`tools/csp-triage.yaml`); a review of a target had none, and GLOSSARY.md's **Tool alert** already spoke of "the tool's
own triage" as if it had.

**Tool triage** (GLOSSARY.md) is that answer for a target. It is a file in the MARA workspace, by default
`calib/tool-triage.yaml`, of entries a person writes: the target (a report's `target_id`), the alert's tool, rule and
file as the report gives them, a verdict (`false_positive` or `accepted_risk`), the reason, who decided and on which
day, the day it expires, and for an accepted risk the approval it rests on. `mara.tool_triage` reads it and records a
usable entry on the alert it names; a **triaged alert** stays in the report with its ruling and no longer keeps the
review incomplete.

What keeps this from being a way round the gate:

- **Off unless the config turns it on** (`tool_triage.enabled`, false by default and in the shipped configs). With it
  off a review is what it was, whatever the file holds.
- **Never read from the target.** The file is named relative to the workspace and may not climb out of it; a target
  that contains the workspace is already refused (`mara.workspace.check_outside`).
- **Bound to one target, one tool, one rule, one file, exactly.** No pattern, no wildcard. An entry for another target
  is not this review's.
- **Dated, and short.** An entry counts from its decision day to its expiry day, and for no more than
  `tool_triage.max_days` (90 by default, 180 at most) between the two; a longer one is not usable at all, so the limit
  cannot be met by writing a far expiry. Expired, the alert blocks again.
- **Not for a secret.** A gitleaks alert cannot be triaged: a secret is removed and rotated, and those alerts also
  decide whether source may leave the host (the secret preflight), which triage does not touch.
- **By a trained adjudicator** whenever the config requires training (G-13), as a human decision is
  (docs/adr/0002-usable-decisions.md).
- **An accepted risk names its approval** (`approval_ref`), as the config's data-retention approvals do.
- **A false positive corroborates nothing.** An alert ruled a false positive no longer lifts a finding at its place to
  evidence tier A. An accepted risk is a real alert and still does: a finding there follows its own path to the gate.
- **Two usable entries that disagree on one alert are both set aside.**

The audit counts the alerts triaged (`tool_alerts_triaged`), the entries for this target that are not usable, by why
(`tool_triage_not_usable[<why>]`: `expired`, `decided_in_future`, `window_too_long`, `untriageable_tool`,
`untrained`, `contradicted`, `malformed`), and the usable ones that matched no alert (`tool_triage_stale`), so the
file stays honest. A tool result in a report gains `triage` only when it was ruled on; a report of a review without
triage reads as it always did.

## Considered options

- **Route tool alerts through the human queue and its decisions** (docs/adr/0003-human-resolution.md). Rejected. A
  decision binds to the reviewed content, byte for byte, so it lapses at the next commit; that is right for a
  finding, whose claim is about that code, and wrong for an advisory on a pinned dependency, which would have to be
  decided again on every commit until the dependency moves. Tickets per alert would also multiply the backlog the
  queue's tightening reads.
- **Honour the target's own suppressions.** Rejected: the target is untrusted and would clear its own alerts.
- **Bind an entry to the content hash of the file it names.** Rejected for now: it lapses on any edit of a lockfile,
  which is the common case, and the expiry already bounds how long an entry stands. A later change may add it as an
  optional field.
- **Patterns over paths or rules, as `tools/csp-triage.yaml` has.** Rejected: that file triages MARA's own tree, read
  by its maintainers in review; one pattern in a target's triage could clear alerts nobody read.

## Consequences

- With triage on and every alert ruled on, a review of a repository with tool alerts can be complete. With it off, or
  with one alert left, nothing changes: the review is incomplete and the gate blocks.
- The expiry makes triage a recurring duty: an entry is re-read and re-dated at least every `max_days`.
- A line shift does not lapse an entry (it names no line), and a rule that fires twice in one file is ruled on once:
  the entry is about that rule in that file. A reader who needs finer rulings fixes one of the two.
- `scripts/tool_triage.py draft` prints entry drafts for a report's untriaged alerts, each with `TODO` for the verdict
  and the reason so that it is not an entry until a person has ruled; `check` lists the entries of a triage file that
  are malformed or not usable today.
