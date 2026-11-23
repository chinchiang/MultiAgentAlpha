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
file as the report gives them, the fingerprints of the alerts read, a verdict (`false_positive` or `accepted_risk`),
the reason, who decided and on which day, the day it expires, and for an accepted risk the approval it rests on. `mara.tool_triage` reads it and records a
usable entry on the alert it names; a **triaged alert** stays in the report with its ruling and no longer keeps the
review incomplete.

What keeps this from being a way round the gate:

- **Off unless the config turns it on** (`tool_triage.enabled`, false by default and in the shipped configs). With it
  off a review is what it was, whatever the file holds.
- **Never read from the target.** The config names the file relative to the workspace, with no drive and no `..`;
  and the review resolves where the file really lies and does not read one inside the target, whatever it is called
  (a symbolic link to a file of the target, a workspace that holds the target): `file_inside_target`.
- **Bound to one target, one tool, one rule, one file, and the alerts a person read.** No pattern, no wildcard. An
  entry lists the **fingerprint** of each alert it rules on: a digest of the text of the line the alert names (of
  its message when the bundle holds no such line, as for an advisory on a lockfile). A shifted line keeps its ruling;
  a changed line, or a new alert of the same rule in the same file, has another fingerprint and blocks. Without this
  a ruling on one false positive would have cleared every later alert of that rule in that file, a real one added by
  the next change included. A review gives its alerts their fingerprints only when tool triage is on, so entries are
  drafted from a report of such a review.
- **Only for a target with a name of its own.** A git repository with an origin is named by it; anything else (a
  directory outside git, a repository without an origin or without a commit) is named by where it lies, and another
  project reviewed at that path would inherit its rulings. Such a target takes no ruling: `unnamed_target`.
- **Dated, and short.** An entry counts from its decision day to its expiry day, and for no more than
  `tool_triage.max_days` (90 by default, 180 at most) between the two; a longer one is not usable at all, so the limit
  cannot be met by writing a far expiry. Expired, the alert blocks again.
- **Not for a secret.** An alert of any gitleaks run (a pre-recorded one is named after its file, `gitleaks-history`)
  or of a rule with a `secrets` part in its id (semgrep's `generic.secrets.…`) cannot be triaged: a secret is removed
  and rotated, and gitleaks' alerts also decide whether source may leave the host (the secret preflight), which triage
  does not touch. Other rules that happen to report a credential are not recognised and can be ruled on.
- **By a trained adjudicator** whenever the config requires training (G-13), as a human decision is
  (docs/adr/0002-usable-decisions.md).
- **An accepted risk names its approval** (`approval_ref`), as the config's data-retention approvals do.
- **A false positive corroborates nothing.** An alert ruled a false positive no longer lifts a finding at its place to
  evidence tier A. An accepted risk is a real alert and still does: a finding there follows its own path to the gate.
- **Usable entries that disagree on one alert are set aside whole.**

The audit counts the alerts triaged (`tool_alerts_triaged`), the entries for this target that are not usable, by why
(`tool_triage_not_usable[<why>]`: `expired`, `decided_in_future`, `window_too_long`, `secret_alert`, `untrained`,
`contradicted`, `unnamed_target`, `malformed`, and `file_inside_target` for the file itself), and the usable entries
none of whose fingerprints matched an alert (`tool_triage_stale`), so the file stays honest. A tool result in a
report gains `fingerprint` only when the review applied tool triage and `triage` only when it was ruled on; a report
of a review without triage reads as it always did.

## Considered options

- **Route tool alerts through the human queue and its decisions** (docs/adr/0003-human-resolution.md). Rejected. A
  decision binds to the reviewed content, byte for byte, so it lapses at the next commit; that is right for a
  finding, whose claim is about that code, and wrong for an advisory on a pinned dependency, which would have to be
  decided again on every commit until the dependency moves. Tickets per alert would also multiply the backlog the
  queue's tightening reads.
- **Honour the target's own suppressions.** Rejected: the target is untrusted and would clear its own alerts.
- **Bind an entry to the content hash of the file it names.** Rejected: it lapses on any edit of the file. The
  fingerprint binds to the one line the alert is about.
- **Bind an entry to its rule and file alone**, as the first version of this change did. Rejected in review of it: it
  cleared alerts nobody had read (above).
- **Patterns over paths or rules, as `tools/csp-triage.yaml` has.** Rejected: that file triages MARA's own tree, read
  by its maintainers in review; one pattern in a target's triage could clear alerts nobody read.

## Consequences

- With triage on and every alert ruled on, a review of a repository with tool alerts can be complete. With it off, or
  with one alert left, nothing changes: the review is incomplete and the gate blocks.
- The expiry makes triage a recurring duty: an entry is re-read and re-dated at least every `max_days`.
- A line shift does not lapse an entry, an edit of the line does, and each alert of a rule in a file is ruled on by
  its own fingerprint. Two alerts on lines with the same text have one fingerprint and are ruled on together.
- What it does not stop: a repository that copies another's origin URL into its own `.git/config` is named as that
  one is, and takes its rulings where rule, file and line text also match. The target is untrusted, and its name is
  its own claim; the fingerprint is what limits this.
- `scripts/tool_triage.py draft` prints entry drafts for a report's untriaged alerts, with their fingerprints and
  `TODO` for the verdict and the reason, so that a draft is not an entry until a person has ruled; `check` lists the
  entries of a triage file that are malformed, not usable today or contradicted.
