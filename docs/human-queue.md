# Human queue: tickets, decisions, and tightening (governance item G-11)

The report (Part V, section 15.1; Part X, G-11) requires that findings the pipeline will not decide on its
own go to a person with the full context, that the person's decision is written back into the calibration
set, and that an over-full queue makes the gate stricter rather than letting findings through faster.
This document describes how the prototype does it.

## 1. What is queued

`src/mara/report/human_queue_out.py::build_queue` runs after L5 scoring and turns a finding into a
`HumanQueueItem` when any of these holds:

| reason | condition |
|---|---|
| `majority_needs_human` | more judge votes say `needs_human` than `true_positive` or `false_positive` |
| `alpha_below_threshold` | Krippendorff's alpha across the judge votes is below `gate.human_threshold_alpha` (the effective threshold, see section 4) |
| `tier_c_high` | the finding is accepted at evidence tier C (single family, not corroborated) and its CVSS 4.0 severity is at or above `human_queue.queue_tier_c_min_severity` |

The item carries everything the judges were *not* allowed to see: the finder families, the skeptic's
verdict and the control it named, the red team's exploitability call and preconditions, and every judge
vote in both passes with its family and whether it was a self-family vote. The blinding protects the
judges from anchoring; the person deciding is supposed to see who said what.

Outputs, written by `mara review` when `human_queue.enabled` is true:

- `out/human_queue.md`: one section per item, human-readable.
- `out/human_queue.json`: `{"target", "generated_at", "items": [HumanQueueItem...]}`.
- `out/report.md`: a "Human queue" section listing the items.
- `out/report.sarif`: queued findings are emitted with `level: note` and
  `properties.humanQueue: true` / `humanQueueKey` / `humanQueueReasons`, so GitHub code scanning never
  shows them as confirmed errors. A queued finding is not accepted and does not count against the gate
  until a person decides.

Every item has a stable key, `sha256("<file>:<line>:<CWE>")[:12]`, which is what deduplicates tickets and
links a decision back to a finding.

## 2. Tickets

`scripts/human_queue_issues.py --queue out/human_queue.json --repo owner/repo` creates one GitHub issue
per item through the `gh` CLI (present on GitHub-hosted runners; needs `GH_TOKEN` with `issues: write`):

- the first line of the body is the marker `<!-- mara-hq:<key> -->`; an open issue with the same marker
  and the `mara-human-queue` label means the item is already ticketed and nothing is created;
- the body is the same context as `human_queue.md` plus the instruction on how to decide;
- the labels `mara-human-queue`, `decision:true-positive` and `decision:false-positive` are created if
  missing.

The person decides by adding exactly one `decision:*` label and closing the issue. Nothing in the
script or the pipeline ever approves a finding; the pipeline only reads outcomes.

`--dry-run` prints the mutating `gh` commands instead of running them.

## 3. Decisions come back

`scripts/human_queue_issues.py --repo owner/repo --sync-decisions` reads the closed issues carrying a
decision label and writes one `calib/decisions/<key>.json` per ticket (format in
`calib/decisions/README.md`) plus `calib/decisions/backlog.json` with the current open count.

`scripts/calibrate.py` reads that directory: a `true_positive` decision on a finding that no sample
label covers becomes an extra label with `source: "human_decision"`, so the families that reported it
are credited with a true positive in the next calibration instead of being penalised for a false one.
A `false_positive` decision confirms the existing verdict. Human decisions therefore move per-family,
per-CWE weights in the same run that recomputes them from the seeded corpus.

## 4. Tightening when the backlog is over the limit

At start-up the pipeline reads `human_queue.backlog_file` (default `calib/decisions/backlog.json`).
When the open count is above `human_queue.backlog_limit`:

- the alpha threshold for `needs_human` rises by `tighten_alpha_step` (capped at 1.0), so more
  low-agreement findings are held rather than accepted;
- tier C findings are no longer queued (`tighten_exclude_tier_c`), they simply stay unaccepted.

The report records `human_queue_backlog`, `human_queue_tightened` and `human_alpha_threshold` in its
bias audit. The mechanism only ever tightens; nothing in the configuration lets a full queue lower a
threshold, and the gate's own thresholds are untouched.

## 5. CI wiring

`.github/workflows/mara-review.yml` has a third job, `human-queue`, that runs only on `push` to
`main` after the tests, with `contents: read` and `issues: write` and nothing else. It runs the mock
review of the seeded fixture, then the ticket script with `--sync-decisions`, and uploads
`out/human_queue.*` and `calib/decisions/` as the `mara-human-queue` artifact.

Two deliberate limits:

- The job stays in `--dry-run` until the repository variable `MARA_HUMAN_QUEUE_ISSUES` is set to
  `true`. Until then it prints the `gh` commands and creates nothing.
- The job has no `contents: write` (governance check G-6 would fail otherwise), so it cannot commit the
  synced decisions. A person runs `python3 scripts/human_queue_issues.py --repo owner/repo
  --sync-decisions` locally and commits `calib/decisions/`, or copies the artifact. The ticket remains
  the record; the directory is its mirror.

Against a real target instead of the fixture, replace the review step with the live review and keep the
rest.

## 6. Configuration

```yaml
human_queue:
  enabled: true
  ticketing: github_issues            # none | github_issues
  label: mara-human-queue
  backlog_limit: 20
  backlog_file: calib/decisions/backlog.json
  tighten_alpha_step: 0.1
  tighten_exclude_tier_c: true
  queue_tier_c_min_severity: High     # High | Critical
```

`enabled: false` turns the queue off entirely (no items, no files); the `needs_human` gate logic is
unaffected.

## 7. Verification

`tests/test_human_queue.py` covers selection reasons and the un-blinded context, tightening only when
the backlog is over the limit, the pipeline reading the backlog and recording it, ticket creation and
decision write-back against a fake `gh`, calibration consuming a true-positive decision, and
`scripts/governance_check.py` reporting G-11 as PASS.
