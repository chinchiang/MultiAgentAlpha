# Shadow-phase runbook: the Pilot poller (G-10, G-11)

How a host runs the shadow phase's live reviews of one **Pilot repository** with the **Pilot poller**
(`scripts/pilot_poller.py`; the terms in bold are in `GLOSSARY.md`). What the poller does in one run, which tickets it
withdraws, the files it keeps and its exit codes are in its docstring; this runbook does not restate them. It names no
real host, repository or installation: those go in the README of the Ticket repository.

## 1. What is where

- **The Pilot repository**: a private GitHub repository whose pull requests are reviewed. It gets no workflow and no
  ticket; its developers do not see the shadow phase.
- **The Ticket repository**: a private repository open to the security team only. Its issues are where the tickets
  are filed, and a clone of it on the host is the **MARA workspace** (`MARA_HOME`): the reviews and the poller's files
  under `pilot/`, the backlog and the decision records under `calib/decisions/`, and the training register
  `training/records.yaml`. Nothing of it is copied into this repository: a decision record names the file, line, CWE
  and adjudicator of a finding.
- **The host**: a Linux x86_64 machine inside the network of the self-hosted endpoints, as section 1 of
  `docs/model-eval-runbook.md` describes, running unattended.

## 2. Prerequisites

1. This repository checked out on the host and installed from the hash-pinned closure (`INSTALL.md` section 2.2), the
   tools installed (`scripts/install_tools.py`), the real config in `config/local/mara.yaml` (`INSTALL.md` section 4)
   with `rollout.phase` as in section 5 below, and `mara check-config config/local/mara.yaml` passing.
2. The model keys in environment variables only (`GEMINI_API_KEY`, the gateway's key), and AWS credentials for
   Bedrock that the default chain refreshes without a person: an instance role or a `credential_process`, not an
   interactive `aws sso login`, whose session expires between runs.
3. A GitHub App installed on the two repositories, with no more access than this:

   | Repository | Permissions |
   |---|---|
   | Pilot repository | `Contents: read`, `Pull requests: read` |
   | Ticket repository | `Contents: read and write`, `Issues: read and write` |

   Its private key on the host only. An installation token lasts an hour, so each run starts from a fresh one in
   `GH_TOKEN`, minted from the App's key; `gh auth setup-git` lets git fetch and push with it.
4. The Ticket repository cloned on the host as the workspace, its commits made by the App's identity
   (`git config user.name`, `user.email` in that clone).
5. The adjudicator's training recorded in the workspace's `training/records.yaml` (`scripts/training_register.py`,
   with `MARA_HOME` set): a decision by an adjudicator untrained on its day answers its ticket and is not used for
   calibration (`docs/adr/0002-usable-decisions.md`).
6. A clone directory outside the workspace (the poller refuses one inside it, or holding it, with exit 2).

## 3. Running it

First a dry run, which reviews, files, withdraws, writes and commits nothing, and prints what a run would review, file
and withdraw:

```bash
MARA_HOME=<workspace> .venv/bin/python scripts/pilot_poller.py --pilot <owner/pilot> --tickets <owner/tickets> \
    --config config/local/mara.yaml --clones <clone dir> --dry-run
```

Then the same command without `--dry-run` from cron, every 15 minutes, in the checkout, with `MAILTO` set to the
operator. The reviews and the ticket script print their progress on stdout, so stdout goes to a log and only stderr is
mailed: the poller's `ERROR` lines, and a child's errors.

```cron
*/15 * * * * cd <checkout> && GH_TOKEN="$(<mint a token>)" MARA_HOME=<workspace> .venv/bin/python scripts/pilot_poller.py --pilot <owner/pilot> --tickets <owner/tickets> --config config/local/mara.yaml --clones <clone dir> >> <log file>
```

## 4. Tickets

The poller files each review's human queue with `scripts/human_queue_issues.py`, and the adjudicator decides on a
ticket as `docs/human-queue.md` says; the next run's sync records the decision in the workspace. Which tickets the
poller withdraws (**Withdrawn ticket**), and what it does with a pull request that closes, merged or not, is in its
docstring.

What the poller does not see: a pull request opened and closed between two runs (within the 15 minutes) never enters
its state, so it is never reviewed.

## 5. The phase

- On the day the first live review of a Pilot repository pull request runs, `rollout.phase: shadow` and `started_on`
  go in `config/local/mara.yaml` and in this repository's `config/mara.yaml` (`docs/agents/pr-flow.md`). What the
  phase does to a blocked gate is in `GLOSSARY.md`, **Gate**.
- Before about day 90 of the phase (G-10 fails once it is a month past `shadow_months`), the baseline report is made
  from the workspace's reviews and kept there:

  ```bash
  MARA_HOME=<workspace> .venv/bin/python scripts/rollout_phase.py --config config/local/mara.yaml baseline \
      --runs <workspace>/pilot/reviews --out <workspace>/pilot/rollout-baseline-<date>.md
  ```

  Without `--out` it would write under `docs/`, which is published. Then `rollout.baseline_report` in
  `config/local/mara.yaml` names that report by its absolute path (`scripts/rollout_phase.py` looks for a relative one
  below this checkout, not the workspace), and `scripts/rollout_phase.py --config config/local/mara.yaml advance --to
  advisory` says whether the move can be made.

## 6. Pausing

Polling is paused (the cron line commented out) and the reason written on the tracking issue when:

- a finding or code of the Pilot repository shows up outside the Ticket repository;
- a policy refuses the config at load, P5 (data residency) above all;
- a week's tokens exceed the threshold the operator sets after the first two weeks.
