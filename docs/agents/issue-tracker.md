# Issue tracker: GitHub

Issues and specs for this repo live as GitHub issues. Use the `gh` CLI for all operations.

## Conventions

- **Create an issue**: `gh issue create --title "..." --body "..."`. Use a heredoc for multi-line bodies.
- **Read an issue**: `gh issue view <number> --json number,title,body,labels,comments`.
- **List issues**: `gh issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'` with appropriate `--label` and `--state` filters.
- **Make an issue a sub-issue of a parent**: `gh issue create --parent <parent> ...`, or `gh issue edit <parent> --add-sub-issue <child>` afterwards (`gh` 2.94+). Older `gh`: `gh api --method POST repos/<owner>/<repo>/issues/<parent>/sub_issues -F sub_issue_id=<child-db-id>` (database id, as in **Blocking** below). Without sub-issues, put `Part of #<parent>` at the top of the child body.
- **Blocking**: GitHub's **native issue dependencies**, the canonical, UI-visible representation. Add an edge with `gh issue create --blocked-by <n>,<n> ...` or `gh issue edit <child> --add-blocked-by <blocker>` (`gh` 2.94+). Older `gh`: `gh api --method POST repos/<owner>/<repo>/issues/<child>/dependencies/blocked_by -F issue_id=<blocker-db-id>`, where `<blocker-db-id>` is the blocker's numeric **database id** (`gh api repos/<owner>/<repo>/issues/<n> --jq .id`, _not_ the `#number` or `node_id`). Where dependencies aren't available, fall back to a `Blocked by: #<n>, #<n>` line at the top of the child body. A ticket is unblocked when every blocker is closed.
- **Count open blockers**: `gh api repos/<owner>/<repo>/issues/<n> --jq .issue_dependencies_summary.blocked_by` (open blockers only; 0 means startable). `gh issue view <n> --json blockedBy` also lists closed blockers, so filter it: `--jq '[.blockedBy.nodes[] | select(.state == "OPEN")] | length'`.
- **Comment on an issue**: `gh issue comment <number> --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`. Then read the labels back with `gh api repos/<owner>/<repo>/issues/<n> --jq '[.labels[].name]'`: right after a change, `gh issue list --label` can still list the issue under its old labels.
- **Close**: post the explanation with `gh issue comment <number> --body "..."`, then `gh issue close <number>`. On an already-closed issue, `gh issue close --comment` drops the comment and still exits 0.

Infer the repo from `git remote -v`; `gh` does this automatically when run inside a clone.

File issues only into the user's own repo. Never file into `mattpocock/skills` (the repo these skills come from) unless the user owns it. In a fork, `gh` can default to the upstream parent, so before the first `gh issue create` of a session, check the target with `gh repo view --json nameWithOwner` and confirm it with the user if it is not their repo.

## Agent briefs

An **Agent brief** (`GLOSSARY.md`) follows the triage skill's template, which lives in the plugin cache, outside this
repository. What this repository asks of a brief on top of it is here.

### Before writing the current behavior

1. Read the code the issue names.
2. Find with `git grep` every direct caller of what the change would touch, and every reader of the same file or
   format (a file a tool writes, a report, a config), not only those the issue names. A reader of a caller's output is
   not required.
3. Run what can be run (the failing case, the command), and write the commit it ran on as a `run:` (below).

### How each statement was established

Every statement of how the code behaves now, under "Current behavior" and wherever else a brief makes one, ends with
how it was established, in parentheses, in one of three forms:

- `run:` the command, or what was reproduced, and the commit or head it ran on:
  `(run: git log --oneline 036fc5a..94f8924 -- docs/agents/issue-tracker.md, empty)`.
- `read:` what was read (a function, a doc, a log, a comment) and at which commit:
  `(read: docs/agents/issue-tracker.md on 94f8924)`.
- `carried:` where it came from (an issue body, a review, a comment), when nobody checked it:
  `(carried: this issue's body, not re-verified)`. A carried statement may stay in the brief; the agent that picks the
  issue up checks it first.

Two sources share one parenthesis, parted by `;`: `(run: …; read: …)`. A marker on a section's heading line covers
every statement of that section: `**Current behavior** (run: each case reproduced in a throwaway repository on <head>)`.

### A rule the brief asks for

A brief that asks for a rule or a procedure to be written down names the one document that states it, and those, if
any, that point at it (`CODING_STANDARDS.md`, "One concept, one wording"), so that the agent does not meet it with a
restatement.

## A rule a document already states

A question of triage, or a fact a handoff passes on, is often one a document of this repository already answers.

- Before a question goes into the notes triage posts (the triage skill's `## Triage Notes`, under "What we still need
  from you"), look for that document. When one answers it, the notes quote its rule with a `read:` marker ("How each
  statement was established", above), which dates the quote by its commit, and ask only what the rule leaves open
  (#453's asked one that `docs/CHANGELOG.md`, "版本規則", answers). A question that asks the owner to set a written rule
  aside says so, and names the rule and where it is written.
- A handoff is held to `CODING_STANDARDS.md`, "One concept, one wording", as any document is: it names the document
  that states a rule it relies on, and quotes none, for the session that reads it takes a restatement, dated by no
  commit, for the rule itself.

## Pull requests as a triage surface

**PRs as a request surface: no.** _(Set to `yes` if this repo treats external PRs as feature requests; `/triage` reads this flag.)_

When set to `yes`, PRs run through the same labels and states as issues, using the `gh pr` equivalents:

- **Read a PR**: `gh pr view <number>`, then `gh pr view <number> --comments` (off a TTY, `--comments` prints only the comments, not the body), and `gh pr diff <number>` for the diff.
- **List external PRs for triage**: `gh api --paginate 'repos/{owner}/{repo}/pulls?state=open' --jq '.[] | select(.author_association | IN("OWNER","MEMBER","COLLABORATOR") | not) | {number, title, author: .user.login, author_association, labels: [.labels[].name]}'`.
- **Comment / label / close**: `gh pr comment`, `gh pr edit --add-label`/`--remove-label`, `gh pr close`.

GitHub shares one number space across issues and PRs, so a bare `#42` may be either: resolve with `gh pr view 42` and fall back to `gh issue view 42`.

## When a skill says "publish to the issue tracker"

Create a GitHub issue.

## When a skill says "fetch the relevant ticket"

Read it as in **Read an issue** above.

## Wayfinding operations

Used by `/wayfinder`. The **map** is a single issue with **child** issues as tickets.

- **Map**: a single issue labelled `wayfinder:map`, holding the Notes / Decisions-so-far / Fog body. `gh issue create --label wayfinder:map`.
- **Child ticket**: an issue linked to the map as a GitHub sub-issue (see **Make an issue a sub-issue of a parent**). Where sub-issues aren't enabled, add the child to a task list in the map body and put `Part of #<map>` at the top of the child body. Labels: `wayfinder:<type>` (`research`/`prototype`/`grilling`/`task`). Once claimed, the ticket is assigned to the driving dev.
- **Blocking**: see **Blocking** under Conventions.
- **Frontier query**: list the map's open children (`gh issue list --state open`, scoped to the map's sub-issues / task list), drop any with an open blocker (see **Count open blockers**, or an open issue in the `Blocked by` line) or an assignee; first in map order wins.
- **Claim**: `gh issue edit <n> --add-assignee @me`, the session's first write.
- **Resolve**: `gh issue comment <n> --body "<answer>"`, then `gh issue close <n>`, then append a context pointer (gist + link) to the map's Decisions-so-far.
