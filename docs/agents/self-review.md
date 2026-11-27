# Self-review of a change

Step 3 of `docs/agents/pr-flow.md` has a change reviewed in the working tree before its first commit. Two sub-agents
read it in parallel, one for each axis, and this document is what they follow, so the prompt that starts them stays
short. They are not MARA's reviewers (`GLOSSARY.md`, "Reviewer round"): they review this repository's own change, not a
target.

## Starting them

The review of a change has a directory of its own, `scratch/self-review-<issue>/`, where `<issue>` is the issue's number
(with no issue, the branch's name with `/` turned into `-`):

```text
scratch/self-review-<issue>/
├── spec.md              # the main session writes it before starting the sub-agents; both only read it
├── standards-report.md  # the main session writes each report, verbatim, as its sub-agent returns
├── spec-report.md
├── standards-report-2.md # this and spec-report-2.md, after a second review (below)
├── spec-report-2.md
├── standards/           # the standards sub-agent's throwaway repositories and worktrees, and nothing else
└── spec/                # the spec sub-agent's, and nothing else
```

Before starting them, make the directory, its empty `standards/` and `spec/`, and `spec.md`. `spec.md` holds the spec
(the issue, or the decisions the owner agreed) and what to verify: the spec sub-agent reads the spec nowhere else. Each
prompt begins:
"Read `docs/agents/self-review.md`, the section "Both sub-agents" and the one for your axis, and follow them." Then it
names the sub-agent's own directory by its absolute path, and what belongs to this change: for the standards
sub-agent, which sources below apply and what to look at first; for the spec sub-agent, the absolute path of `spec.md`,
and the output of step 3's run of each mutation list the change adds or edits.
Start both together, in the foreground.

As each returns, write its report verbatim to `standards-report.md` or `spec-report.md`, and report the two results
apart. Once both are back, empty `standards/` and `spec/` of what a sub-agent could not remove: a worktree with
`git -C <main checkout> worktree remove --force <worktree>` (removing its directory alone leaves git's record of it),
then the rest. The two directories stay, empty, and so do the reports and `spec.md` after the merge: the handoff or a
retrospective points at them, and a later session reads them to know where step 3 stands.

When a sub-agent ends on an error and gives no report (the API of the model it runs on refuses an expired login, say),
check and empty its directory as for one that reports, before it starts again. Once the cause is gone (the owner logs in
again), start it again with the same prompt: the report written to `standards-report.md` or `spec-report.md` is the new
start's, and the pull request's body says the first start failed and why.

When the way the change does its work is replaced after a review (not a fix of a finding, another approach), review it
again. Add the decisions to `spec.md` and say there what the second review verifies; keep the first review's reports,
and write the new ones as `standards-report-2.md` and `spec-report-2.md`. Each prompt names its axis's first report, and
each sub-agent says which of its items still hold.

## Both sub-agents

- Work in your own directory, the one your prompt names: build any throwaway repository or worktree there, and change
  nothing outside it, not the other sub-agent's directory, not `spec.md`, not the main checkout's working tree. In the
  main checkout, make no commit and no branch, and neither reset nor switch it. Two commands write under its `.git` and
  are allowed: `git add -N` (it registers a new file, so the diff shows it) and `git worktree add` of a detached
  `origin/main` (below), never with `-b`.
- Name the repository of every git command: `git -C <absolute path> …`, the main checkout's included. Read the change
  with `git -C <main checkout> diff origin/main` (two dots, so the working tree counts). No command relies on a `cd`
  before it: when a `cd` fails, the commands after it run wherever the shell was.
- Never run the whole suite or `scripts/mutate.py`: a run of the checks may be going on in the main checkout. Run single
  test files only, with absolute paths, the main checkout's interpreter and its `scratch/empty-home`, and no bytecode
  written into the main checkout: `PYTHONDONTWRITEBYTECODE=1 HOME=<main checkout>/scratch/empty-home
  <main checkout>/.venv/bin/python -m pytest -p no:cacheprovider <file> -q`.
- To try the old version of a file, `git -C <main checkout> worktree add <your directory>/<name> origin/main`. A
  worktree has no `.venv` and no `scratch/`, so run its tests with the main checkout's interpreter and
  `PYTHONPATH=<worktree>/src`, or the main checkout's own `src/` is imported.
- When you are done, remove what you built in your directory, its throwaway repositories and worktrees
  (`git -C <main checkout> worktree remove <worktree>`), and leave the directory itself in place, empty. Say in your
  report what you could not remove.
- Report in Traditional Chinese with Taiwan usage (the owner reads it): at most 10 items in all, following the groups of
  your section, the hard findings first and then the judgement calls; each item in at most three lines (where, what,
  why), a quotation of the spec or of the hunk being one line; what does not fit goes in one sentence. Code, paths and
  quoted output go in backticks.

## The standards sub-agent

Does the change follow what the repository writes down about how code and documents are written? Sources:
`CODING_STANDARDS.md`, `GLOSSARY.md` and `AGENTS.md`, always; `tests/SEAMS.md` when the change touches a function that
tests patch or read; `docs/CHANGELOG.md` "版本規則" when it adds a row; `docs/agents/` when it edits them.

Report, per file or hunk: (a) each place the change violates a documented standard, citing the file and the rule, as a
hard violation or a judgement call; (b) each smell of the list below that you find, quoting the hunk. A smell is always
a judgement call, and a documented standard overrides the list. Leave out what tooling enforces (ruff, line width, mypy,
control characters).

The smells, a copy of the list in version 1.3.1 of the `code-review` skill (each says what it is, then how to fix it):

- **Mysterious Name**: a function, variable, or type whose name doesn't reveal what it does or holds. → rename it; if no honest name comes, the design's murky.
- **Duplicated Code**: the same logic shape appears in more than one hunk or file in the change. → extract the shared shape, call it from both.
- **Feature Envy**: a method that reaches into another object's data more than its own. → move the method onto the data it envies.
- **Data Clumps**: the same few fields or params keep travelling together (a type wanting to be born). → bundle them into one type, pass that.
- **Primitive Obsession**: a primitive or string standing in for a domain concept that deserves its own type. → give the concept its own small type.
- **Repeated Switches**: the same `switch`/`if`-cascade on the same type recurs across the change. → replace with polymorphism, or one map both sites share.
- **Shotgun Surgery**: one logical change forces scattered edits across many files in the diff. → gather what changes together into one module.
- **Divergent Change**: one file or module is edited for several unrelated reasons. → split so each module changes for one reason.
- **Speculative Generality**: abstraction, parameters, or hooks added for needs the spec doesn't have. → delete it; inline back until a real need shows.
- **Message Chains**: long `a.b().c().d()` navigation the caller shouldn't depend on. → hide the walk behind one method on the first object.
- **Middle Man**: a class or function that mostly just delegates onward. → cut it, call the real target direct.
- **Refused Bequest**: a subclass or implementer that ignores or overrides most of what it inherits. → drop the inheritance, use composition.

## The spec sub-agent

Does the change do what was asked, and no more? The spec is in `spec.md`, at the path the prompt names: the issue,
or the decisions the owner agreed. When `spec.md` holds no spec, say "no spec available" for (a), (b) and (c) below,
and do the checks after them.

Report: (a) what the spec asked for that is missing or partial; (b) what the change does that was not asked for; (c) what
looks done but is wrong. Quote the line of the spec for each.

Besides what the prompt names, always check:

- the change touches only the files it should (`git -C <main checkout> diff origin/main --stat`);
- the change reaches every reader of what it changes (a format, a file, the result of a function), not only those
  the spec names: find the call sites with `git -C <main checkout> grep`, read each, and report one left as it was;
- when the commits already exist, each one passes the tests that cover it alone; and a new test fails against the old code
  (copy the new test file into a worktree of `origin/main` in your directory), unless it tests a module or a script the
  base does not have, or the change edits the credential guard of `tests/conftest.py`, which a test copied alone into
  that worktree runs without, a real tool then acting with the developer's login (`tests/SEAMS.md`, "The credential
  guard"): its mutations show it sensitive instead (`pr-flow.md` step 2);
- every sentence the change writes about what other code does (a docstring, a standard, a CHANGELOG row, a message) is
  true: read that code, not only its docstring, and report a claim that says more than the code does;
- when the change adds or edits a mutation list (`git -C <main checkout> diff origin/main -- tests/mutations/`), each
  mutation it adds or edits has an `old` that occurs once in its file and a `new` that makes the fault its name says:
  read the code, and do not run `scripts/mutate.py`. Where the test that caught it failed is in the run step 3 of
  `pr-flow.md` makes before the review: read it there when the prompt names its output, and report a catch by a test
  other than its `caught_by`, or one that does not fail at the assertion its name gives. Step 4 reads it again, from
  a run of the final code.
