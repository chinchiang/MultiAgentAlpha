# Self-review of a change

Step 3 of `docs/agents/pr-flow.md` has a change reviewed in the working tree before its first commit. Two sub-agents
read it in parallel, one for each axis, and this document is what they follow, so the prompt that starts them stays
short. They are not MARA's reviewers (`GLOSSARY.md`, "Reviewer round"): they review this repository's own change, not a
target.

## Starting them

Each prompt begins: "Read `docs/agents/self-review.md`, the section "Both sub-agents" and the one for your axis, and
follow them." What follows is only what belongs to this change: for the standards sub-agent, which sources below apply
and what to look at first; for the spec sub-agent, the spec (or the decisions that were agreed) and what to verify. Start
both together, in the foreground, and report the two results apart.

## Both sub-agents

- Change no file of the working tree and make no commit. Two commands write under `.git` and are allowed: `git add -N`
  (it registers a new file, so the diff shows it) and `git worktree` (below). Read the change with `git diff origin/main`
  (two dots, so the working tree counts).
- Never run the whole suite or `scripts/mutate.py`: a run of the checks may be going on in the main checkout. Run single
  test files only, with the main checkout's interpreter and its `scratch/empty-home`:
  `HOME=<main checkout>/scratch/empty-home <main checkout>/.venv/bin/python -m pytest -p no:cacheprovider <file> -q`.
- To try the old version of a file, `git worktree add` a copy under `scratch/` and remove it afterwards
  (`git worktree remove`). A worktree has no `.venv` and no `scratch/`, so run its tests with the main checkout's
  interpreter and `PYTHONPATH=<worktree>/src`, or the main checkout's own `src/` is imported.
- Report in Traditional Chinese with Taiwan usage (the owner reads it), within 400 words. When the findings do not fit,
  give the hard ones first, then the judgement calls, and the rest in one sentence. Code, paths and quoted output go in
  backticks.

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

Does the change do what was asked, and no more? The spec is the issue, a path the prompt names, or the decisions the
owner agreed; the prompt quotes them, for the sub-agent has no other access to them. With no spec, say "no spec available"
for (a), (b) and (c) below, and do the checks after them.

Report: (a) what the spec asked for that is missing or partial; (b) what the change does that was not asked for; (c) what
looks done but is wrong. Quote the line of the spec for each.

Besides what the prompt names, always check:

- the change touches only the files it should (`git diff origin/main --stat`);
- when the commits already exist, each one passes the tests that cover it alone; and a new test fails against the old code
  (copy the new test file into a worktree of `origin/main`);
- every sentence the change writes about what other code does (a docstring, a standard, a CHANGELOG row, a message) is
  true: read that code, not only its docstring, and report a claim that says more than the code does.
