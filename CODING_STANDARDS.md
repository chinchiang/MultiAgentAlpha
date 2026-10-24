# Coding standards

The judgement calls a review checks. What a tool checks is not here: lint (`ruff check`), the width of the lines a
change adds (`scripts/line_width.py`), types (mypy) and the tests run in CI and, before a push, in
`scripts/check_local.py`.

## Module docstrings name their terms, their decisions and their purity

A module's docstring names the GLOSSARY.md terms it implements and the ADRs it follows, each ADR by its full path
(`docs/adr/0008-reply-accounting.md`), and says whether the module is pure. A module that is pure apart from one thing
says what that thing is: "Pure, except that settle() records decisions on the consensus rows it is given".

## A docstring says what the code does

Every claim in a docstring or comment holds for the code beside it: what a function returns, counted as the code
counts it ("the consensus rows a decision was recorded on", where the code counts rows, not decisions); which inputs it
skips; in which order it decides. A docstring moved with its code moves verbatim, and one rewritten with its code is
rewritten whole. History belongs in the commit message and the pull request; a known gap that a test pins is named by
pointing at the follow-up.

## One concept, one wording

A concept the glossary names is written with the glossary's word everywhere: code, docstrings, comments, tests, docs
and the other glossary entries. A change that adds or renames a term rewords the old phrasing in the files it touches,
and the `_Avoid_` lists name the words to look for. Persisted and public identifiers (audit counter names, incomplete
reason codes, report and workbench keys) keep their names; the pull request says which ones now differ from the
glossary.

## An ADR is amended, never rewritten

An ADR's decision text stays as it was decided. A later change adds a dated paragraph, "Amended YYYY-MM-DD: …", in the
Consequences when the ADR has them, else after the decision and before the considered options; a later ADR that amends
one says so in a line of its own ("Amended by ADR 0007 (docs/adr/0007-review-status-and-gate.md): …"). The amendment
says what changed, what of the original decision still stands, and which of its sentences the change made stale and
what holds instead; those sentences are left as they were decided.

## A CHANGELOG row records one version

`docs/CHANGELOG.md` has one row per version, newest first, in Traditional Chinese with Taiwan usage, under its five
columns (日期, 版本, 變更摘要, 變更者, 查證狀態) and its version rules ("## 版本規則"). The summary opens with the kind
of change and the ADR it follows, numbers its parts (1), (2), …, says which tests were added or changed, whether the
workbench demo was recaptured, and ends with whether the report body changed ("報告正文未變"). 查證狀態 carries the
counts `scripts/check_citations.py` gives; when the report body did not change, the evidence and word counts repeat the
previous row's. `mara.__version__` equals the newest row's version (`tests/test_version.py`). A pure refactor adds no
row.

## A doc names no version Dependabot bumps

A GitHub Action that `.github/dependabot.yml` keeps up to date is pinned by commit SHA with a `# vX.Y.Z` comment, and
Dependabot rewrites both in each bump; it cannot edit docs. So a living doc that names such an action names no
version: it says the action is pinned by SHA and points at the workflows' `# vX.Y.Z` comments
(`docs/tools-provenance.md`'s Code Scanning table). A dated record (`docs/actions-inventory-<date>.md` and the like)
names the version of its date. The tools in `tools/versions.lock` are relocked by hand, not by Dependabot, and their
docs keep naming their versions.

## A behaviour change commits its mutation list

The mutations a behaviour change's tests were checked against (`scripts/mutate.py`) are committed with the change, as
`tests/mutations/<name>.yaml`. A change that makes a committed list stale re-aligns each `old` to the code in the same
commit, or drops a mutation that no longer means anything; `tests/test_mutation_lists.py` goes red on a list that does
not load. A re-aligned mutation still makes the fault its name says: a review compares each re-aligned `old`/`new` with
the list's previous version, and a mutation that now makes another fault is renamed or re-aligned again.

## Lines are wrapped by hand

`ruff format` is not part of the checks. Code is wrapped by hand within 150 columns, the way the code around it is; a
change keeps the wrapping style of the file it edits, and a new file may follow either. The width is checked: ruff
checks src/, and `scripts/line_width.py` the lines a change adds to any Python file, so the wider lines already in
tests/ and scripts/ stay until a change rewrites them.
