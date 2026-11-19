# From a branch to a merged pull request

A change that becomes a pull request goes through these steps in order. Each ends on a condition you can check.

1. **Branch from the latest main.** `git fetch`, then `git switch -c <name> origin/main`. Done when
   `git log origin/main..HEAD` is empty.
2. **Red first.** Write the failing test at a seam the owner has confirmed (`mattpocock-skills:tdd`). Done when it fails
   for the reason you meant: read the failure message, not only the exit code. A change of documents or tests only has
   no red stage: say so in the body, and say which assertions you proved sensitive some other way (a test that fails
   on a made-up bad input, a hand-made bad copy of the file).
   A test written after the fix, or green the moment it is written, is shown red on the base's code in a worktree of
   `origin/main` under `scratch/` (`git worktree add scratch/<dir> origin/main`), with the new and changed test files
   copied in and the main checkout's tools linked in (`ln -s "$PWD/.mara-tools" scratch/<dir>/.mara-tools`, from the
   main checkout), run with the main checkout's interpreter, `PYTHONPATH=<worktree>/src` and `HOME=scratch/empty-home`,
   and the worktree removed after (`git worktree remove --force`, which removes the link and leaves the main checkout's
   `.mara-tools` as it is). Git ignores `.mara-tools`, so a worktree has none, and a test that needs a tool looks for it
   below the repository it sits in and skips: a run that skips more than the same test files skip in the main checkout
   has not shown those tests red. Neither `git stash` (its stack is shared by every
   worktree of the checkout) nor the base's files written over the main checkout's (a run of the checks may be reading
   them). A test that fails without reaching the part it is about is not red for the reason you meant: a `DID NOT RAISE`
   because an `or` with a value on its left never reads the right (`hint or name`), say. Change the test until it
   reaches that part. A test of a module or a script the base does not have fails there on its import or on the
   missing file (`ModuleNotFoundError`, `No such file or directory`), which shows nothing of what it checks: such a
   test is shown sensitive by its mutations, each caught by it at the assertion its name gives (step 3), and the body
   says so.
3. **Make it green, review it, then commit it.** Green in the working tree, nothing committed yet: the code, its
   `tests/mutations/<name>.yaml` and `tests/SEAMS.md`, and, when the change takes a version, the version, its CHANGELOG
   row and the demo page. Run `scripts/check_local.py --only worktree` beside the tests (seconds): ruff; the width of
   the lines the working tree adds to Python files (`lines-worktree`) and the control characters of those it adds to any
   text file (`chars-worktree`), over the merge base with `--base` (origin/main by default), committed or not, untracked
   files included and those git ignores left out; and `pytest-worktree`, which checks that every mutation list loads
   and every pointer of `tests/SEAMS.md` names something that is there. A finding costs an edit now, and a rebuild of
   the commits at step 4. mypy, semgrep, the whole suite and gitleaks wait for step 4.
   Then run each mutation list the change adds or edits once, `scripts/mutate.py <list> --focused-only` without
   `AWS_PROFILE` and `GEMINI_API_KEY`, one after the other and after `--only worktree` has ended (a mutation edits the
   files the checks read), and read each `CAUGHT` line as step 4 says: where it failed, and its mark. A `caught_by` that
   another test beats, or a name that is not the fault its `new` makes, is fixed now, before the review, and not by a
   rebuild after step 4. The lists the change touches but does not add or edit wait for step 4. A list refused for the
   Python it needs (`needs Python <specifier>`, exit 2) runs with an interpreter it takes, as step 4 says.
   Review that tree before the first commit, so a finding costs an edit and not a rebuild: `mattpocock-skills:code-review`
   with `origin/main` as the fixed point, where the sub-agents read `git -C <main checkout> diff origin/main` (two
   dots: the skill's three-dot form reads commits only; run `git add -N <new file>` first, or the diff leaves new files
   out), the two axes reported apart. What the prompts say every time is in `docs/agents/self-review.md`. A review you
   did not run is said so in the body.
   Then commit, each commit passing. Product code in its own commit; its mutation list and `tests/SEAMS.md` beside it.
   The version, its CHANGELOG row and the demo page go in **the version commit** (`GLOSSARY.md`), the branch's last
   commit, which may hold nothing else and which `scripts/version_commit.py` makes (its docstring gives its arguments
   and what it refuses): `scripts/renumber.py` renumbers only when the rebase stops with no commit left to apply, so a
   version commit in the middle sends you to the hand-made fix. The counts of tests and mutations its row states are
   what `scripts/change_counts.py --base origin/main` prints once the change is done (`--worktree` before the commits),
   its `changed` split by hand into what the change did (its docstring says why).
   To change a commit you have made without `rebase -i` or `--amend`, start from
   a clean working tree (`git status --short` prints nothing): a fix you have not committed is committed on the branch
   first, as a commit of its own (`git commit -am <message>`, after `git add`, or the `git add -N` above, for a new
   file). Otherwise, after the rename, `git switch` refuses a fix to a file of the branch and leaves you on
   `<name>-old`, and carries any other change to the rebuilt branch, where the check below does not show it. Then
   rename the branch (`git branch -m <name> <name>-old`), cut `<name>` again from the base the old branch was cut from
   (`git switch -c <name> $(git merge-base <name>-old origin/main)`: a later `origin/main` waits for step 6's rebase),
   and rebuild the commits one by one with `git checkout <name>-old -- <files>`, which takes each file from the old
   branch's last commit, the fix included (a file the old branch deleted is not carried: `git rm` it). Check that
   `git diff <name>-old..HEAD` prints nothing, so the rebuilt branch holds what the old one did; then delete the old
   one (`git branch -D <name>-old`). A branch already pushed takes `git push --force-with-lease origin <name>`.
   To move work you have not committed to a branch cut again from `origin/main` (the branch was cut from a stale base,
   say), carry it in a patch, as step 2 keeps away from the stash, whose stack every worktree and session shares. With
   every new file of the change registered with `git add -N`, record the change
   (`git diff HEAD --binary > scratch/move.patch`) and check that the patch holds all of it
   (`git apply -R --check scratch/move.patch` exits 0) before anything is discarded: `git reset --hard -q` discards the
   work, and deletes a file registered with `git add -N` from the disk too, so from there the patch is its only copy. Cut
   the branch again (`git fetch`, `git switch -C <name> origin/main`: `-C` resets `<name>`, so it must hold no commit of
   yours), bring the work back (`git apply --3way scratch/move.patch`), unregister what it staged (`git reset -q`) and
   register the new files again (`git add -N`). Check that `git diff HEAD --binary | git patch-id --stable` prints what
   `git patch-id --stable < scratch/move.patch` prints; the id leaves whitespace out, and differs when `origin/main`
   changed lines beside the change: read `git diff HEAD` against the patch then. An apply that fails exits 1:
   - a file both changed is marked `UU`, and a new file `origin/main` also added with other content `AA`, each with
     conflict markers; one it added with the same content applies, and shows no change;
   - a file of the change that `origin/main` deleted stops the whole apply before any file is written
     (`error: <file>: does not exist in index`). Apply the rest
     (`git apply --3way --exclude=<file> scratch/move.patch`). To keep the file, write its old version back from the
     blob the `index <old>..` line of its part of the patch names (`git show <old> > <file>`, `git add <file>`) and
     apply that part (`git apply --3way --include=<file> scratch/move.patch`); it is then one of the new files.

   Resolve them, `git reset -q`, `git add -N` each new file, and read `git diff HEAD` against the patch, new files
   included.
   Done when `scratch/self-review-<issue>/` holds `standards-report.md` and `spec-report.md`, and
   `standards-report-2.md` and `spec-report-2.md` after a second review (`docs/agents/self-review.md`), or the body says
   the review was not run; each mutation of the lists the change adds or edits was caught by its `caught_by` at the
   assertion its name gives in the run above; every finding of the review is fixed or answered in the body; and the
   work is committed.
4. **Run the checks, one after the other.** `scripts/check_local.py` as `AGENTS.md` gives it; then
   `scripts/mutate.py --base origin/main`, without `AWS_PROFILE` and `GEMINI_API_KEY`. It runs, focused and one after
   the other, each mutation list the change (committed or not, untracked files included) touches: the list itself, the
   file of one of its mutations, or one of its focused test files (`--lists-for origin/main` prints them and runs
   nothing). It ends on a `summary`: each list's last line, then the marked catches, the catches with no `at:` and
   the `LEFT` lines of all of them. Re-run one list alone with `scripts/mutate.py <list> --focused-only`. A list whose
   `requires-python` this interpreter does not take is a `SKIP` line of the summary: run it alone with an interpreter
   it takes (`>=3.13`: a venv of `tools/dev-requirements-py313.txt`, as CI's 3.13 job installs). A mutation
   edits `src/`, so never run two of these at once. Done when every check `AGENTS.md` lists is `ok` and every mutation
   of those lists is caught for the reason its name says.
   Of every other mutation of those lists, read each marked catch and each `LEFT` line the summary gathers: a test the
   change adds or edits can catch an old mutation before its `caught_by` does.
   For the mutations the change adds or edits, read where the test that caught each failed (third paragraph of "A
   behaviour change commits its mutation list" in `CODING_STANDARDS.md`): it fails at the assertion its name gives, not
   at a `TypeError`, an import error or an earlier assertion. `mutate.py` prints it on each `CAUGHT` line, `at:` and the
   source line, and `results.json` holds it as `at` and `error`. Open the log its entry lists under `logs` only for a
   marked catch (`GLOSSARY.md`), one with no `at:`, or one whose line is not the assertion of the mutation's name. When
   to write an `error:` is in the same paragraph of `CODING_STANDARDS.md`. Every mutation names the test meant to catch
   it (`caught_by`; `tests/test_mutation_lists.py` fails on one that does not), so that a catch by another is marked: for
   a mutation you add, the test you mean it for, not what a run happens to report. When a mutation breaks a check that
   several cases of a parametrized test hold, name the test without its parameters: pytest stops at the first case that
   fails, the first of those cases in its parameters, and naming another marks the catch `(expected …)`. A `LEFT <path>`
   line names a path git status lists after a run that it did not before: once you know the run left it, and not someone
   working in the checkout meanwhile, remove a file it added (`git status` shows `??`) and `git restore` one it changed
   or deleted.
   A fix made after this step goes into the commit it belongs to (rebuild as in step 3, so the version commit stays
   last) and this step runs again on the branch head; the numbers in the body are those of that run, and a fix the
   sub-agents did not see is said so in the body.
5. **Write the body** to `scratch/pr-body-<name>.md` (`mattpocock-skills:pr`), in English, ending with the attribution
   line; search it for control characters. Show what the change does before and after, and what you did not run.
   What it says the change does, and so do the commit messages and the CHANGELOG row, is against `origin/main`, not
   against a version of your own that a review saw: a fault only that version had is not one the change fixes. A fact
   you verified names the commit it was verified on, and facts verified on different commits are written apart (a fault
   reproduced on the commit the issue was triaged on, and the new tests red on the base the branch was cut from). What
   you did not run includes the code no job of CI runs: the `win32` branches of the tests' stand-in tools, since CI runs
   no Windows job.
6. **Push, open the pull request, watch it.** `git fetch` first: if `origin/main` moved, rebase; if the version was
   taken, run `scripts/renumber.py`. `main` is `strict`: a branch that lacks the latest `origin/main` cannot merge, and
   `--admin` does not get round that. Then `.venv/bin/python scripts/pr_checks.py <n>` in the background. It waits until
   at least one check is reported and none is pending, printing nothing on stdout until then, so what it prints is
   final:
   - each check's state, and a `LOG` line for a job whose log cannot be read;
   - each tool's result line from the job logs (the script's docstring names the tools): `ok`, `NOT` with the step to
     read, or `MISS` when the logs hold fewer of the tool's steps than CI runs;
   - each pytest job's skipped tests, in full where no missing tool explains them;
   - each workflow a pull request triggers that did not run, and the active rulesets requiring one of its checks.

   Done when it exits 0. On exit 1, read each line it marks: the step a `NOT` names, the job's log for a `MISS` or a
   `LOG`, a failed check's job, and for a required check that did not run, why it did not. When it stops because the
   head moved, run it again. Exit 2 is gh failing: read its error.
   When semgrep's accepted count differs from `main`'s or from your local run, find out why before the body states a
   number. A rule that timed out on a file drops that rule's findings there: `semgrep_ci.py`'s clean line ends with how
   many timeouts there were and on which files, and a line above it names each timeout's rule and file. When no timeout
   explains the difference, download the job's SARIF (`gh run download <run> -n l0-sarif`) and compare its
   `semgrep.sarif`, the scan of this repository with its accepted findings, finding by finding (rule, file, line) with
   the other: `fixture-semgrep.sarif` beside it is the scan of the seeded fixture.
7. **Give the owner the merge command**, with the full 40-character head SHA, and do not run it. `git fetch` once more
   and check that `origin/main` has not moved since step 6; if it has, rebase and push again, because the branch
   would no longer be up to date and CI runs again. The ruleset R1 `update` rule keeps the state `BLOCKED` even when the
   checks pass, which is why the command has `--admin`:
   `! gh pr merge <n> --repo chinchiang/MultiAgentAlpha --merge --admin --delete-branch --match-head-commit <sha>`.
   A `HTTP 404: Reference does not exist` from `--delete-branch` only means the remote branch was already deleted; it
   is not a failure.
8. **After the owner says it is merged, look at GitHub before anything else.** `gh pr view <n> --json state,mergeCommit`
   says `MERGED`, and `origin/main` carries the new version. When it does not, find the cause: a command the owner sends
   with a leading `!` is echoed into the conversation as a `<bash-input>` block, so no block means it did not run; ask
   the owner to send it again, and look once per message. When it does, switch to main, fast-forward, delete the
   branch once `git merge-base --is-ancestor` says it is in main, and update the handoff.

Versions are fixed at merge time, not when the branch is cut. Whether a change takes a version, and which, is in
`docs/CHANGELOG.md`, "版本規則". A change that takes one bumps `mara.__version__`, adds its row and rebuilds the demo page
with `scripts/build_workbench_demo.py`, all in the version commit, the branch's last (step 3).
