# From a branch to a merged pull request

A change that becomes a pull request goes through these steps in order. Each ends on a condition you can check.

1. **Branch from the latest main.** `git fetch`, then `git switch -c <name> origin/main`. Done when
   `git log origin/main..HEAD` is empty.
2. **Red first.** Write the failing test at a seam the owner has confirmed (`mattpocock-skills:tdd`). Done when it fails
   for the reason you meant: read the failure message, not only the exit code. A change of documents or tests only has
   no red stage: say so in the body, and say which assertions you proved sensitive some other way (a test that fails
   on a made-up bad input, a hand-made bad copy of the file).
3. **Green, in commits that each pass.** Product code in its own commit; its `tests/mutations/<name>.yaml` and
   `tests/SEAMS.md` beside the code they describe. The version, its CHANGELOG row and the demo page go in **the last
   commit** of the branch (it may hold nothing else): `scripts/renumber.py` renumbers only when the rebase stops with no
   commit left to apply, so a version commit in the middle sends you to the hand-made fix. To change an earlier commit
   without `rebase -i` or `--amend`: rename the branch (`git branch -m <name> <name>-old`), cut `<name>` again from
   `origin/main`, and rebuild the commits one by one with `git checkout <name>-old -- <files>` (a file the old branch
   deleted is not carried: `git rm` it). Done when `git diff <name>-old..HEAD` is exactly the changes you meant; then
   delete `<name>-old`. A branch already pushed takes `git push --force-with-lease`.
4. **Run the checks, one after the other.** `scripts/check_local.py` as `AGENTS.md` gives it, and `scripts/mutate.py
   tests/mutations/<name>.yaml --focused-only` on each file the change touches, without `AWS_PROFILE` and `GEMINI_API_KEY`. A mutation edits `src/`,
   so never run the two at once. Done when every check `AGENTS.md` lists is `ok` and every mutation is caught.
5. **Self-review.** `mattpocock-skills:code-review` against `origin/main`, the two axes reported apart. Done when every
   finding is fixed or answered in the body. A review you did not run is said so in the body.
   A fix made after the review goes into the commit it belongs to (rebuild as in step 3, so the version commit stays
   last), and step 4 runs again on the branch head; the numbers in the body (step 6) are those of that run.
6. **Write the body** to `scratch/pr-body-<name>.md` (`mattpocock-skills:pr`), in English, ending with the attribution
   line; search it for control characters. Show what the change does before and after, and what you did not run.
7. **Push, open the pull request, watch it.** `git fetch` first: if `origin/main` moved, rebase; if the version was
   taken, run `scripts/renumber.py`. `main` is `strict`: a branch that lacks the latest `origin/main` cannot merge, and
   `--admin` does not get round that. Then `gh pr checks <n> --watch` in the background. Done when every required check
   has a result you have read, in the logs where the colour is not enough (a skipped test, a scanner's own verdict).
8. **Give the owner the merge command**, with the full 40-character head SHA, and do not run it. `git fetch` once more
   and check that `origin/main` has not moved since step 7; if it has, rebase and push again, because the branch
   would no longer be up to date and CI runs again. The ruleset R1 `update` rule keeps the state `BLOCKED` even when the
   checks pass, which is why the command has `--admin`:
   `! gh pr merge <n> --repo chinchiang/MultiAgentAlpha --merge --admin --delete-branch --match-head-commit <sha>`.
   A `HTTP 404: Reference does not exist` from `--delete-branch` only means the remote branch was already deleted; it
   is not a failure.
9. **After the owner says it is merged, look at GitHub before anything else.** `gh pr view <n> --json state,mergeCommit`
   says `MERGED`, and `origin/main` carries the new version. When it does not, find the cause: a command the owner sends
   with a leading `!` is echoed into the conversation as a `<bash-input>` block, so no block means it did not run; ask
   the owner to send it again, and look once per message. When it does, switch to main, fast-forward, delete the
   branch once `git merge-base --is-ancestor` says it is in main, and update the handoff.

Versions are fixed at merge time, not when the branch is cut. A change of tests, documents, the text of an old row, or
a pure refactor takes no new version and no CHANGELOG row. A fix to `scripts/` or product code bumps the patch number,
adds one row, and rebuilds the demo page with `scripts/build_workbench_demo.py`. The rules in full: `docs/CHANGELOG.md`,
"版本規則".
