# From a branch to a merged pull request

A change that becomes a pull request goes through these steps in order. Each ends on a condition you can check.

1. **Branch from the latest main.** `git fetch`, then `git switch -c <name> origin/main`. Done when
   `git log origin/main..HEAD` is empty.
2. **Red first.** Write the failing test at a seam the owner has confirmed (`mattpocock-skills:tdd`). Done when it fails
   for the reason you meant: read the failure message, not only the exit code.
3. **Green, in commits that each pass.** Product code in its own commit; a mutation list and `tests/SEAMS.md` beside the
   code they describe.
4. **Run the checks, one after the other.** `scripts/check_local.py` as `AGENTS.md` gives it, and `scripts/mutate.py <list>
   --focused-only` on each list the change touches, without `AWS_PROFILE` and `GEMINI_API_KEY`. A mutation edits `src/`,
   so never run the two at once. Done when all seven checks are `ok` and every mutation is caught.
5. **Self-review.** `mattpocock-skills:code-review` against `origin/main`, the two axes reported apart. Done when every
   finding is fixed or answered in the body. A review you did not run is said so in the body.
6. **Write the body** to `scratch/pr-body-<name>.md` (`mattpocock-skills:pr`), in English, ending with the attribution
   line; search it for control characters. Show what the change does before and after, and what you did not run.
7. **Push, open the pull request, watch it.** `git fetch` first: if `origin/main` moved, rebase; if the version was
   taken, run `scripts/renumber.py`. Then `gh pr checks <n> --watch` in the background. Done when every required check
   has a result you have read, in the logs where the colour is not enough (a skipped test, a scanner's own verdict).
8. **Give the owner the merge command**, with the full 40-character head SHA, and do not run it:
   `! gh pr merge <n> --repo chinchiang/MultiAgentAlpha --merge --admin --delete-branch --match-head-commit <sha>`.
9. **After the owner says it is merged, look at GitHub before anything else.** `gh pr view <n> --json state,mergeCommit`
   says `MERGED`, and `origin/main` carries the new version: a command pasted too early often has not taken effect. Then
   switch to main, fast-forward, delete the branch once `git merge-base --is-ancestor` says it is in main, and update the
   handoff.

Versions and CHANGELOG rows: `docs/CHANGELOG.md`, "版本規則".
