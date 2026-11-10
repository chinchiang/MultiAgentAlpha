# MultiAgentAlpha

- Before writing or reviewing code or docs: read `CODING_STANDARDS.md`, the judgement calls a review checks.
- Before every push: run `HOME=$PWD/scratch/empty-home .venv/bin/python scripts/check_local.py` (CI has no `~/.mara`).
  It runs seven of the checks a pull request's CI runs; the script's docstring names them. Add `--only osv` (network)
  when a change touches `tools/*-requirements.txt` or `tools/osv-*.toml`, or when L0 fails on osv.
- Before moving, renaming or re-signing a function in `src/mara` or `scripts/`: read `tests/SEAMS.md`, what the tests
  patch or read and the shape each relies on.
- Before starting a change you will push: read `docs/agents/pr-flow.md`, the steps from a branch to a merged pull request.
- When naming anything in code, docs or tests: use the terms of `GLOSSARY.md`; a new term is added to it.
- Commit messages, pull request bodies, handoffs, architecture reports and other files a later step needs go in
  `scratch/`, not `/tmp` (which is emptied). It is excluded from git by `.git/info/exclude`; on a fresh clone add
  `/scratch/` there first.

## Agent skills

### Issue tracker

GitHub Issues (`chinchiang/MultiAgentAlpha`, via `gh`). Before creating, reading or commenting on an issue: read
`docs/agents/issue-tracker.md`.

### Triage labels

Before labelling or triaging an issue: read `docs/agents/triage-labels.md`, which maps the five roles to this tracker's
labels.

### Domain docs

Single-context: `GLOSSARY.md` and `docs/adr/` at the repo root. Before exploring an area: read `docs/agents/domain.md`.
