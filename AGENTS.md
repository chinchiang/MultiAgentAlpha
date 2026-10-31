# MultiAgentAlpha

- `CODING_STANDARDS.md`: the judgement calls a review checks (module docstrings, what a docstring may claim, one
  wording per concept, ADR amendments, CHANGELOG rows, line wrapping). Read it before writing or reviewing code or docs.
- `scripts/check_local.py`: six of the checks a pull request's CI runs (ruff, line width, mypy, semgrep, the whole
  suite, gitleaks), each output kept under `out/check-local/`. Run `.venv/bin/python scripts/check_local.py` before
  every push. Run it with `--only osv` too (L0's three osv-scanner scans, over the network) when a change touches
  `tools/*-requirements.txt` or `tools/osv-*.toml`, or when L0 fails on osv.
- `tests/SEAMS.md`: what the tests patch or read in the pipeline, the agents and the workbench, and the shape each
  relies on. Read it before moving, renaming or re-signing a function there.
- `GLOSSARY.md`: the domain's words, and this repository's CONTEXT.md. Name things in code, docs and tests with its
  terms; a new term is added to it.

## Agent skills

### Issue tracker

GitHub Issues (`chinchiang/MultiAgentAlpha` via `gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

Default five canonical triage labels (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`,
`wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context (`GLOSSARY.md` and `docs/adr/` at the repo root). See `docs/agents/domain.md`.
