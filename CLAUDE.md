# MultiAgentAlpha

- `CODING_STANDARDS.md`: the judgement calls a review checks (module docstrings, what a docstring may claim, one
  wording per concept, ADR amendments, CHANGELOG rows, line wrapping). Read it before writing or reviewing code or docs.
- `scripts/check_local.py`: five of the checks a pull request's CI runs (ruff, line width, mypy, the whole suite,
  gitleaks), each output kept under `out/check-local/`. Run `.venv/bin/python scripts/check_local.py` before every push.
- `tests/SEAMS.md`: what the tests patch or read in the pipeline, the agents and the workbench, and the shape each
  relies on. Read it before moving, renaming or re-signing a function there.
- `GLOSSARY.md`: the domain's words, and this repository's CONTEXT.md. Name things in code, docs and tests with its
  terms; a new term is added to it.
