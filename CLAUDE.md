# MultiAgentAlpha

- `CODING_STANDARDS.md`: the judgement calls a review checks (module docstrings, what a docstring may claim, one
  wording per concept, ADR amendments, CHANGELOG rows, line wrapping). Read it before writing or reviewing code or docs.
- `scripts/check_local.py`: four of the checks a pull request's CI runs (ruff, mypy, the whole suite, gitleaks), each
  output kept under `out/check-local/`. Run `.venv/bin/python scripts/check_local.py` before every push.
- `GLOSSARY.md`: the domain's words, and this repository's CONTEXT.md. Name things in code, docs and tests with its
  terms; a new term is added to it.
