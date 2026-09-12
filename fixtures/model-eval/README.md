# Synthetic model-evaluation outputs (test fixtures only)

These files imitate the native output formats of garak (report JSONL with `eval` rows) and
CyberSecEval (`prompt_injection_stat.json`, `mitre_frr_stat.json`) so that
`scripts/model_eval.py report` and its parsers can be tested without endpoints. The numbers are
invented and carry no information about any real model. `report` refuses to label a report `live`
from this directory, and nothing here is ever written to `docs/`.
