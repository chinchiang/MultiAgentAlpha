# Synthetic model-evaluation outputs (test fixtures only)

These files imitate the native output formats of garak (report JSONL with `eval` rows) and
CyberSecEval (`prompt_injection_stat.json`, `mitre_frr_stat.json`, and the response files `report`
reads beside them: `prompt_injection_judge_responses.json`, `mitre_frr_responses.json`) so that
`scripts/model_eval.py report` and its parsers can be tested without endpoints. Each response file has
as many rows as its stat file counts, every row with text in its response and its judge reply, so a
report built from this directory has no empty response; the yes / no and refusal / accept splits equal
the stat files. The numbers are invented and carry no information about any real model. `report`
refuses to label a report `live` from this directory, and nothing here is ever written to `docs/`.
