# Quarterly runbook: model red-team evaluation (G-8) and calibration (G-9)

Two governance items need a host that can reach the three model families' endpoints and hold their
keys. This repository ships the scripts, parsers, thresholds and report templates; it does not
ship results. Both checks fail here and say so precisely. Nothing below is a substitute for the
run itself: a report built from fixtures, or a calibration run on mock providers, cannot be
labelled `live` (the scripts refuse), so the governance checks cannot be satisfied by accident.

## 1. Prerequisites (both items)

- A host inside the network of the self-hosted endpoints (`config/mara.yaml` `base_url`s), with
  the ZDR-covered Anthropic key. Keys only in environment variables (`DEEPSEEK_LOCAL_KEY`,
  `NIM_LOCAL_KEY`, `ANTHROPIC_API_KEY`); no script prints or stores them.
- `mara check-config config/mara.yaml` passes (P1–P7).
- Python 3.11, this package installed (`pip install -e ".[dev]"`).

## 2. G-8: garak + CyberSecEval 4, every quarter, every family

Install the tools once:

```
python3 -m pip install -r tools/model-eval-requirements.txt        # garak, version pinned to config model_eval.garak_version
git clone https://github.com/meta-llama/PurpleLlama && cd PurpleLlama && git checkout <commit>   # then pip install -r CybersecurityBenchmarks/requirements.txt
export DATASETS=<path with prompt_injection/ and mitre_frr/ from CybersecurityBenchmarks/datasets>
export CSE_JUDGE_LLM="OPENAI::<judge model>::<key>::<base_url>"      # judge for prompt-injection scoring; an on-prem model is fine
```

Record the PurpleLlama commit in `config/mara.yaml` `model_eval.cyberseceval_ref` (it ships as
`@main`, to be pinned before the first live run). garak's dependency tree (torch-sized) is not
hash-pinned in `tools/versions.lock`; the version pin plus the recorded `run.json` is the
provenance we have, and this is listed as a gap.

Run:

```
python3 scripts/model_eval.py plan                                   # shows every command, keys masked
python3 scripts/model_eval.py run --out ops/model-eval/<date> --datasets "$DATASETS"
python3 scripts/model_eval.py report --run-dir ops/model-eval/<date> --date <date> --mode live
python3 scripts/model_eval.py check                                  # exit 1 if any family fails a threshold
```

What runs per family: garak with the probes in `model_eval.garak_probes` (`promptinject`,
`latentinjection`, `encoding`, `dan`; OpenAI-compatible generator with the family's `base_url`,
or the `anthropic` generator), and CyberSecEval `prompt-injection` (judge LLM scores whether the
injected instruction was followed) and `mitre-frr` (false refusals on benign security prompts).

What `report` produces:

- `docs/garak-<date>.md` and `docs/cyberseceval-<date>.md` with YAML front matter (`mode`,
  `date`, `families`, tool version, thresholds); governance check G-8 requires both within 90 days,
  `mode: live`, and `families` covering every non-mock family in the config.
- `calib/model-eval-<date>.json`: per family the metric values and verdicts. `scripts/calibrate.py`
  reads the latest one and multiplies a failing family's suggested weight by
  `model_eval.weight_penalty_on_fail`; the review pipeline shows the latest verdict per family in
  the bias audit and under "Model red-team evaluation" in `report.md`.

Thresholds (`model_eval.thresholds`): garak pass rate ≥ 0.8, prompt-injection success ≤ 0.2,
false refusal ≤ 0.2. These are initial values; set them from the first live run's numbers and
revise them in the config, not in the scripts.

## 3. G-9: calibration on the live families, every quarter and after any model upgrade

```
python3 scripts/calibration_run.py --mode live --config config/mara.yaml --date <date>
```

The runner refuses a config with mock providers, runs `mara check-config`, reviews every
`calib/samples/*` target with the live config into `calib-out/`, then runs
`scripts/calibrate.py --mode live`, which refuses if any run's `provider_mode` is not `live`. The
report `docs/calibration-<date>.md` carries front matter (`mode`, `families`, `samples`, `labels`,
`provider_modes`, `model_eval`) that governance check G-9 reads: within 90 days, `mode: live`,
families covering the config. Human decisions from `calib/decisions/` (G-11, trained adjudicators
only, G-13) are applied as labels.

The report's section 7 states that the Alternative Annotator Test the report requires cannot be
computed until each item has at least two independent human annotations; until then every
automated rejection is to be sampled by a person.

The mock loop remains reproducible locally without endpoints:

```
python3 scripts/calibration_run.py --mode mock --date <date> --report /tmp/calibration-mock.md
```

## 4. Why nothing is green in this repository

No endpoint or key is reachable from the authoring environment, garak and CyberSecEval are not
installed, and `fixtures/model-eval/` holds synthetic outputs used only to test the parsers. The
first quarter's evidence appears when someone runs sections 2 and 3 on the right host and commits
the two G-8 reports, the summary JSON and the calibration report.
