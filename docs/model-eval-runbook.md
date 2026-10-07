# Quarterly runbook: model red-team evaluation (G-8) and calibration (G-9)

Two governance items need a host that can reach the three model families' endpoints and hold their
keys. This repository ships the scripts, parsers, thresholds and report templates; it does not
ship results. Both checks fail here and say so precisely. Nothing below is a substitute for the
run itself: a report built from fixtures, or a calibration run on mock providers, cannot be
labelled `live` (the scripts refuse), so the governance checks cannot be satisfied by accident.

## 1. Prerequisites (both items)

- A host inside the network of the self-hosted endpoints (`config/mara.yaml` `base_url`s), with
  AWS credentials for Bedrock (`AWS_PROFILE`, e.g. after `aws sso login`) and the Gemini key. Keys
  only in environment variables (`GLM_LOCAL_KEY`, `GEMINI_API_KEY`; `DEEPSEEK_LOCAL_KEY` for the
  standbys); no script prints or stores them. The GLM endpoint is signed by the IEC internal CA:
  garak and CyberSecEval do not read `ca_bundle`, so export `SSL_CERT_FILE` pointing at a bundle
  that holds both the public roots and the IEC chain for their runs.
- G-8 gap: `scripts/model_eval.py` has no garak or CyberSecEval wrapper for Claude on Bedrock or the
  Gemini API yet. `plan` lists both families as skipped, `run` evaluates the rest and exits 1, and
  the live report refuses to cover the missing families, so G-8 stays red until a wrapper exists.
- `mara check-config config/mara.yaml` passes (P1–P8).
- Python 3.11 on Linux x86_64, this package installed from the hash-pinned closure
  (`pip install --require-hashes --only-binary=:all: -r tools/dev-requirements.txt && pip install --require-hashes --only-binary=:all: -r tools/build-requirements.txt && pip install --no-deps --no-build-isolation -e .`).

## 2. G-8: garak + CyberSecEval 4, every quarter, every family

Install the tools once:

```
python3 -m pip install --require-hashes --only-binary=:all: -r tools/build-requirements.txt
python3 -m pip install --require-hashes --no-build-isolation -r tools/model-eval-requirements.txt   # garak 0.17.0 and its whole closure, every file's SHA-256 pinned
git clone https://github.com/meta-llama/PurpleLlama && cd PurpleLlama && git checkout 4be64c3a24442b51c76175e6ec67722cc3f5fe38   # then pip install -r CybersecurityBenchmarks/requirements.txt
export DATASETS=<path with prompt_injection/ and mitre_frr/ from CybersecurityBenchmarks/datasets>
export CSE_JUDGE_LLM="OPENAI::<judge model>::<key>::<base_url>"      # judge for prompt-injection scoring; an on-prem model is fine
```

The PurpleLlama commit is pinned in `config/mara.yaml` `model_eval.cyberseceval_ref`: `4be64c3a2444`,
main as of 2026-09-24 (a commit of 2026-08-17). Its `CybersecurityBenchmarks/benchmark/run.py` still takes
every flag `cyberseceval_commands` emits and ships `datasets/prompt_injection/prompt_injection.json` and
`datasets/mitre_frr/mitre_frr.json`; moving the pin means re-checking both. garak's dependency tree (194 distributions,
torch and the CUDA wheels included) is hash-pinned in `tools/model-eval-requirements.txt` since
2026-09-17, resolved on CPython 3.11 / Linux x86_64; a run host on another platform must relock
with `scripts/relock_requirements.py` first. Two entries (langdetect, ecoji) are sdists because no
wheel exists. Install the hash-pinned build closure first and disable build isolation; both
sdists were built successfully with that backend on 2026-09-18. This pins their source and build
tools but does not attest the publishers' builds or replace the actual live evaluation. CyberSecEval's
`requirements.txt` at that commit pins versions but not hashes; it still needs its own resolved hash
closure before the live run.

Run:

```
python3 scripts/model_eval.py plan                                   # shows every command, keys masked
# run: CyberSecEval takes the keys only inside its arguments, so they travel in the child's environment
# and a one-line shim restores them inside the child; `ps` and /proc/<pid>/cmdline show placeholders only
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

The samples carry planted credentials (their answer keys label them CWE-798), which the live secret
preflight would otherwise refuse to send. The runner passes `--calibration-sample` for targets below
`calib/samples/` only; `mara review` then exempts exactly the gitleaks findings at a labelled file
and line, logs `secret_preflight_calibration_exempted` in the audit trail, and still blocks live
egress for any other secret.

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
