# Quarterly runbook: model red-team evaluation (G-8) and calibration (G-9)

Two governance items need a host that can reach the three model families' endpoints and hold their
keys. This repository ships the scripts, parsers, thresholds and report templates, and commits the
reports of the runs once they have happened: G-9 has its first live calibration (2026-10-08), G-8 has
no live run yet (section 4). Nothing below is a substitute for the run itself: a report built from fixtures, or a calibration run on mock providers, cannot be
labelled `live` (the scripts refuse), so the governance checks cannot be satisfied by accident.

## 1. Prerequisites (both items)

- A host inside the network of the self-hosted endpoints (`config/mara.yaml` `base_url`s), with
  AWS credentials for Bedrock (`AWS_PROFILE`, e.g. after `aws sso login`) and the Gemini key. Keys
  only in environment variables (`GLM_LOCAL_KEY`, `GEMINI_API_KEY`; `DEEPSEEK_LOCAL_KEY` for the
  standbys); no script prints or stores them. The GLM endpoint, and the CyberSecEval judge when it is on the
  same gateway, are signed by an internal CA: garak and CyberSecEval do not read `ca_bundle`, so `run` writes
  for each family a bundle of the public roots plus that family's own chain and `model_eval.judge_ca_bundle`
  under the run directory and points `SSL_CERT_FILE` at it (the CyberSecEval judge runs in the process of the
  model under evaluation, so Gemini's run needs the judge's chain although Gemini itself has none).
- Routes: Claude through garak's `bedrock` generator (no key; `temperature` and `top_p` are suppressed,
  Opus 5.5 refuses both); Gemini through its OpenAI-compatible endpoint in both tools, so the key is
  sent in a header (CyberSecEval's GOOGLEGENAI provider would put it in the URL); GLM through the
  gateway's OpenAI-compatible endpoint.
- Empty outputs are not passes: garak records a failed call or an answer cut short as an empty output,
  and its detectors score it as a pass. The request is tuned so every family answers (Gemini without
  `frequency_penalty` / `presence_penalty`, no `stop` sequences for the OpenAI-compatible targets,
  `max_tokens` 4096 for the reasoning models), and a garak run with more than 20 % empty evaluated
  outputs is reported as `missing`.
- Empty responses are not safe either, and CyberSecEval's stat files do not show them. In `prompt-injection` the judge step
  refuses an empty response, so the row drops out of the judge file and of the stat file and the rate is taken over the rows
  that remain; a judge that replies with nothing is read as "no injection". In `mitre-frr` a prompt that could not be queried
  gets the response `FAIL TO QUERY`, and the refusal scan reads that, like an empty text, as an answer that is no refusal. A query
  that fails all its retries leaves no row. `report` reads the response files next to the stat files and counts the rows that
  are empty or absent against the rows of the datasets (`--datasets`, required for `live`); a metric with more than 20 % of
  them is `missing`, and so is one whose response file is not there. Without `--datasets` only empty responses are counted.
- Scale and cost: the configured probes send 7,210 prompts × 5 generations to each family (about
  36,000 calls; Bedrock takes one generation per call). Budget it before the quarterly run; a trial
  with `garak_probes: [test.Test]` (8 prompts) checks the wiring for a few cents.
- G-8 gap: CyberSecEval at the pinned ref has no Bedrock provider. `plan` lists it as skipped for the
  anthropic family, `run` exits 1, and that family's two CyberSecEval metrics stay missing, so G-8
  stays red for it until there is a route (e.g. the same model through the Anthropic API).
- `mara check-config config/mara.yaml` passes (P1–P8).
- Python 3.11 on Linux x86_64, this package installed from the hash-pinned closure
  (`pip install --require-hashes --only-binary=:all: -r tools/dev-requirements.txt && pip install --require-hashes --only-binary=:all: -r tools/build-requirements.txt && pip install --no-deps --no-build-isolation -e .`).

## 2. G-8: garak + CyberSecEval 4, every quarter, every family

Install the tools once:

```
python3 -m pip install --require-hashes --only-binary=:all: -r tools/build-requirements.txt
python3 -m pip install --require-hashes --no-build-isolation -r tools/model-eval-requirements.txt   # garak 0.17.1 and its whole closure, every file's SHA-256 pinned
python3 -m venv <cse-venv> && <cse-venv>/bin/python -m pip install --require-hashes --only-binary=:all: -r tools/cyberseceval-requirements.txt   # CyberSecEval's closure, in a venv of its own
git clone https://github.com/meta-llama/PurpleLlama && cd PurpleLlama && git checkout 4be64c3a24442b51c76175e6ec67722cc3f5fe38   # CyberSecEval runs from this checkout
export DATASETS=<path with prompt_injection/ and mitre_frr/ from CybersecurityBenchmarks/datasets>
export CSE_JUDGE_LLM="OPENAI::<judge model>::<key>::<base_url>"      # judge for prompt-injection scoring; an on-prem model is fine
```

The PurpleLlama commit is pinned in `config/mara.yaml` `model_eval.cyberseceval_ref`: `4be64c3a2444`,
main as of 2026-09-24 (a commit of 2026-08-17). Its `CybersecurityBenchmarks/benchmark/run.py` still takes
every flag `cyberseceval_commands` emits and ships `datasets/prompt_injection/prompt_injection.json` and
`datasets/mitre_frr/mitre_frr.json`; moving the pin means re-checking both. garak's dependency tree (197 distributions,
torch and the CUDA wheels included) is hash-pinned in `tools/model-eval-requirements.txt` since
2026-09-17, resolved on CPython 3.11 / Linux x86_64; a run host on another platform must relock
with `scripts/relock_requirements.py` first. Two entries (langdetect, ecoji) are sdists because no
wheel exists. Install the hash-pinned build closure first and disable build isolation; both
sdists were built successfully with that backend on 2026-09-18. This pins their source and build
tools but does not attest the publishers' builds or replace the actual live evaluation. CyberSecEval's own
`requirements.txt` at that commit pins versions but not hashes, and osv-scanner reports advisories against several of its pins (pillow,
pypdf, paramiko, langchain-core, urllib3, setuptools). `tools/cyberseceval-requirements.txt` is the hash-pinned closure of `tools/cyberseceval-requirements.in` (109
distributions, wheels only, resolved on CPython 3.11 / Linux x86_64 like the others). That file is upstream's with floors in
place of the vulnerable pins (pillow, pypdf, paramiko, langchain-core, urllib3), `typing-extensions` relaxed to what
`langchain-core` needs, `semgrep` 1.179.0 for 1.51.0 (CodeShield looks up `semgrep-core` when it is imported, and 1.51.0 holds
urllib3 at 1.26.20) and `setuptools` 81.0.0, the last release with `pkg_resources`, which two benchmark modules import. What
relocking cannot fix is a dated exception in `tools/osv-cyberseceval.toml` and `tools/trivyignore.yaml`. Install it in a
virtual environment of its own: its pins disagree with the garak closure (boto3, openai).

What was run on it (2026-11-12): the install with `--require-hashes`; `import CybersecurityBenchmarks.benchmark.run` and `--help`
from the PurpleLlama checkout; `model_eval.py plan` under that environment's interpreter with `PYTHONPATH=<repo>/src`.
`model_eval.py run --tool cyberseceval` was not run (it needs the keys, the datasets and a judge). It starts CyberSecEval with
its own interpreter and the working directory it was started in, so run it with that environment's Python, from the PurpleLlama
checkout, with an absolute `--out`.

Run:

```
python3 scripts/model_eval.py plan                                   # shows every command, keys masked
# run: CyberSecEval takes the keys only inside its arguments, so they travel in the child's environment
# and a one-line shim restores them inside the child; `ps` and /proc/<pid>/cmdline show placeholders only
python3 scripts/model_eval.py run --out ops/model-eval/<date> --datasets "$DATASETS"
python3 scripts/model_eval.py report --run-dir ops/model-eval/<date> --date <date> --mode live --datasets "$DATASETS"
python3 scripts/model_eval.py check                                  # exit 1 if any family fails a threshold
```

What runs per family: garak with the probes in `model_eval.garak_probes` (`promptinject`,
`latentinjection`, `encoding`, `dan`; OpenAI-compatible generator with the family's `base_url`,
or the `anthropic` generator), and CyberSecEval `prompt-injection` (judge LLM scores whether the
injected instruction was followed) and `mitre-frr` (false refusals on benign security prompts).

Before a full run, look at what garak sends and at a small sample of what comes back. On 2026-11-11 the three families answered
a `promptinject` run mostly with empty outputs (1104, 276 and 1075 of 1280): `promptinject` sets the generator's `max_tokens`
from each prompt (60 to 256) before every call, over the 4096 of the generator options, and a reasoning model spends that on
reasoning. `garak_command` now passes `--probe_options` that take `max_tokens` out of the attributes `promptinject` overwrites;
nothing but the request on the wire shows that such a setting arrived.

- *On the wire*: point the generator (`openai.OpenAICompatible`, `uri` in the generator options) at a local stub that answers
  every chat request with a fixed text and records the `max_tokens` of each body. Run one `--spec` per module of
  `model_eval.garak_probes` with `--generations 1` and the `--generator_option_file` and `--probe_options` that `plan` prints.
  Every request must carry the 4096 of the options file. On 2026-11-12: `promptinject.HijackHateHumans` without the probe
  options sent 60, 64, 100, 150, 200 and 256 (256 requests, no 4096) and with them 4096 (256 of 256); `dan`, `latentinjection`
  and `encoding` sent 4096 on all of their 386, 2,216 and 3,840 requests. A proxy in the environment answers requests to
  `127.0.0.1` with a 403 page: set `NO_PROXY=127.0.0.1`. The stub is a page of Python and is not kept in the repository.
- *A sample*: a site config at `$XDG_CONFIG_HOME/garak/garak.site.yaml` with `run: {soft_probe_prompt_cap: 64}` makes garak take
  64 prompts of a probe instead of its 256, so `model_eval.py run` with `model_eval.garak_probes: [promptinject.HijackHateHumans]`
  finishes in about an hour and a half for the three families. Count the empty outputs of each family: an output is empty when it is `None` **or** blank text, and
  garak's own `nones` counts only the first. On 2026-11-12 all three families had none (320 outputs each), and the timing
  (about 32, 33 and 13.5 seconds a prompt, five generations each) puts the 7,210 prompts of a full run at roughly 64, 67 and 27
  hours one family after the other.

What `report` produces:

- `docs/garak-<date>.md` and `docs/cyberseceval-<date>.md` with YAML front matter (`mode`,
  `date`, `families`, tool version, thresholds); governance check G-8 requires both within 90 days,
  `mode: live`, and `families` covering every non-mock family in the config.
- `calib/model-eval-<date>.json`: per family the metric values and verdicts, in the MARA workspace
  (`MARA_HOME`, else the working directory; `--summary-root` overrides it). `scripts/calibrate.py`
  reads the latest one and multiplies a failing family's suggested weight by
  `model_eval.weight_penalty_on_fail`; the review pipeline shows the latest verdict per family in
  the report's `model_eval` and under "Model red-team evaluation" in `report.md`.

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

## 4. Where things stand (G-9: 2026-10-12; G-8: 2026-11-11)

- **G-9 is green.** The first live calibration ran on 2026-10-08 against the production panel (Claude Opus 5.5
  on Bedrock, Gemini 3.8 Flash, GLM on the IEC gateway), five samples and 51 labels, about four hours:
  `docs/calibration-2026-10-08.md`, `calib/history.json`, `calib/latest.json`. Precision / recall / F1 were
  anthropic 0.45 / 0.82 / 0.58, gemini 0.58 / 0.55 / 0.57 and glm 0.41 / 0.80 / 0.54; the suggested weights
  were not written into `config/mara.yaml`. Its Alternative Annotator Test did not pass because there are no
  human decisions to compare yet (no trained adjudicator, G-13), so P8 keeps every rejected non-D finding in
  the human queue. Run section 3 again within 90 days and after any model upgrade.
- **G-8 is still red, but the garak half is wired and runs.** On 2026-11-11 `scripts/model_eval.py run --tool garak`
  ran against all three families with garak 0.17.1, using a copy of the config whose `garak_probes` was only
  `test.Test` (8 prompts, 5 generations each, 40 attempts per family, no source code sent): Claude Opus 5.5 on Bedrock,
  Gemini 3.8 Flash, and GLM on the IEC gateway (through its internal CA bundle) all exited 0 with `always.Pass` 40/40,
  and `report --mode dry-run` read the three garak reports back (garak pass rate 1.0 for each family). The
  first attempt had failed before sending any prompt: garak joins a relative `--report_prefix` onto
  `~/.local/share/garak/garak_runs/`, so `garak_command` now passes an absolute one (v0.13.84; its CHANGELOG row
  says GLM was not run, because the key was not at hand while the fix was made: GLM ran the same day, afterwards).
  `always.Pass` always passes, so this shows the wiring, the keys, the TLS path and the report format, and says
  nothing about how safe a model is. What is still missing for G-8:
  - garak with the real `garak_probes` in `config/mara.yaml` (about 36,000 calls for the full `run`, which has
    not been made);
  - CyberSecEval: it has not been run for any family, and at the pinned ref it has no Bedrock provider, so the
    anthropic family's two CyberSecEval metrics stay missing until there is a route;
  - the reports themselves: there is still no `docs/garak-*.md`, `docs/cyberseceval-*.md` or
    `calib/model-eval-<date>.json`, and the trial output is `dry-run` at best, which G-8 does not accept.
- `fixtures/model-eval/` holds synthetic outputs used only to test the parsers; nothing generated from them
  is, or can be, labelled `live`.
