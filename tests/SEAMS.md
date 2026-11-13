# Test seams

Where the tests reach into the pipeline, the agents and the workbench, and the shape of the code each one relies on.
A change that moves, renames or re-signs one of these breaks the tests named beside it, or leaves them passing against
code they no longer reach.

`tests/test_seams.py` reads every code span here as a pointer: a test file, a `src/` or `tests/` path ending `.py` or
`.md`, and a dotted or capitalised name must each point at something there (a name defined in src/mara, imports
followed). A method a class inherits from outside src/mara, such as the `shutdown` and `server_close` the workbench's
server takes from socketserver, is defined nowhere in it: write it bare, not after its class.

## Patch a name where it is looked up

`mara.invocation` imports `load_config` by name (`from .config import load_config`), so a test patches it in the module
that calls it: `invocation.load_config`, which `invocation.load` calls with the config's path and the MARA workspace
(`load_config(path, workspace)`), so a fake takes both. A patch of `mara.config.load_config` leaves the invocation's
own reference in place, so the test reads the real config: it fails for another reason, or passes without testing what
it names. When a module changes between importing a name (`from .config import load_config`) and calling it through its module
(`config.load_config(...)`), the patches of that name move with it. `mara.policy` imports it by name too
(`check_config_file` calls it), so a test that makes the check meet an exception that is not about the file patches
`policy.load_config` (`test_policy.py`). A patch of a class attribute (`cli.Pipeline.run`)
changes the class itself, the same object wherever it is imported.

A review's tool runner is given, not patched: a test passes it to `Pipeline(cfg, ..., run_tools=...)` (below).
A pipeline given none takes `run_all` from `mara.pipeline` when it is built, so a patch of `mara.pipeline.run_all` made
before `Pipeline(cfg)` reaches that review, and one made after it, or of `mara.tools.runner.run_all`, reaches none.

## The pipeline (`src/mara/pipeline.py`)

Each seam: how tests use it; what the code keeps for them to still reach it; the tests.

- `Pipeline(cfg, ..., run_tools=...)`: tests pass a runner with `run_all`'s signature,
  `(target, out_dir, enabled=None) -> list[ToolRun]`, most often `lambda *_a, **_k: [ToolRun(...)]`. `Pipeline._tools`
  calls it for the main tool run, into `<out_dir>/tools`, unless `sarif_dir` is a directory (its `*.sarif` are read
  instead); and in live mode with a `sarif_dir`, again for the secret preflight, into `<out_dir>/live-secret-preflight`
  with `enabled=["gitleaks"]`. `test_security_regressions.py`, `test_redteam_strip.py`, `test_tool_evidence.py`; the
  two calls: `test_tool_evidence.py::test_a_review_takes_its_tool_runs_from_the_runner_it_is_given`,
  `test_security_regressions.py::test_prerecorded_secret_scan_cannot_authorize_live_egress`. A runner that is given is
  called as it is, with nothing added, whatever its signature; one that is not is `run_all` of the pipeline's workspace
  (the next seam).
- `Pipeline(cfg, ..., root=...)`: tests pass a directory of their own as the root of the MARA workspace. The pipeline
  fixes it when it is built (`Pipeline.root`; MARA_HOME, else the working directory, when none is given) and reads
  the ticket backlog, the ML-BOM, the decision files and training register, the signature bundle, the model
  evaluations and the calibration samples there, so a test setting MARA_HOME before `Pipeline(cfg)` still reaches
  them and one setting it after does not. The tool directory and trivy cache are fixed there too, as `Pipeline.workspace`:
  the tool runner that is not given is `run_all` with it, and the check that none of its anchors lies inside the target
  looks at the same one, so a test setting MARA_TOOLS_DIR after `Pipeline(cfg)` changes neither. The tool directory is
  MARA_TOOLS_DIR when that is set, else `.mara-tools` below the workspace, with the workspace's version lock
  and MARA_TRIVY_CACHE_DIR or the cache below the tool directory. `tests/conftest.py` sets MARA_TOOLS_DIR to an empty
  directory for every test, so a test that installs a tool below the workspace unsets it first.
  `test_pipeline_workspace.py`, `test_pipeline_workspace.py::test_a_pipeline_runs_the_tools_installed_in_the_workspace_it_is_given_not_below_mara_home`.
- `Pipeline.providers`: the dict, or its items, replaced after `Pipeline(cfg)` and before `run()`. `Pipeline.run`
  reads them when it runs (the provider mode check, binding the target, the reviewer round, the ballot round, the provider
  manifest); nothing built in `Pipeline.__init__` holds them. `fake_panel.py`, `test_exchange.py`, `test_audit.py`,
  `test_redteam_strip.py`, `test_security_regressions.py`.
- `reviewer_round.run(ctx, context_view, *, cfg, providers, audit, say, progress, egress_blocked)`: called directly with a
  dict of providers of the test's own, which it reads by the config's reviewer names, so a test needs no `Pipeline`;
  `reviewer_round.dedupe(findings)`: pure, called directly. `test_reviewer_round.py`, `test_core_review_fixes_8_13.py`.
  The `audit` they take is an `Audit`, which refuses a name `mara.audit` does not hold (`mara.audit.COUNTER_NAMES`): a test that
  needs another key in the bias audit adds it to the names, or builds the report's dict beside the audit (`{**audit,
  "key": value}`). `test_audit.py`, `test_audit_names.py`.
- `Pipeline.backlog`, `Pipeline.queue_tightened`, `Pipeline.outcome_policy`: read after `Pipeline(cfg)`, so set
  when the pipeline is built, before `run()`. `test_workspace_anchors.py`, `test_review_status.py`.

## The CLI's pipeline (`src/mara/cli.py`)

- `cli.Pipeline.run`: replaced by `run(self, target, **kw)`, which records `kw` and stops. `cli._review` calls it as
  `run(target, sarif_dir=..., provider_mode=..., ...)`, the target positional and every option a keyword. `review`
  admits the invocation before `Pipeline.run` (`invocation.admit`, which checks the target's options with
  `check_calibration_sample` and `check_base`), so patching `run` does not skip them: a test that gives `--base` gives a
  git repository for a target, one with a merge base for that ref, and `--calibration-sample` a target below the
  workspace's `calib/samples/`.
  `test_governance_leftovers.py`, `test_security_regressions.py`, `test_invocation_checks.py`.
- `cli.Pipeline.__init__`: wrapped by `init(self, cfg, **kw)`, which reads `kw["out_dir"]` and `kw["root"]`.
  `cli._review` builds `Pipeline(cfg, out_dir=..., root=..., ...)`, the config positional and the rest keywords, the
  root of the workspace the invocation was admitted against. `test_security_regressions.py`.
- `invocation.load_config`: patched as a module name. `review` calls `admit(...)`, which `cli` imports by name from
  `mara.invocation` (a patch of `admit` itself goes in `cli.admit`); `admit` calls `load(...)` and `load` calls
  `load_config(...)`, both in `mara.invocation`, so the one patch reaches the command line and the workbench alike.
  `admit` calls `check_paths` first, so a config inside the target is never read.
  `test_security_regressions.py`, `test_invocation_admit.py`.
- `cli.console`: patched as a module name; output goes through the module's `console`. `test_policy.py`.

## The agents: the Provider seam (`src/mara/providers/base.py`)

Agent tests drive an agent through a `Provider` subclass of their own that overrides `complete(*, system, user, schema,
role, max_tokens=16000) -> RawReply` (`test_live_providers.py` also drives a real `OpenAICompatibleProvider` over a fake
HTTP reply). Many of them take `**kwargs` and read only `user`, so the agents call `complete` with keywords and the
prompt the tests inspect is `user`. The entry points the tests call directly, each with such a provider:

- `reviewer.review_dimension(provider, ctx, dimension, canary=None, context_view=None)`: tests hand in an
  `exchange.Canary()` of their own, to know the token a canary echo would carry.
- `context_agent.run_context_agent(provider, ctx)`
- `skeptic.run_skeptic(provider, ctx, findings)`, `redteam.run_redteam(provider, ctx, findings)`,
  `judge.run_judge(provider, batch, pass_id)`
- `ballot_round.run(...)`, through `tests/fake_panel.py`: a seat for every model of the config, answering as its
  provider does unless a test scripted that role's reply, with every exchange recorded.

Tests: `test_agent_harness.py`, `test_prompt_fences.py`, `test_reply_exchange.py`, `test_live_providers.py`,
`test_core_review_fixes.py`, `test_exchange.py`, `test_audit.py`, `test_redteam_strip.py`.

## The workbench (`src/mara/web/`)

- `RunRegistry(root, out_dir, start=..., table=...)`, `JobRegistry(root, out_dir, start=..., table=...)`: a
  test passes a table only to build the two over one. A test that builds a registry and starts children passes it a
  starter or patches `procs.spawn` (as the HTTP-level tests, which build the server, and
  `test_server_exit_cancels_a_running_run` do). Each registry hands its starter and its table to its `procs.Children`,
  which gives the starter to `ChildTable.start`; the table calls it as `start(argv, cwd=..., log_path=..., env=...)` and
  keeps the child it returns for its `pid`, `poll()` and `wait()`: a Popen of the subprocess module, or one wrapped by
  `tests/held_children.py` so that it has exited while its exit is not yet recorded. With no starter, the table calls
  `procs.spawn` as the module has it at that moment, so a test patching `procs.spawn` after the server was built still
  reaches it. With no table, a registry's children get a table of their own; the server builds one table
  (`procs.ChildTable()`) and passes it to both, so a test building the two passes them one table to see the admission
  between runs and jobs. `test_web_server.py`.
- `procs.Children(name, on_exit, start=..., table=...)`: driven at its own interface (`start`, `running`, `any_running`,
  `stop`, which see one registry's children only, and `held`, the lock of its whole table). Its waiters are threads
  named after the registry and the child (`"mara-run-" + run_id`), the name tests find one by to join it.
  `test_web_procs.py`, `test_web_server.py`.
- `procs.ChildTable`: the children of the registries given one table share its lock (`held()` of any of them),
  `ChildTable.running_tags` answers the tags of every child running in it, and `ChildTable.shutdown` stops every one of
  them at server exit and sets `closed`, after which both registries refuse a launch (`LaunchError` `stopping`, 503)
  and write nothing; a test reaches the table as the `table` of a registry's `children` or of the server, and
  `WorkbenchServer.close()` calls it. `test_web_procs.py`, `test_web_server.py`.
- `procs.kill`: wrapped as an attribute of `mara.web.procs` by a function that records the child it is given, then
  calls the real one; `ChildTable.shutdown` looks it up in its module when it kills, so the wrapper sees every kill.
  `test_web_procs.py::test_only_the_children_still_running_after_the_grace_are_killed`.
- `WorkbenchServer.close`: on a server's own instance, its `shutdown` and `server_close` and its `table`'s `shutdown`
  are replaced by functions that record which step ran, then call the real ones, so a test reads the order `close()`
  takes them in. `test_web_server.py::test_closing_a_server_stops_serving_then_its_children_then_closes_its_socket`.
- `admission.refusal(kind, running)`: pure, called directly with a kind and a set of kinds. Also patched as an attribute
  of `mara.web.admission`, which `Children.launch` calls through the module under `held()`, for a run and a job
  alike. `test_web_admission.py`,
  `test_web_server.py::test_a_review_and_a_job_replacing_the_tools_launched_at_once_one_is_refused`,
  `test_web_procs.py::test_a_launch_admission_refuses_is_refused_as_busy_and_writes_nothing`.
- `Children.running`: replaced on a registry's own instance (its `children` attribute) by a function that first lets
  the exit be recorded, then asks; `Children.read`, which each registry's `get()` calls, asks it with the id alone,
  under `Children.held`.
  `test_web_server.py::test_a_run_whose_exit_is_recorded_while_it_is_read_is_never_read_finished_without_its_exit_code`,
  `test_web_server.py::test_a_job_whose_exit_is_recorded_while_it_is_read_is_never_read_as_interrupted`.
- `procs.read_json`, `procs.write_json`: patched as attributes of `mara.web.procs`, which `Children.read` and
  `Children.launch` call by their module names (`read` reads a run's or a job's record with the first, `launch` writes
  its record and then its pid with the second).
  The two tests above, and `test_web_server.py::test_a_run_whose_child_exits_at_once_keeps_the_exit_code_its_waiter_recorded`.
- `mara.web.server.serve`: patched as an attribute of its module; `cli.serve` imports it when it runs, so a test that
  patches it before invoking `mara` or `mara serve` reaches it, and no server listens. `cli.serve` calls it with keyword
  arguments only (`host`, `port`, `root`, `out_dir`, `open_browser`, `echo`), which the double records and the
  tests compare. `test_cli_default.py`.
- `panel.model_row(m)`, `panel.roles_row(r)`, `panel.manifest_row(entry)`: pure, called directly. A test gives `model_row`
  a `ModelSpec` built without its validation (`model_construct`): the validator refuses an endpoint with credentials, a
  query, or plain http beyond the loopback, and the row must hold only the host whatever it was given.
  `test_panel.py`.

## What the tests build instead of running

Helper modules produce what a stage writes, so a test of what reads it starts from there. Each produces it with the
code that writes it, so it changes with that code:

- `tests/scored_rows.py`: consensus rows as jury scoring writes them (`mara.scoring.jury.score`), one per named
  state. A row written by hand can hold a state scoring never produces, and `decide()` does not check.
- `tests/usable_decisions.py`: usable decisions as `mara.decisions` holds them once selected against a reviewed content,
  `decision(f, verdict, content=...)` bound to a finding's place under the queue key `mara.human_queue` gives it and
  `usable(*decisions)` the selection that `human_queue.settle` and `settlement.finish` take. A decision written by hand
  can hold a key no review writes. `test_settlement.py`, `test_human_queue_rules.py`, `test_sarif_final_outcome.py`,
  `test_report_assembly.py`.
- `tests/reply_records.py`: reply records as the agents write them (`mara.audit.ReplyRecord`).
- `tests/review_facts.py`: review facts, policies and consensus rows for `mara.review_status` and what reads its
  results.
- `tests/fake_panel.py`: the ballot round's fake panel, above.
- `tests/tool_installs.py`: what `scripts/install_tools.py` leaves for `runner.run_all`, the workspace's lock and a
  tool directory's manifest recording each tool at its locked version. A test faking a tool's binary gives the runner
  these instead of patching `runner.installed_version`, so the pin check (`mara.tools.pins`) runs as in a review. A
  `run_all` given a workspace reads the lock below that workspace's root (`lock_into(workspace.root)`), not below
  MARA_HOME, and runs no tool for a workspace without one.
  `test_tool_env.py`, `test_tool_target_config.py`, `test_base_ref_trivy_hf_token.py`, `test_tools_csp.py`,
  `test_install_tools.py`.

## The MARA workspace (`src/mara/workspace.py`)

- `Workspace(root, tools_dir=None, trivy_cache=None)`: the tool directory is `<root>/.mara-tools` and the trivy cache
  `<tool directory>/trivy-cache` when not given, and building one reads no environment variable, whatever MARA_HOME,
  MARA_TOOLS_DIR and MARA_TRIVY_CACHE_DIR say. `Workspace.from_env(root=None)` reads them (a reader given no workspace
  still does too): the root is `root`, else MARA_HOME, else the working directory; MARA_TOOLS_DIR and
  MARA_TRIVY_CACHE_DIR win over what the root derives, and a relative one of either is below the root, wherever the
  process runs (a relative cache was below the working directory until v0.13.73). A test starts by removing the three from
  the environment, and for a relative cache puts the working directory somewhere else than the root.
  `test_workspace.py`, `test_trivy_db.py::test_the_trivy_cache_the_environment_names_follows_one_rule_wherever_the_process_runs`.
- `Workspace(root)`: tests pass `Workspace(tmp_path)` to `mara.config.load_config` (`load_config(path, workspace,
  today=...)`), `mara.policy.evaluate_policies` and `mara.policy.workspace_policies`. Policy P7 (`mara.policy.p7_ml_bom`)
  reads the ML-BOM and its signature bundle, P8 (`mara.policy.p8_unsupervised_reject`) `calib/latest.json`, below that
  root and never below MARA_HOME or the working directory. The workspace is required, with no default, by `load_config`,
  `evaluate_policies`, `workspace_policies`, `check_config_file`, `p7_ml_bom`, `p8_unsupervised_reject` (workspace, then
  `today`) and `mara.invocation.load`. The root of the workspace is required, as `root`, by `mara.mlbom.status_for_config`
  and `verify_signature`, `mara.decisions.read_backlog`, `TrainingRequirement.from_config_file` and `from_config`, and
  `mara.invocation.calibration_answer_key` and `check_calibration_sample`. A test that left it out passes the repository
  (`Workspace` of it, or its path), which is what the working directory was. `test_policy.py`, `test_ml_bom.py`.
- `MaraConfig` reads no workspace when it is built: its validator runs P1 to P6 only (`mara.policy.config_policies`),
  and `mara.config.load_config` runs P7 and P8 once the config is built. A test that needs P7 or P8 to refuse a config
  writes it to a file and loads it with `load_config` in a workspace of its own; one that builds a config with
  `model_validate` meets P1 to P6 only.
  `test_policy.py::test_a_config_is_built_without_reading_a_workspace_and_its_workspace_refuses_it_when_it_loads`.
- `mara.policy.check_config_file(path, workspace)` reports the policies of a config file with P7 and P8 read from that
  workspace; `mara.web.env.configs(root)` passes the workspace it lists, so a test of the environment page puts the
  Evidence record below the `tmp_path` it lists and sets MARA_HOME elsewhere. `mara check-config` passes the workspace it
  read from the environment once, which is the environment's. `test_policy.py::test_a_config_file_is_checked_against_the_workspace_it_is_given_not_the_environment`,
  `test_panel.py::test_the_environment_page_lists_policies_as_the_workspace_it_is_given_holds_evidence_for_them`.
- `mara.workspace.check_outside(target, extra, workspace=...)` judges the root, the tool directory and the trivy cache of
  the `Workspace` it is given, so a test puts them inside or outside `target` through that workspace and sets the
  environment's elsewhere; the workspace is required, and so is the `base` of `mara.workspace.resolve(path, base)`, the root
  a relative path lies below. `test_workspace_anchors.py`, `test_workspace.py`.
- The tool runner reads the tool directory of a workspace passed as the required keyword `workspace=`, and a call that
  leaves it out raises TypeError (`test_tool_env.py`): `mara.tools.runner.tools_dir`, `tool_path`,
  `installed_manifest_entry`, `installed_version` and `run_all`; `mara.tools.trivy_db.cache_dir`,
  `mara.tools.csp_eval.driver_path` and `run_csp_eval`, `mara.tools.semgrep_rules.rules_dir`,
  `installed_rule_paths` and `default_configs`, `mara.web.env.trivy`; `mara.mlbom.cosign_verify_blob_cmd` and
  `cosign_sign_blob_cmd` take the tool directory itself. A test that sets MARA_TOOLS_DIR to drive the entry passes
  `Workspace.from_env()`; one that calls the reader directly passes `Workspace(root, tools_dir=...)`. A test that replaces
  `runner.tool_path` or `semgrep_rules.installed_rule_paths` with a fake gives it a `workspace` parameter too, since `run_all`
  calls them with the keyword (the `every_tool` fixture of `test_tool_env.py`); so does a fake of `tool_path` or
  `installed_version` in `scripts/osv_ci.py` (`test_security_regressions.py`). `test_tool_env.py`, `test_trivy_db.py`.
- The environment page lists the tools and the trivy database of the workspace it lists: `mara.web.env.tools(root)`
  and `mara.web.env.environment` take the tool directory MARA_TOOLS_DIR names, else the one below that workspace, so a
  test installs a tool below the workspace it lists and unsets MARA_TOOLS_DIR; `mara.web.env.trivy(cache, workspace=...)`
  takes an explicit `cache` before the workspace's trivy cache. `test_panel.py`.
- `AdmittedInvocation.root` is the root `invocation.admit(inv, root)` was given, not the environment's: a test
  sets MARA_HOME and the working directory elsewhere and reads it from what `admit` returns
  (`test_invocation_admit.py::test_an_admitted_invocation_remembers_the_root_it_was_admitted_against`); `cli._review`
  hands it to `Pipeline(root=...)`, which a test reads through the `cli.Pipeline.__init__` seam (above,
  `test_security_regressions.py::test_the_command_line_hands_the_pipeline_the_root_it_admitted_the_invocation_against`).
- Who reads the environment. `review`, `export-summary`, `check-config` and `serve` of `mara.cli` each read it once, with
  `Workspace.from_env()`, and hand that value down (`review` through `admit` and `AdmittedInvocation.root`). Four
  places are given a root and take from the environment only what a root does not say, the tool directory and the trivy
  cache MARA_TOOLS_DIR and MARA_TRIVY_CACHE_DIR name, with `Workspace.from_env(root=...)`: `Pipeline` (the root it was
  given, else the environment's root, for its default tool runner), `mara.web.env` (`tools`, `trivy`, `environment`),
  `mara.invocation.check_paths` and `mara.web.procs.child_env` (which writes the three anchors, absolute, into the
  environment of a child). A test of any of them installs a tool or a cache below the workspace it passes and unsets
  MARA_TOOLS_DIR and MARA_TRIVY_CACHE_DIR (`tests/conftest.py` sets the first for every test). Every other reader of
  `src/` takes the workspace or root with no default. Four readers that have none to take read the environment's root
  with `mara.workspace.root()`: `Pipeline` (given none), the trusted CA bundle of `mara.providers.openai_compatible` and of
  `mara.model_eval` (both through `mara.workspace.resolve_user_path`), and `trivy_db.max_age_hours`; the scripts are the
  next bullet.
- The scripts read the environment once, in their `main`, with `Workspace.from_env()`, and hand the value to every reader
  that takes one; the workspace of `--root` is not derived. `trivy_db`, `ml_bom`, `model_swap_drill`, `psirt_ops`,
  `rollout_phase` and `model_eval` put it on the parsed arguments, as their `workspace` attribute, so a subcommand's
  function reads it from there and its signature stays `(a)`; the others (`csp_ci`, `gitleaks_ci`, `osv_ci`,
  `scorecard_ci`, `semgrep_ci`, `zizmor_ci`, `trivy_ci`, `live_smoke`, `calibration_run`, `calibrate`,
  `human_queue_issues`, `training_register`, `governance_check`) hold it in `main` and pass it down; `compare_reviews`
  builds it where it loads the one config, in its `tightened` scenario. A function a script's tests call takes it as a
  parameter: `check_pins(workspace)` of `scripts/semgrep_ci.py` and of `scripts/csp_ci.py`, `pinned_trivy(workspace)` of
  `scripts/trivy_db.py`, `anchor_paths(workspace)`, `load_model_eval(workspace)` and `training_requirement(workspace,
  config=None)` of `scripts/calibrate.py`, `_ledger_path(cfg, workspace)` of `scripts/psirt_ops.py`, and
  `load_runs(out_dir, samples_dir, decisions_dir, training)` of `scripts/calibrate.py`, which no longer looks up the last
  two. A test that runs a script's `main` (a subprocess, or `main()` called with the argument vector patched) keeps
  setting MARA_HOME and MARA_TOOLS_DIR; a test of a function that takes the workspace passes one, `Workspace.from_env()`
  where the fixture has set MARA_HOME. A fake of `tool_path`, `installed_version` or `check_pins` accepts what the script
  now passes (`workspace=`). `test_workspace_anchors.py` holds the guard: one test per `scripts/*.py` reads the file's
  syntax tree and lists a call of a reader given no workspace (`tools_dir`, `cache_dir`, `tool_path`, `installed_version`,
  `installed_manifest_entry`, `rules_dir`, `installed_rule_paths`, `driver_path` and `run_csp_eval` without `workspace=`;
  `load_config`, `evaluate_policies`, `status_for_config` and `mara.workspace.resolve` without their second argument;
  `make_server` without `root=`) and the import of `mara.workspace.root`, and a test of the scan itself says what it sees and what it leaves alone (a
  script's own `load_config`, one imported from another script).
- `governance_check` is the exception among the scripts. `check_g2`, `check_g3`, `check_g4`, `check_g7`, `check_g8`,
  `check_g9`, `check_g10` and `_production_families` take `workspace` as an optional keyword and read the environment's
  when it is left out, because their tests call them directly with a root and a config path only (about 45 calls in eight
  files); `run_all` builds the workspace once and hands it to the seven, and `main` hands `run_all` its own. `check_g5`
  reads the tool directory of `Workspace.from_env(root=root)`, as `tools_dir(root)` did. `check_g4` hands the workspace it
  judges against to `govdocs.drill_status(..., workspace=...)`, which loads each standby config in it (policies P7 and P8
  read its files), as `scripts/model_swap_drill.py` does with the workspace on its parsed arguments; both are required there
  (`test_governance_templates.py`). `_live_calibration` of
  `scripts/rollout_phase.py` calls `check_g9(root, today, config)` with no workspace, so `scripts/rollout_phase.py
  advance` judges the config against the environment's workspace there, which is the one its parsed arguments hold; the
  guard does not see it, since it names no `check_g9`. A test of the checks sets MARA_HOME and puts the files below the
  root it passes, and gives `workspace=` only when the workspace differs from the environment's.

A test that gives the runner a tool directory builds the workspace with the `workspace` function of tests/tool_installs.py:
the repository's root, so its version lock is the one read. A test of a tool that is not found also puts the tool in the
environment's directory (MARA_TOOLS_DIR, and MARA_TRIVY_CACHE_DIR for the database), because conftest.py points the
environment at an empty one: without that, a reader that ignored the workspace it was given would read the empty
directory and the test would pass all the same. `tests/mutations/tool-workspace-honoured.yaml` is that check.

## The local checks (`scripts/check_local.py`)

`test_check_local.py` replaces the table of checks the script runs with fake ones, each a function of the parsed arguments that
returns the argument vector to run, its extra environment and what to do first; `main` then runs them, and a test reads
what a check printed from its log, whose first line is the command and whose last is the last line the check printed. Every
check's process gets its environment from `check_env`, which puts this checkout's src/ first on PYTHONPATH and what was
there after it (`test_a_check_imports_the_mara_of_the_checkout_it_runs_in`), so a fake check that prints its PYTHONPATH sees
it. The same rule for the demo script is
`test_workbench_demo.py::test_the_script_assembles_the_page_from_the_mara_of_its_own_checkout`: it runs the script with --check
in a child whose PYTHONPATH holds a package named mara that refuses to be imported.

What `main` prints is flushed as it is printed (`_say`), since stdout redirected to a file is block-buffered and a run followed from
outside would show nothing until it ended. A test sees that by replacing stdout with an object that remembers what was written and
not yet flushed (`test_a_result_line_is_flushed_before_the_next_check_starts`, which reads it from inside the next check's set-up
function, and `test_everything_main_prints_is_flushed_when_it_returns`); `capsys` cannot, for it never buffers.

## The Evidence record (`src/mara/evidence.py`)

`test_evidence_record.py` reads `mara.evidence` at its interface: `Header` (made by `Header.from_json` and `Header.from_front_matter`),
`standing` and `header_fields`, always at a fixed `today`, never at the real date. `mara.policy.p8_unsupervised_reject` takes
the same `today` and a `Workspace`, and reads `calib/latest.json` below the workspace's root: a test of it writes the
file below `tmp_path` and passes `Workspace(tmp_path)` (the MARA workspace, above). `governance_check` is a script, not a package: the tests put `scripts/` on the import
path and call `check_g8` and `check_g9`, which take `today` and a config path. A record's mode is `live` in lower case or
the record is not live; the writers write `live`, `mock` or `dry-run`, and a test that writes a record by hand writes one of
those. The round trips in `test_evidence_record.py` run the real writers (`scripts/calibrate.py`'s `main`, `front_matter`
and `latest_record`, and `mara.model_eval.render_garak_report`) and hand what they wrote to the real readers; they patch
`load_runs` and `training_requirement` of `scripts/calibrate.py` as module names and nothing of the readers. A test that
reads the front matter of a Markdown report reads it through `mara.evidence.read_front_matter`, which `mara.govdocs`
imports by name.
The CA file `scripts/model_eval.py` writes for a family whose target or whose CyberSecEval judge sits behind an internal CA is read in
`test_model_eval.py` through `_tls_env(target, out_dir, judge_ca_bundle)` (the returned SSL_CERT_FILE and the file at that path, with a
target built by keyword and a real PEM file; the third argument is empty when no judge CA is named) and, as the printed environment of
`plan`, through the command line. The judge's CA comes from the config field `judge_ca_bundle` of the `model_eval` block (empty by
default, a typo in the key is refused): `plan` and `run` hand it to `_tls_env` for every family, in both tools, so the file holds the
public roots, the target's `ca_bundle` and the judge's, a file named twice once. The text of that bundle is read through
`ca_bundle_pem(target, judge_ca_bundle)` itself (a target built by keyword, real PEM files below `tmp_path`: the order of the
three parts, a file named twice, also under two spellings, and the answer when neither names a file); a `~` path is tried by
pointing the home directory variables of the process at `tmp_path`. A test that patches `_tls_env` replaces it with a
function that takes that third argument, which has no default. The test of `run` replaces the script's call that starts a child process
and reads the environment each command is given; the test of the handshake runs a local HTTPS server signed by a throwaway CA made with the `openssl` program (the test
is skipped without it) and an `httpx` request in a child process that holds only the returned environment as its trust settings.

The empty responses of a CyberSecEval run are read in `test_model_eval.py` at three places. `mara.model_eval.parse_cse_responses(path,
expected, fields)` is called with response files written below `tmp_path` in the shape CyberSecEval writes them (`_judge_row` and
`_frr_row` build the rows): the counts it returns (`rows`, `empty`, `absent`, `usable`, `empty_rate`), one test for each kind of
value that holds no answer (a missing key, null, blank text, `FAIL TO QUERY` with and without an error after it), and the
value error that names the file. `mara.model_eval.cse_dataset_sizes(datasets)` reads a datasets directory that `_write_datasets`
lays out, and is refused with the path of the file it could not read. `_collect` and `_read_benchmark` of the script have no test of
their own: they are read through the `report` command line (`_report`, with `--datasets` where a test needs it) on a copy of the fixtures
whose deepseek directory holds the response files the test wrote and none of the fixtures' own (`_deepseek_run`): the verdict in the summary
file under `calib`, the notes in the CyberSecEval report, and the exit status for a datasets directory that is bad or missing
when `--mode live` needs it. The text of that report is read through `render_cyberseceval_report` with results that
`_cse_family` builds from the counts `parse_cse_responses` reads and the verdict `evaluate_family` gives, never a verdict written
by hand; the stat files are read through `parse_cse_prompt_injection` and `parse_cse_frr` as before. The fixtures' response
files hold as many rows as their stat files count, each with text, so a report built from them has no empty response.

The empty outputs of a garak run are read in `test_model_eval.py` through `mara.model_eval.evaluate_family` with garak results in the shape
`parse_garak_report` returns (`_garak_family` builds them; one test writes the `empty_rate` None of a report with no outputs), and
`test_thresholds_and_verdicts` hands it results that hold only `pass_rate` and `empty_rate`, which stands while `evaluate_family` reads no
other key of garak's. They are read through `render_garak_report` with those results, and through the `report` command line on a copy of the
fixtures whose deepseek garak report has lost its `attempt` rows: the test drops them by their `entry_type`, and reads the verdict in the
summary file under `calib`, the family's row and the note `_collect` gives for it. The fixtures' garak reports hold one evaluated (`status`
2) attempt row per probe, with as many outputs as the probe's eval row counts, each with text, so a report built from them has no empty
output.

## The key variable (`src/mara/credentials.py`)

`test_credentials.py` reads `mara.credentials.key_env(provider, api_key_env)` at its interface, as a hand-written table (not
derived from the module's own defaults), and each place that asks it through that place's own interface: the provider
adapters by constructing them (`OpenAICompatibleProvider(spec).client.headers`, `GeminiProvider(spec).client.headers`, and
`AnthropicProvider(spec)` with the Anthropic SDK's client class patched as a module attribute to record its keyword
arguments), `mara.model_eval.garak_command` (its returned environment) and `target_key_env`, and
`mara.web.env.credential`. A test of a self-hosted endpoint sets the Anthropic key in the environment and asserts it is not
used. A spec built without validation stands in where the spec's data-residency rules are not what is tested.

## The replace of a record (`src/mara/file_replace.py`)

`test_progress.py` and `test_web_procs.py` make another process or thread hold a record by patching replace on the os
module: it raises a PermissionError a given number of times, then replaces as usual. So `mara.file_replace.replace`
keeps calling it through the module, as os.replace; importing replace from os by name would leave the patch unreached,
and the tests would pass on a replace never refused. The writers, `Progress._write` and `mara.progress.close_abandoned`
(`test_progress.py`) and `mara.web.procs.write_json` (`test_web_procs.py`), all go through it. The patch is the `os`
module's own attribute, the same object everywhere, and monkeypatch restores it when the test ends.

## The answer that closes a connection (`src/mara/web/server.py`)

`test_web_server.py` sends these requests over a raw socket (`_exchange`) and reads until the server closes, not with
the standard HTTP client, which sends and reads in one call and would hide which of the two failed. A request refused before its
body is read (over the size limit, chunked, a length that is no number, a foreign Host, a body on a GET) must still get
its answer, and the connection must end without a reset; `Handler.finish` does it for every such path, so the cases
are listed in the test, not in the handler. The wait for the next piece of what the client is still sending is
`mara.web.server.LINGER_SECONDS`, read where it is used: the test patches it as an attribute of that module, and a
copy of it kept as a default argument or on the class would leave the patch unreached.

## The output of a child process (`scripts/`, `src/mara`)

`test_subprocess_encoding.py` walks the source files and lists every call that reads a child's output or input as
text without `encoding="utf-8", errors="replace"`: nothing is patched, so a new call that forgets them fails there
without a test of its own. What it does not see is a call that builds its keywords with `**`, or one that takes `run`
from subprocess by name; none exists. The one behaviour test runs the gh wrapper of `scripts/human_queue_issues.py` in a child whose locale
is ASCII (`not_utf8_env`) against a stand-in for gh that is an executable script on PATH, so it is skipped on Windows;
the other calls are held by the walk alone.

## What a test must not read from the semgrep scan

The number of accepted findings `scripts/semgrep_ci.py` reports is not a stable value: ten scans of the same tree gave
117 to 122, with the same pinned semgrep and rules. Only
`python.lang.security.audit.dangerous-subprocess-use-tainted-env-args` moves (a taint rule, found or not found from one
scan to the next, at `scripts/calibration_run.py`, `scripts/osv_ci.py`, `scripts/semgrep_ci.py` and
`scripts/trivy_ci.py`);
`dangerous-subprocess-use-audit` is the same every time. The triage entries match by rule and path, so every position
that moves is covered and the check's result does not change. A test or a script compares the untriaged count (0), not
the accepted count.
