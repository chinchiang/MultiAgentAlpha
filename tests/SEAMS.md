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
that calls it: `invocation.load_config`. A patch of `mara.config.load_config` leaves the invocation's own reference in
place, so the test reads the real config: it fails for another reason, or passes without testing what it names. When a
module changes between importing a name (`from .config import load_config`) and calling it through its module
(`config.load_config(...)`), the patches of that name move with it. A patch of a class attribute (`cli.Pipeline.run`)
changes the class itself, the same object wherever it is imported.

A review's tool runner is given, not patched: a test passes it to `Pipeline(cfg, ..., run_tools=...)` (below).
`run_all` is that parameter's default, bound when the class is defined, so a patch of `mara.pipeline.run_all` or
`mara.tools.runner.run_all` reaches no review.

## The pipeline (`src/mara/pipeline.py`)

Each seam: how tests use it; what the code keeps for them to still reach it; the tests.

- `Pipeline(cfg, ..., run_tools=...)`: tests pass a runner with `run_all`'s signature,
  `(target, out_dir, enabled=None) -> list[ToolRun]`, most often `lambda *_a, **_k: [ToolRun(...)]`. `Pipeline._tools`
  calls it for the main tool run, into `<out_dir>/tools`, unless `sarif_dir` is a directory (its `*.sarif` are read
  instead); and in live mode with a `sarif_dir`, again for the secret preflight, into `<out_dir>/live-secret-preflight`
  with `enabled=["gitleaks"]`. `test_security_regressions.py`, `test_redteam_strip.py`, `test_tool_evidence.py`; the
  two calls: `test_tool_evidence.py::test_a_review_takes_its_tool_runs_from_the_runner_it_is_given`,
  `test_security_regressions.py::test_prerecorded_secret_scan_cannot_authorize_live_egress`.
- `Pipeline.providers`: the dict, or its items, replaced after `Pipeline(cfg)` and before `run()`. `Pipeline.run`
  reads them when it runs (the provider mode check, binding the target, the ballot round, the provider manifest); nothing built
  in `Pipeline.__init__` holds them. `fake_panel.py`, `test_exchange.py`, `test_audit.py`,
  `test_redteam_strip.py`, `test_security_regressions.py`.
- `Pipeline.dedupe`: called on the class, a static method. `test_core_review_fixes_8_13.py`.
- `Pipeline.backlog`, `Pipeline.queue_tightened`, `Pipeline.outcome_policy`: read after `Pipeline(cfg)`, so set
  when the pipeline is built, before `run()`. `test_workspace_anchors.py`, `test_review_status.py`.

## The CLI's pipeline (`src/mara/cli.py`)

- `cli.Pipeline.run`: replaced by `run(self, target, **kw)`, which records `kw` and stops. `cli._review` calls it as
  `run(target, sarif_dir=..., provider_mode=..., ...)`, the target positional and every option a keyword.
  `test_governance_leftovers.py`, `test_security_regressions.py`.
- `cli.Pipeline.__init__`: wrapped by `init(self, cfg, **kw)`, which reads `kw["out_dir"]`. `cli._review` builds
  `Pipeline(cfg, out_dir=..., ...)`, the config positional and the rest keywords. `test_security_regressions.py`.
- `invocation.load_config`: patched as a module name. `cli._review` calls `invocation.load(...)`, which calls
  `load_config(...)`; `review` calls `check_paths` first, so a config inside the target is never read.
  `test_security_regressions.py`.
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

- `RunRegistry(workspace, out_dir, start=..., table=...)`, `JobRegistry(workspace, out_dir, start=..., table=...)`: a
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
  of `mara.web.admission`, which both registries call through the module under `held()`.
  `test_web_admission.py`,
  `test_web_server.py::test_a_review_and_a_job_replacing_the_tools_launched_at_once_one_is_refused`.
- `Children.running`: replaced on a registry's own instance (its `children` attribute) by a function that first lets
  the exit be recorded, then asks; `get()` calls it with the id alone, under `Children.held`.
  `test_web_server.py::test_a_run_whose_exit_is_recorded_while_it_is_read_is_never_read_finished_without_its_exit_code`,
  `test_web_server.py::test_a_job_whose_exit_is_recorded_while_it_is_read_is_never_read_as_interrupted`.
- `procs.read_json`, `procs.write_json`: patched as attributes of `mara.web.procs`, which the registries call through
  the module (`get()` reads a run's or a job's record with the first, `create()` writes a run's pid with the second).
  The two tests above, and `test_web_server.py::test_a_run_whose_child_exits_at_once_keeps_the_exit_code_its_waiter_recorded`.
- `mara.web.server.serve`: patched as an attribute of its module; `cli.serve` imports it when it runs, so a test that
  patches it before invoking `mara` or `mara serve` reaches it, and no server listens. `cli.serve` calls it with keyword
  arguments only (`host`, `port`, `workspace`, `out_dir`, `open_browser`, `echo`), which the double records and the
  tests compare. `test_cli_default.py`.

## What the tests build instead of running

Helper modules produce what a stage writes, so a test of what reads it starts from there. Each produces it with the
code that writes it, so it changes with that code:

- `tests/scored_rows.py`: consensus rows as jury scoring writes them (`mara.scoring.jury.score`), one per named
  state. A row written by hand can hold a state scoring never produces, and `decide()` does not check.
- `tests/reply_records.py`: reply records as the agents write them (`mara.audit.ReplyRecord`).
- `tests/review_facts.py`: review facts, policies and consensus rows for `mara.review_status` and what reads its
  results.
- `tests/fake_panel.py`: the ballot round's fake panel, above.
