# Test seams

Where the tests reach into the pipeline and the agents, and the shape of the code each one relies on. A change that
moves, renames or re-signs one of these breaks the tests named beside it, or leaves them passing against code they no
longer reach.

## Patch a name where it is looked up

`mara.pipeline` imports `run_all` by name (`from .tools.runner import ToolRun, load_prerecorded, run_all`), and
`mara.cli` imports `load_config` the same way. A test patches such a name in the module that calls it:
`mara.pipeline.run_all`, `cli.load_config`. A patch of `mara.tools.runner.run_all` leaves the pipeline's own reference
in place, so the test runs the real tools: it fails for another reason, or passes without testing what it names. When a
module changes between importing a name (`from .tools.runner import run_all`) and calling it through its module
(`runner.run_all(...)`), the patches of that name move with it. A patch of a class attribute (`cli.Pipeline.run`)
changes the class itself, the same object wherever it is imported.

## The pipeline (`src/mara/pipeline.py`)

Each seam: how tests use it; what the code keeps for them to still reach it; the tests.

- `Pipeline.run_tools(target, sarif_dir)`: patched on the instance, `lambda *_: [ToolRun(...)]`. The main tool run goes
  through it, called with positional arguments, and it returns `list[ToolRun]`. `test_security_regressions.py`,
  `test_redteam_strip.py`, `test_tool_evidence.py`.
- `mara.pipeline.run_all`: patched as a module name. In live mode with pre-recorded SARIF, the secret preflight calls
  `run_all(..., enabled=["gitleaks"])` itself, outside `run_tools`.
  `test_security_regressions.py::test_prerecorded_secret_scan_cannot_authorize_live_egress`.
- `Pipeline.providers`: the dict, or its items, replaced after `Pipeline(cfg)` and before `run()`. `Pipeline.run`
  reads them when it runs (the mode check, binding the target, the ballot round, the provider manifest); nothing built
  in `Pipeline.__init__` holds them. `fake_panel.py`, `test_exchange.py`, `test_audit.py`,
  `test_redteam_strip.py`, `test_security_regressions.py`.
- `Pipeline.dedupe`: called on the class, a static method. `test_core_review_fixes_8_13.py`.
- `Pipeline.backlog`, `Pipeline.queue_tightened`, `Pipeline.outcome_policy`: read after `Pipeline(cfg)`, so set
  when the pipeline is built, before `run()`. `test_workspace_anchors.py`, `test_review_status.py`.

## The CLI's pipeline (`src/mara/cli.py`)

- `cli.Pipeline.run`: replaced by `run(self, target, **kw)`, which records `kw` and stops. `cli._review` calls it as
  `run(target, sarif_dir=..., mode=..., ...)`, the target positional and every option a keyword.
  `test_governance_leftovers.py`, `test_security_regressions.py`.
- `cli.Pipeline.__init__`: wrapped by `init(self, cfg, **kw)`, which reads `kw["out_dir"]`. `cli._review` builds
  `Pipeline(cfg, out_dir=..., ...)`, the config positional and the rest keywords. `test_security_regressions.py`.
- `cli.load_config`, `cli.console`: patched as module names. `cli._review` calls `load_config(...)`, and output goes
  through the module's `console`. `test_security_regressions.py`, `test_policy.py`.

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

## What the tests build instead of running

Helper modules produce what a stage writes, so a test of what reads it starts from there. Each produces it with the
code that writes it, so it changes with that code:

- `tests/scored_rows.py`: consensus rows as jury scoring writes them (`mara.scoring.jury.score`), one per named
  state. A row written by hand can hold a state scoring never produces, and `decide()` does not check.
- `tests/reply_records.py`: reply records as the agents write them (`mara.audit.ReplyRecord`).
- `tests/review_facts.py`: review facts, policies and consensus rows for `mara.review_status` and what reads its
  results.
- `tests/fake_panel.py`: the ballot round's fake panel, above.
