# Renewal review of the dated scanner exceptions (2026-11-23)

**Review date:** 2026-11-23  
**Reviewed by:** drafted by Claude Code; the owner's review is the merge of the pull request that carries this record  
**Reviewed baseline:** `main` at `69d917008e291900a01e70876df57c7c999f9c2d`  
**Earlier record:** [`cve-2026-59951-exception-review-2026-10-16.md`](cve-2026-59951-exception-review-2026-10-16.md), which said that a dated entry after 2026-12-31 "is a new exception, with a review of its own". This is that review.  
**Decision:** The eighteen entries (eight in `tools/osv-semgrep.toml`, ten in `tools/osv-cyberseceval.toml`, mirrored by ten in `tools/trivyignore.yaml`) are renewed from 2026-12-31 to **2027-03-31**. This is a review of code paths, not a proof that no upstream behaviour reaches the affected code.

## Why a renewal and not a relock

The rule of both files is to remove an entry, and relock, at the release that lets the closure take the fix. No such release exists:

| Pin | Held by | Fix needs | Newest release, read from PyPI on 2026-11-23 |
|---|---|---|---|
| `mcp==1.29.0` | semgrep 1.179.0 | mcp 1.30.0 | semgrep 1.186.0 (2026-11-18) still requires `mcp==1.29.0` |
| `opentelemetry-api~=1.37.0` | semgrep 1.179.0 | opentelemetry-api 1.45.1 / 1.45.2 | semgrep 1.186.0 still requires `opentelemetry-api~=1.37.0` |
| `wcmatch~=8.3` | semgrep 1.179.0 | wcmatch 11.2 | semgrep 1.186.0 still requires `wcmatch~=8.3` |
| `setuptools==81.0.0` | CyberSecEval imports `pkg_resources` | setuptools 83.0.0 / 84.1.0 | setuptools 84.2.1; its wheel, and 82.0.0's, hold no `pkg_resources` (81.0.0's holds 19 files of it) |

`requires_dist` of semgrep 1.181.0 through 1.186.0 was read from `https://pypi.org/pypi/semgrep/<version>/json`; every one of the eight releases carries the three pins unchanged. Left alone, both scans would have failed on 2027-01-01 with nothing to bump.

## What the scanners report today

`osv-scanner` 2.5.1 (the locked one) was run on each closure with an empty configuration, so that nothing was ignored:

- `tools/semgrep-requirements.txt`: eight advisories, exactly the eight entries. None is withdrawn.
- `tools/cyberseceval-requirements.txt`: ten advisories, exactly the ten entries. None is withdrawn.
- No entry matches nothing, and no advisory is reported that has no entry.

`scripts/check_local.py --only osv`, with the configurations, ends `ok` on all four scans. Its line reads "0 ignored" for these two closures although eight and ten are: osv-scanner leaves an ignored advisory out of the SARIF the script counts from, so the count says nothing of the entries. That is a fault of the message, noted here and not changed.

## The reasons, read again

Against semgrep 1.179.0 as installed from the hash-locked closure (`.mara-tools/semgrep-venv`, `semgrep/__init__.py` `__VERSION__ = "1.179.0"`):

**mcp (CVE-2026-59951, -116684, -116685, -116686, -115563).**
- semgrep imports `mcp.server.*`, `mcp.shared.*` and `mcp.types` and nothing else of `mcp`; no file of it names `ClientSession`, `streamablehttp_client`, `sse_client` or `mcp.client`. The three client-side advisories (-116685, -116686, -115563) have no code in semgrep that reaches them.
- The server is built in `semgrep/commands/mcp.py`, `setup_mcp_server()`, and started only by `mcp.run(...)` in the same file, under the `semgrep mcp` command. The two server-side advisories (-59951, -116684) need that command.
- MARA calls semgrep with an argv that begins `scan --metrics=off --disable-version-check --sarif --output` (`mara.tools.semgrep_rules.scan_args`), from `mara.tools.runner.run_all` and `scripts/semgrep_ci.py`. No file under `src/mara`, `scripts` or `.github` passes `mcp` to it.

**opentelemetry-api (CVE-2026-114603, -126360).**
- The parsers run through `propagate.extract`, which semgrep calls in one place, `Telemetry.extract()` (`semgrep/telemetry.py`), on a carrier it builds itself with a `traceparent` and no `tracestate`, and only when both `SEMGREP_TRACE_PARENT_TRACE_ID` and `SEMGREP_TRACE_PARENT_SPAN_ID` are set. `extract()` is called at the end of the tracing set-up, which returns early unless tracing is enabled (`--trace`).
- MARA passes no `--trace`. The environment semgrep gets is `mara.tools.runner.tool_env`: of the parent's variables only an allowlist, which holds no `SEMGREP_*` and no `OTEL_*` name. The two `SEMGREP_*` variables it does set are its own, `SEMGREP_ENABLE_VERSION_CHECK=0` and `SEMGREP_SEND_METRICS=off` (`semgrep_rules.scan_env`), neither of them a trace variable. The entries' wording, "passes no SEMGREP_* or OTEL_* variable", is true of the parent's variables and is to be read so.

**wcmatch (CVE-2026-132276).**
- semgrep imports `wcmatch` in one file, `semgrep/target_manager.py`, to match target paths against the include and exclude patterns of the rules it runs. The reviewed repository controls the paths and no pattern: MARA passes `--x-ignore-semgrepignore-files`, and the rules are the hash-locked checkout.
- The entry rests on a measurement of 2026-11-21 (the 224 globs of the pinned rules against crafted paths, at most 0.024 s a match) and says to re-check "when the pinned rules change". `tools/versions.lock` and both requirement files are unchanged since that day (`git log --since=2026-11-20` names no commit for them), so the measured rules are the pinned ones. **The measurement was not run again for this review:** the rules checkout could not be installed where the review was made.

**setuptools (CVE-2026-59890, GHSA-xmj3-9gf7-h52w), CyberSecEval closure only.**
- Both need a build or an installation this closure does not do: one an sdist built on a macOS file system, the other a legacy wheel installed on Windows. The closure is installed with `pip --require-hashes --only-binary=:all:` on Linux (`tools/cyberseceval-requirements.in`).
- semgrep is in this closure only so that CodeShield finds `semgrep-core` when it is imported; the benchmarks run here (`prompt-injection`, `mitre-frr`) do not start it, so the eight semgrep entries hold here for a stronger reason than in the semgrep closure.

## What this review did not do

- It did not run semgrep, or CyberSecEval: the reading above is of source, and of how MARA builds the command line.
- It did not repeat the wcmatch timing (above).
- It did not read semgrep 1.180.0 through 1.186.0 for the same code paths. They are not installed; the renewal is for the locked 1.179.0. Moving the lock to a later release that keeps the pins needs these readings made again on that release.
- It did not look for advisories OSV does not hold.

## Conditions, and when the entries go

Keep an entry only while all of these hold:

1. semgrep stays at a release that carries the pin, and the affected package stays confined to the semgrep and CyberSecEval closures (`tools/osv-scanner.toml` stays without entries; `tests/test_ignore_expiry.py` checks that, and that the OSV and Trivy entries and their dates agree).
2. MARA and CI call semgrep with `scan` only, without `--trace`, with `tool_env`, and never `semgrep mcp` or `semgrep ci`.
3. The pinned rules are the ones the wcmatch entry was measured on, or it is measured again.
4. The CyberSecEval closure is installed from wheels on Linux.

Remove the entries of a pin, and relock, at the first semgrep release that relaxes it; `scripts/osv_watch.py` and the L0 job's 30-day warning (`scripts/ignore_expiry.py`) are what will say so. On **2027-03-31** the scanners fail again on whatever is still reported. A date after that is another new exception, with a review of its own; this record does not license it.

## Evidence

- PyPI JSON for semgrep 1.181.0 to 1.186.0, mcp, opentelemetry-api, wcmatch and setuptools, read 2026-11-23; the wheels of setuptools 81.0.0, 82.0.0 and 84.2.1, listed that day.
- `osv-scanner` 2.5.1 over both lockfiles with an empty configuration, and `scripts/check_local.py --only osv` with the configurations, 2026-11-23.
- `semgrep/commands/mcp.py`, `semgrep/telemetry.py`, `semgrep/target_manager.py` and every `import mcp` line of semgrep 1.179.0.
- `src/mara/tools/semgrep_rules.py`, `src/mara/tools/runner.py`, `scripts/semgrep_ci.py`, `.github/workflows/mara-review.yml`.
- `tools/osv-semgrep.toml`, `tools/osv-cyberseceval.toml`, `tools/trivyignore.yaml`, `tools/cyberseceval-requirements.in`, `tests/test_ignore_expiry.py`.
