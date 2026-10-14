# Security policy

This file is about vulnerabilities in **this repository's own code**: the `mara` package under
`src/`, the scripts under `scripts/`, the GitHub Actions workflows and the tooling lock under
`tools/`. It is the entry point for anyone outside the project who finds a security problem in
that code. It is not the hand-off from the review pipeline to a product PSIRT; that mechanism
(Cyber Resilience Act Article 14 early warning for A-tier Critical findings) is described in
[docs/psirt-integration.md](docs/psirt-integration.md) and has nothing to do with reporting
problems in MARA itself.

## Scope

In scope: `src/mara/**`, `scripts/**`, `.github/workflows/**`, `tools/versions.lock`,
`tools/*-requirements.txt` and the configuration under `config/`. That includes the local web
workbench `mara serve` (`src/mara/web/`): its loopback-only listener, the session token, the Host,
Origin and Sec-Fetch-Site checks, the hash-based Content-Security-Policy and the review and job
subprocesses it starts (design: [docs/adr/0006-local-web-workbench.md](docs/adr/0006-local-web-workbench.md)).
A report about it should also name the browser and its version, and the exact `mara serve` command.

Out of scope, on purpose: `fixtures/vuln-sample/` and `calib/samples/` are **deliberately
vulnerable** review material (reflected and DOM XSS, SQL injection, IDOR, hard-coded tokens, an
insecure workflow, outdated packages). They exist so the pipeline, the pre-recorded SARIF and
the calibration corpus have something to find. Reports about them will be closed without
action, and the same goes for the advisories GitHub Code Scanning and OpenSSF Scorecard raise
against those directories.

## Supported versions

There are no releases. Only the `main` branch is supported; a fix lands there and is described
in a GitHub security advisory.

## How to report a vulnerability

Use GitHub private vulnerability reporting for this repository:

<https://github.com/chinchiang/MultiAgentAlpha/security/advisories/new>

Please do not open a public issue or pull request for a security problem. Include the affected
file and line, the version or commit you tested, and a reproduction (a command, a config, a
minimal input). If the problem involves a model provider or a self-hosted endpoint, say which
provider class (`anthropic`, `bedrock`, `gemini`, `openai_compatible`, `mock`) and never include a real API key
or AWS credential.

Private vulnerability reporting was switched on for this repository on 2026-09-17
(*Settings → Code security → Private vulnerability reporting*), so while the repository is public
the link above opens the private advisory form directly.

**While the repository is private (since 2026-09-21)** GitHub does not offer private vulnerability
reporting, and the link above returns 404. Everyone who can read the code is then a collaborator:
report the problem to the maintainer (@chinchiang) directly through a non-public channel (a direct
message or an internal e-mail, not an issue, pull request or discussion). The maintainer opens a
draft security advisory for it, and the rest of this policy applies unchanged. When the repository
is made public again, check that the setting above is still on before relying on the link.

## What happens next

The maintainer reads every private report, confirms receipt in the advisory thread, and works
the report through the same three stages the pipeline uses for its own PSIRT hand-off: an early
acknowledgement, an assessment (is it reachable, what is the impact, which commits are affected),
and a fix or a documented decision. The clocks in `docs/psirt-integration.md` (24 hours, 72
hours, 14 days) are the internal targets for those stages; they are targets the maintainer aims
for, not a contractual commitment, and they are shown here so a reporter knows what to expect.

Coordinated disclosure: once a fix is on `main`, the advisory is published with credit to the
reporter unless they ask otherwise. If a report turns out to describe the seeded material or a
non-reachable condition, the advisory is closed with the reasoning written down.

## How this repository checks itself

Every pull request runs the L0 tools pinned and verified in `tools/versions.lock` (semgrep with
pinned rules, osv-scanner over the hash-locked Python closures, trivy with an offline database,
gitleaks, zizmor, csp-evaluator). While the repository is public their SARIF goes to GitHub Code Scanning; while it is
private (since 2026-09-21) that upload job is skipped, because Code Scanning on a private repository needs
GitHub Advanced Security, and the SARIF is kept as a workflow artifact instead. OpenSSF Scorecard runs on every
push to `main` and weekly: through the GitHub API while public; while private as `scorecard --local` with the
locked CLI, which runs only the checks that need no API (Dangerous-Workflow, Token-Permissions,
Binary-Artifacts, Pinned-Dependencies, Security-Policy, Dependency-Update-Tool) and uploads nothing.
Dependabot keeps the SHA-pinned actions current. How each tool is
sourced, verified and what remains unverified is recorded in
[docs/tools-provenance.md](docs/tools-provenance.md). Vulnerability disclosure for a problem those
tools miss is what this file is for.

## 正體中文摘要

本檔案處理的是**本 repo 自身程式碼**的漏洞回報：請使用上方的 GitHub private vulnerability
reporting 連結，不要開公開 issue。`fixtures/vuln-sample/` 與 `calib/samples/` 是刻意種下漏洞的審查材料，
不受理。本機網頁工作台 `mara serve`（`src/mara/web/`）也在範圍內：只聽本機位址、權杖、Host／Origin／Sec-Fetch-Site 檢查、hash-based CSP 與它啟動的審查和背景工作子程序，回報時請另附瀏覽器與版本、啟動 `mara serve` 的完整指令。管線把 A 級 Critical finding 交給產品 PSIRT 的流程在 `docs/psirt-integration.md`，與本檔案無關。
回報後的處理節奏比照該文件的三個階段（預警、通報、報告），時限是內部目標而非承諾。本 repo 已於
2026-09-17 開啟 private vulnerability reporting，公開期間上方連結直接開啟私密回報表單。自 2026-09-21
repo 改為私有後，GitHub 不提供該功能、連結回應 404；此時能讀到程式碼的都是協作者，請以私訊或內部
郵件直接告知維護者（@chinchiang），不要開 issue、PR 或 discussion，由維護者建立 draft security
advisory 後依本檔案流程處理。重新公開時，先確認該設定仍為開啟。
