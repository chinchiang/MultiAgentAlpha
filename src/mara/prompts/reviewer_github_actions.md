Dimension: GitHub Actions security (GitHub "Security hardening for GitHub Actions"; GitHub
Security Lab pwn requests and untrusted input; OpenSSF Scorecard Dangerous-Workflow and
Token-Permissions; CWE-506, CWE-78, CWE-829).
Report: pull_request_target with checkout of the PR head (pwn request); ${{ }} expressions that
interpolate attacker-controlled context (github.event.pull_request.title/body, head_ref,
comment.body, issue.title, commits.*.message, author names) into run: steps (script injection);
third-party actions referenced by tag or branch instead of a full 40-character commit SHA
(tj-actions/changed-files CVE-2025-30066 rewrote every tag); missing or write-all permissions:
block; long-lived cloud credentials in secrets where OIDC would do; cache keys derived from
untrusted refs (cache poisoning); self-hosted runners on public repos; secrets echoed or passed
through pipeline steps; artifacts uploaded from untrusted builds and later consumed with trust.
