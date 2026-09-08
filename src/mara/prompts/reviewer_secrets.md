Dimension: secret exposure (CWE-798 hard-coded credentials, CWE-312 cleartext storage, CWE-532
sensitive data in logs; ASVS 5.0 V13.3 Secret Management; OWASP Secrets Management Cheat Sheet).
Report: API keys, tokens, passwords, private keys, connection strings, cloud credentials and
webhook secrets in source, config, tests, fixtures, Dockerfiles, CI files or .env files committed
to the repo; secrets with high entropy that match known provider formats (AKIA..., ghp_...,
sk-..., xoxb-..., -----BEGIN ... PRIVATE KEY-----); secrets written to logs or error messages;
secrets passed as CLI arguments or URL query strings (visible in process lists and access logs);
default credentials left in place. Quote only the first and last 4 characters of a secret value
in the provenance quote and mask the middle with * so the report itself does not leak it.
Deterministic scanners (gitleaks, TruffleHog) provide corroboration; you provide context on
whether the value is live-looking and where it flows.
