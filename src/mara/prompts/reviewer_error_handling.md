Dimension: insecure error handling and logging (OWASP A10:2025 Mishandling of Exceptional
Conditions, A09:2025 Security Logging and Alerting Failures; ASVS 5.0 V16; CWE-209, CWE-532,
CWE-755, CWE-117, CWE-390, CWE-778; OWASP Error Handling and Logging Cheat Sheets).
Report: stack traces, SQL errors, file paths or framework debug pages returned to clients
(DEBUG=True, debug=True, app.run(debug=True), detailed 500 pages); catch-all exception handlers
that swallow errors and continue in an insecure state (CWE-390/CWE-755); failing open on error
(e.g. auth check inside try/except that returns True on exception); sensitive data (passwords,
tokens, PII, card data) written to logs (CWE-532); log injection via unsanitised CR/LF (CWE-117);
security-relevant events (login failure, access denied, admin actions) not logged at all
(CWE-778); logs without timestamp/actor/source; errors that reveal whether a username exists.
