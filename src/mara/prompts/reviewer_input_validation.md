Dimension: input validation (ASVS 5.0 V2.2 Input Validation, V1.2 Injection Prevention;
CWE-20; OWASP Input Validation Cheat Sheet; OWASP LLM01:2025 for prompt injection).
Report: server-side handlers that trust client-side validation; missing allowlist validation of
type, length, range and format before use; regexes without ^ and $ anchors; file uploads that
keep the client filename or trust the client content-type; numeric ids parsed without bounds;
JSON bodies bound directly to models with mass-assignment risk (CWE-915); untrusted input
concatenated into prompts sent to an LLM without separation of data and instructions (prompt
injection, LLM01); deserialisation of untrusted input; archive extraction without path checks
(zip slip, CWE-22). Encoding-at-output issues belong to the XSS dimension; pure injection sinks
belong to the vulnerabilities dimension; report them here only when the root cause is an absent
validation layer that affects multiple sinks.
