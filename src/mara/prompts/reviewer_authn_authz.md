Dimension: authentication and authorization (ASVS 5.0 V6 Authentication, V7 Session Management,
V8 Authorization, V9 Self-contained Tokens, V10 OAuth/OIDC; OWASP A01:2025, A07:2025;
OWASP API1:2023 BOLA, API5:2023 BFLA; NIST SP 800-63-4).
Report: endpoints that read/modify a resource by an id from the request without a per-object
ownership check (BOLA/IDOR, CWE-639/CWE-862); admin or function-level checks missing or done
client-side (CWE-285); default-allow authorization; passwords stored without a slow salted hash
(CWE-916); missing brute-force protection on login (CWE-307); session tokens predictable, not
rotated on login, without Secure/HttpOnly/SameSite (CWE-384/CWE-614); JWTs with alg none, shared
HMAC secret in code, or no expiry validation (CWE-347); OAuth without PKCE or with loose redirect
URI matching. Deny-by-default and validate-on-every-request are the controls to look for.
