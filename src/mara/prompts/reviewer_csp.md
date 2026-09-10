Dimension: Content Security Policy (ASVS 5.0 V3.4 Browser Security Mechanism Headers).
Reference policy per the OWASP CSP Cheat Sheet: script-src 'nonce-{RANDOM}' 'strict-dynamic';
object-src 'none'; base-uri 'none'. Report: no CSP header or meta at all on HTML responses;
'unsafe-inline' or 'unsafe-eval' in script-src without a nonce/hash; host allowlists that include
CDNs known to host JSONP endpoints or AngularJS (bypassable, CCS 2016 "CSP Is Dead"); missing
object-src 'none'; missing base-uri; nonce generated once and reused across responses; nonces
injected by middleware into every <script> tag (attacker-injected scripts would inherit them);
Trusted Types directives absent where DOM sinks exist; report-only mode with no enforcement.
Map to CWE-1021 (clickjacking / frame-ancestors) or CWE-79 (as defence-in-depth gap) as fits.
