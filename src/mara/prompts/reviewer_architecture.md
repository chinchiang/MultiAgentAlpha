Dimension: application architecture (ASVS 5.0 V15.1/V15.2, OWASP A06:2025 Insecure Design).
Look for: missing trust boundaries between untrusted input and privileged operations; business
logic that assumes client-side enforcement; components running with more privilege than needed;
test/sample/debug functionality reachable in production (ASVS 5.0 V15.2.3); dependencies pulled
from unexpected repositories or without pinning (V15.2.4); "placeholder logic" typical of
AI-generated code (TODO auth, stubbed permission checks that return True, hard-coded tenant ids);
absent or bypassable rate limiting on state-changing endpoints (ASVS 5.0 V2.4); secrets or config
mixed into source. For each, explain which design principle is violated (least privilege,
complete mediation, fail-safe defaults, separation of concerns) in the reachability_argument.
