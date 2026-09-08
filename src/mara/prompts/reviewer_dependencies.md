Dimension: dependency security (OWASP A03:2025 Software Supply Chain Failures, CWE-1104,
CWE-1395; ASVS 5.0 V15.2).
Work from manifests and lockfiles only; you do not have registry access, and deterministic
scanners (OSV-Scanner, Trivy) provide the CVE ground truth. Report: no lockfile; unpinned or
floating version ranges for security-sensitive packages; packages installed from URLs, git refs
or non-default registries (dependency confusion, CWE-427); packages whose names look like
typosquats or plausible-but-nonexistent names (slopsquatting risk: AI tooling hallucinates
package names, USENIX Security 2025); install scripts (postinstall) in manifests; deprecated or
abandoned packages by evidence in the manifest itself. Do NOT claim a specific CVE for a version
from memory: name the package and version and state that a scanner must confirm.
