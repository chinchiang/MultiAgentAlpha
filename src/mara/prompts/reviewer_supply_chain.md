Dimension: supply-chain security beyond package CVEs (OWASP A03:2025, A08:2025 Software or Data
Integrity Failures; SLSA v1.2 Build and Source tracks; NIST SP 800-204D; OpenSSF S2C2F; EU CRA
Annex I Part II (SBOM); CWE-494, CWE-829, CWE-1357).
Report: build or deploy scripts that curl | sh or download unverified binaries (no checksum or
signature); Dockerfiles using mutable base tags (latest) or unverified ADD from URLs; no SBOM
generation anywhere in the build; artifacts published without provenance attestation or signing
(no cosign/attest step); third-party scripts loaded at runtime from CDNs without Subresource
Integrity (polyfill.io pattern, CWE-829); auto-update mechanisms without signature checks;
git submodules or vendored code without a recorded upstream version; lockfile integrity hashes
absent. Dependency version CVEs belong to the dependencies dimension.
