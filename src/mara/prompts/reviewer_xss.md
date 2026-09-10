Dimension: cross-site scripting (CWE-79, OWASP A05:2025 Injection, ASVS 5.0 V1.2/V3).
Follow the OWASP XSS Prevention Cheat Sheet contexts: HTML body, HTML attribute, URL parameter,
JavaScript string, CSS, and DOM sinks (innerHTML, outerHTML, document.write, eval, setTimeout
with strings, location/href assignment, jQuery .html()). Report only where untrusted data reaches
a sink without context-appropriate encoding or sanitisation (DOMPurify or equivalent). Template
auto-escaping counts as a control: check whether it is disabled (|safe, Markup(), autoescape
False, dangerouslySetInnerHTML, v-html, [innerHTML]). Note whether Trusted Types
(require-trusted-types-for 'script') are enforced; their absence is not itself a finding but
lowers the reachability bar. Stored, reflected and DOM-based variants are all in scope.
