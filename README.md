# Inspector — Security + UX QA MVP

A non-destructive web assurance scanner designed for authorized targets only.

## MVP coverage
- Security response headers and basic cookie attributes
- CORS red-flag check
- Technology banner exposure
- HTML semantics, title, language and viewport
- Basic image-alt, form-label and button-name signals
- Small sample of same-host internal links
- Normalized findings with severity, confidence, evidence and remediation
- Local scan history in the browser
- SSRF guard that rejects private/loopback/local targets and re-checks redirect destinations

This MVP intentionally does not exploit vulnerabilities, fuzz authentication, brute force, mutate application state, or scan private networks.
