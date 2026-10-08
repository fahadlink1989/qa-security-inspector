# Inspector open-source scanner stack

Inspector is the product/orchestration layer. Scanner binaries run in isolated workers and return normalized evidence.

## Recommended engines

| Engine | Role | Default Inspector profile | Licensing note |
| --- | --- | --- | --- |
| OWASP ZAP | Web DAST and passive baseline | `safe` uses Baseline / API safe mode | Apache-2.0 |
| Nuclei | Vulnerability, exposure and misconfiguration validation | Rate-limited safe templates; intrusive/DoS/fuzz/bruteforce classes excluded by default | MIT |
| Greenbone / OpenVAS | Network vulnerability assessment | Separate opt-in network worker | GPL-2.0 / GPL-2.0+ components |
| Playwright + axe-core | Browser QA and accessibility | Built into Inspector | Playwright Apache-2.0 |
| Trivy | Dependencies, containers, IaC and filesystem vulnerabilities | Repository/container worker | Apache-2.0 |
| Gitleaks | Secret detection in repositories | Repository worker; never return raw secret values | MIT |

Nmap is intentionally not a default embedded engine. Its NPSL has commercial-product restrictions and Nmap offers a separate OEM license. Get licensing advice before embedding or redistributing it.

## Production architecture

```
Customer browser
     |
     v
Inspector web app / API
     |
     +--> Postgres / object storage
     |
     +--> job queue
            |
            +--> web worker: ZAP + Nuclei + Playwright
            |
            +--> network worker: OpenVAS / Greenbone
            |
            +--> code worker: Trivy + Gitleaks
```

The web application must never execute scanner binaries directly. Workers run in isolated containers with CPU/memory/time limits.

## Worker contract

Inspector signs every worker request with:

- `x-inspector-timestamp`
- `x-inspector-signature = HMAC_SHA256(secret, timestamp + "." + rawBody)`

Endpoint:

`POST /v1/scan`

Body:

```json
{
  "version": 1,
  "jobId": "uuid",
  "engine": "zap",
  "profile": "safe",
  "target": "https://example.com/",
  "metadata": {}
}
```

Workers must reject:

- requests with invalid or stale signatures;
- unsupported engines/profiles;
- localhost, RFC1918, link-local, metadata-service and other private/reserved destinations unless running a separately authorized internal-network agent;
- arbitrary customer-provided CLI flags or templates;
- redirects to blocked address space.

## Safe web profile

### ZAP
Use the Baseline scan for the default public-web profile. It spiders the target and performs passive analysis. Active API scans must be a separate explicit option.

### Nuclei
Use a fixed server-side template allowlist and fixed limits. Do not allow users to upload or select arbitrary templates in the SaaS UI. Exclude fuzzing, brute force, DoS and intrusive classes from the default profile.

### OpenVAS
Run only in a dedicated worker with target ownership confirmation and per-customer concurrency limits. Internal scanning should use a customer-deployed agent rather than routing private networks through the SaaS control plane.

## Result normalization

Every engine result should be transformed to Inspector's common finding schema:

```
fingerprint
engine
checkId
category
severity
title
summary
impact
evidence
affectedLocations
remediation
confidence
evidenceQuality
workflowStatus
firstSeen
lastSeen
```

Raw scanner reports should be retained as evidence objects, while the customer UI works from the normalized schema.

## Commercialization

Before shipping third-party binaries, maintain a software bill of materials and legal review of the exact versions/licenses you deploy. Keep upstream names in technical attribution, but market the product as Inspector rather than implying endorsement by scanner projects.
