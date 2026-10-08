# Inspector product audit — 8 October 2026

Baseline: main commit `30f28c1`. Compared all six supplied HostedScan screenshots against the repository source. Inspector keeps its own branding. Screenshot times identify the reference, not a claim that hidden HostedScan backend behavior was tested.

| Reference / function | Before | Changes in this branch | Remaining work |
|---|---|---|---|
| 4:26:06 onboarding | Local goal preference, Continue only navigated | Continue opens selected scan profile; users without a workspace get workspace creation | Server-side user onboarding/preferences |
| 4:32:41 dashboard | Risk cards, score, recent scans/risks | Zero scores retained; aggregation preserves findings across scanner profiles and scopes fingerprints by target | Durable running jobs and operational health monitoring |
| 4:32:53 targets | Add/list, last scanned, start scan | Target drawer, label editing, remove from future scans, per-target history, observed subdomain relationships, duplicate URL rejection | Editable URL requires a new target to preserve evidence; search/pagination and asset ownership verification |
| 4:33:22 risks | Drawer and web/auth/network workflow; code workflow absent | Unified status/owner API for all types, owner/history/verification UI, CVE/CVSS/CWE display when supplied, first/last seen preservation | Dedicated retest adapters for code/auth/network; organization roles and tenant isolation |
| 4:33:31 scans | Web background jobs, synchronous other types | Unified queue/status for web/auth/code/network, failed jobs visible, details drawer and historical scan report link, selectable external web engines | Durable queue/recovery, cancellation, full engine-level progress; non-web progress currently marks execution stages rather than measurable engine percentages |
| 4:33:49 reports | Downloads existed; undefined variable caused runtime failure; sections unwired | Fixed generation, target/severity/status filters, all/security/technical modes, PDF/CSV/HTML, evidence export, scan-specific historical reports, CSV formula protection | Scheduled delivery, fully configurable section checkboxes, multilingual PDF font embedding |
| New Scan (requested; modal not visible in attached screenshots) | Type selection and authorization, one target | Multiple web targets, real selected-engine dispatch, unavailable engines disabled, daily/weekly profile and target selection | Arbitrary schedule/timezone profiles; durable multi-target execution; external code/network engine selection |
| Settings / scanner architecture | Names marked Connected from worker URL configuration alone | Reachability/capability status and binary checks; external names cannot masquerade as installed engines | Deploy isolated workers, configure ZAP and a real Greenbone adapter, test each external engine and commercial licensing |
| Remediation | Rule/AI plans, partial guidance display | Ownership, verification, evidence references; ungrounded AI action references filtered; incomplete web retest cannot claim resolution | Engineering ticket integration and measured fix verification for each external engine |

## Validation

- `npm run build`: passed.
- `npm test`: 15 regression tests passed for risk scope/workflow, reports, AI evidence references, scan API validation and job lifecycle/credential non-persistence.
- Chromium browser journey with API fixtures: target edit/history/relationships, scan details, risk ownership, report filtering and disabled unavailable engines; passed with no browser page errors. This verifies UI wiring, not live scanner execution or production storage.
- Worker server syntax checked.
- No scans against third-party targets were run during this audit.

## Infrastructure and release blockers

Production `/api/engine-status` reports no scanner worker URL/secret configured. External scanner adapters in source are not live integrations until isolated workers and their backing services are provisioned and tested. Greenbone is currently an HTTP adapter boundary, not a bundled implemented Greenbone service.

The current store uses whole-workspace versioned Blob snapshots. It does not provide cross-instance transactions, customer authentication, authorization/tenant isolation, or durable job leasing. Concurrent writes can overwrite one another. Background jobs are bounded by Vercel function lifetime; a long batch can stop before all targets finish. Credentials held only in memory cannot resume after process failure. These need a transactional database and a durable queue/worker service before selling a multi-customer platform.

Cron is a basic daily dispatcher with limits of two projects and two assets per project; it is not a complete commercial scheduler. Existing schedules now need explicit authorization in New Scan. Scheduled reports are labelled planned rather than displayed as a working tab.

The connected Vercel project lookup returned a `pr-testing` project with domains different from `qa-security-inspector.vercel.app` and a failed latest deployment. Deployment log access returned 403 for that scope. CLI fallback had no saved credentials. Production release and production scan/storage QA were therefore not performed. Resolve project/team access and domain mapping before release.
