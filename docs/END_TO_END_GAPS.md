# Inspector functionality audit — 2026-10-09

Compared the six supplied HostedScan screenshots with main at 9e04799.

| Function | Evidence / implementation | Remaining work |
|---|---|---|
| Onboarding | Intent modal and workspace creation exist | Persist onboarding progress per user |
| Dashboard | Aggregates stored scan findings | Tenant-specific access, coverage-aware health score |
| Targets | Create/edit/remove and scan entry points | Asset relationships, scope verification, full target history |
| New Scan | Web/deep/auth/code modes and authorization confirmation | Multi-target jobs, engine selection and profiles |
| Scans | Persisted job records, status polling and progress | Durable queue, leases, cancellation and recovery |
| Risks | Shared target/type-scoped selection, code status controls, lifecycle timestamps | Ownership, audit actors, all-engine retest orchestration |
| Reports | HTML/PDF/CSV use shared risk selection; exports no longer truncate at 200/30 findings | Saved reports, scan-specific and target filters, scheduled reports |
| Worker engines | HMAC worker routes and health capability flags | Provision workers; verify each engine against authorized fixtures |
| Persistence | Versioned whole-workspace private Blob snapshots | Transactional database: concurrent mutations can overwrite changes; reads stop after 1000 blobs |
| Authentication | No application-level tenant authentication found in audited routes | Required before commercial multi-user release |
| Scheduling | Daily cron with project schedules | Per-target scheduling, timezone, retries, due-job deduplication |

## Changes in this increment
- Shared risk selection covers each auth target and repository; web/deep scan scopes remain distinct.
- Findings with identical fingerprints on different targets no longer collapse.
- Code risks support workflow status updates; status changes record transition history.
- Carry workflow history and first/last seen through web, auth and code reruns. Reopen resolved findings when detected again.
- Preserve scanner metadata during normalization, including CVE/CVSS/CWE and references.
- Retest absence with failed/skipped/partial coverage is inconclusive, never a verified fix.
- Record retest outcome and mark original finding resolved only after complete coverage.
- Reports use the same selection as Risks, include all selected findings, and escape spreadsheet formula prefixes.
- Engine Settings use individual advertised capabilities instead of treating worker connectivity as all engines being available.

## Verification
- `npm run build` passes.
- `node tests/risk-model.test.mjs` checks target isolation, scan mode isolation, multiple repositories/auth targets, inconclusive retests, workflow validation, rescan status continuity and reopening.
- These fixtures are tests only. No demonstration findings were added to product data.
- Production end-to-end execution remains unverified: Vercel connector returns 403 for pr-testing.
- Railway project listing returned no projects; Neon Inspector project search returned none. No infrastructure provisioned by this increment.

## Required next release
1. Provision transactional storage, migrate existing records without deleting newly collected results, verify concurrent updates.
2. Introduce workspace membership and authenticated API access.
3. Provision isolated engines and durable job execution with recovery.
4. Verify add target → authorized scan → stored findings → status change → rescan → matching report, then deploy.
