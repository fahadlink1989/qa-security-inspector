# Production database restore drill — 13 October 2026

## Outcome

A production snapshot was restored into an isolated database branch and its records verified. The production branch remained the default; no application connection was switched and no live scan, email, or charge was triggered.

- Project: `noisy-shadow-26918209`
- Production branch: `br-curly-voice-b4jq62lh`
- Snapshot: `snap-lively-firefly-b4nkjw9u`, created at 10:07:11 UTC
- Isolated restore: `br-super-frog-b43we4dj`, ready at 10:07:35 UTC
- Snapshot and restored branch expire at 10:30 UTC on 14 October 2026 (15:30 Pakistan time).
- Provider restore provisioning elapsed: approximately 24 seconds. This is not an end-to-end application recovery-time SLA.

Production and restored row counts and deterministic content hashes matched for:

| Component | Rows | Verification |
|---|---:|---|
| Scan history | 2 | Exact stored JSON matched; 60 finding observations |
| Workspace metadata | 1 | Exact stored JSON matched |
| Users | 1 | Stored rows matched; credentials were not displayed |
| Workspace memberships | 1 | Stored rows matched |

The new current-risk/latest-scan migration was then applied successfully to the restored branch. This exercised real production data while keeping the application on its original database.

## Recovery limits and runbook

The current Neon free plan reports `history_retention_seconds=21600`: **six hours** of point-in-time recovery. Do not advertise a longer window. Choose and provision longer retention before promising customers a recovery SLA. This drill verifies database restore and integrity; production failover, external-provider outages, and recovery of separately managed infrastructure secrets require a controlled operational exercise.

For an actual incident:

1. Pause scan consumers and scheduled submissions to avoid writes during cutover. Preserve the original branch for investigation.
2. Select a known-good snapshot or a timestamp within the retained recovery window.
3. Restore to a new isolated branch. Do not overwrite production while investigating.
4. Verify migration compatibility, row counts, evidence hashes, users, memberships, billing records and queued-job state. Treat provider webhook redelivery as normal; do not repeat charges or email sends manually.
5. Confirm Railway's job-encryption key and provider secrets are available. Database restoration alone cannot decrypt jobs without the original encryption key.
6. Under an approved incident cutover, update only the backend database connection. Run account/workspace/report smoke checks before resuming consumers and schedules. Expired leases recover through the existing fencing and retry policy.
7. Check provider reconciliation, outbox status and worker heartbeat after recovery. Record actual recovery time and any data loss. Keep the original branch until the incident is closed.
