# Backend foundation

The Vercel frontend uses a same-origin `/api/*` rewrite to the Railway backend. Database credentials and scanner secrets exist only in Railway environment variables. Railway runs the API, a continuously polling job consumer, and separately isolated scanner engines. Neon PostgreSQL is the source of truth.

## Storage and isolation

Users, password hashes, sessions, workspace memberships, job leases, encrypted job payloads, scheduling deduplication keys and worker heartbeats have dedicated SQL tables. Project/asset/finding documents remain in a JSONB document per workspace during this migration. Mutations lock the workspace row in a transaction and increment its revision, preventing lost updates. This is transactional document storage, not a fully normalized relational findings model.

Every product API resolves a hashed, expiring session token to membership and establishes a server-only workspace context. Request project IDs never determine the workspace. Viewer accounts cannot mutate data. Cookie sessions are HttpOnly, Secure in production, SameSite=Lax, expire in seven days and are revoked on logout. Mutating browser requests require an explicitly allowed Origin. Passwords use salted scrypt. Login/register attempts are rate-limited in PostgreSQL.

New accounts create empty, isolated workspaces. Legacy shared Blob data is not assigned to newly registered users. No automatic production data deletion or shared-data ownership claim occurs.

## Durable jobs

Scan submission commits an encrypted payload and a queued job before returning HTTP 202. Consumers claim using `FOR UPDATE SKIP LOCKED`, with 90-second leases refreshed every 20 seconds. Expired leases are reclaimed, failures retry up to three attempts, and credentials are erased after terminal completion/failure. AES-256-GCM binds ciphertext to both workspace and job IDs.

Result writes check the current lease inside the storage transaction. Stable job-derived scan IDs prevent duplicate saved results when a process stops between saving results and acknowledging completion. Delivery is at least once; scanner execution itself may repeat after a crash. Retests also use the queue. Scheduling uses explicit authorization, UTC day/week slots and a unique workspace/target/slot deduplication key.

## Scanner deployment

The engine container runs as a non-root user on Railway private networking. Requests require an HMAC and recent timestamp. ZAP is a separate private daemon, with API key, bounded crawling, form submission disabled and a fresh session per scan. Nuclei uses two reviewed read-only HTTP templates in this repository; it does not run the full community CVE collection. Trivy and Gitleaks perform repository analysis. Gitleaks output is redacted. Missing/failed engine coverage is reported as a gap, never a clean result.

Private network scans remain disabled on this public deployment. OpenVAS needs a separately deployed Greenbone adapter in the customer's authorized network. Do not enable ALLOW_PRIVATE_TARGETS on the public worker to bypass this restriction.

## Operations and verification

`backend/start.mjs` applies additive migrations under a PostgreSQL advisory lock, starts Next.js, then starts the queue consumer and minute scheduler. `/api/health` verifies database access. `/api/internal/tick` requires a separate worker credential.

`VERIFY_BACKEND=1` runs the integration checks in `backend/verify.mjs`; `RUN_REAL_SCAN=1` additionally scans the owner's Inspector URL and checks report persistence and actual ZAP execution. Temporary QA accounts, projects and jobs are removed in `finally`. Disable these flags after verification. `node --test tests/risk-model.test.mjs` checks risk lifecycle behavior.

Secrets: DATABASE_URL, JOB_ENCRYPTION_KEY (32 random bytes, base64), INTERNAL_WORKER_SECRET, SCANNER_WORKER_SECRET and ZAP_API_KEY. Rotate encryption keys only after draining encrypted pending jobs or implement key versioning first.

Remaining commercial account features: verified email delivery/password recovery, invitations, account MFA/SSO, billing quotas, and richer audit administration. They are not represented as implemented.
