# Production provider setup and launch gates

The backend integrations are implemented, but configuring a provider is not the same as verifying a real transaction. Never label live delivery, payment, or PageSpeed verified based only on mocked tests.

## No-terminal setup

Open Railway → Inspector project → inspector-backend → Variables. Add the variables below through the dashboard and deploy the staged configuration. Do not put secret keys in GitHub source, NEXT_PUBLIC variables, screenshots, or chat. The application only exposes configuration booleans and delivery/subscription status.

### Email (Resend)

1. In Resend, add a sending domain and complete its DNS verification. Choose a verified sender address.
2. Create a sending API key. Configure `RESEND_API_KEY`, `EMAIL_FROM` (for example, `Inspector <security@your-verified-domain>`), and `APP_PUBLIC_URL=https://qa-security-inspector.vercel.app` on the Railway backend.
3. In Resend, create a webhook to `https://qa-security-inspector.vercel.app/api/email/webhook` for `email.delivered`, `email.bounced`, `email.complained`, and `email.failed`. Save its signing secret as `RESEND_WEBHOOK_SECRET`.
4. From Inspector Settings, explicitly invite a controlled test inbox using “Send invitation by email.” Verify that Settings changes from queued to accepted to delivered. Accept the email invitation. Test Forgot password → Send a password reset email, reset once, and verify that reusing the link fails.

Email is optional on invitation creation: a manual link remains available. Password-reset links expire in 30 minutes and are single use. Recovery codes remain available. Outbox contents are encrypted, then erased after provider acceptance or permanent failure. Retry keys are stable; automatic retries stop before the provider's 24-hour deduplication window. “Accepted” does not mean inbox delivery. Delivery events have verified signatures and duplicate-event protection.

### Billing (Stripe)

1. Start in Stripe test mode. Create a recurring price for the commercial plan you have chosen; no price is assumed by this release. Enable the Stripe customer portal.
2. Set `STRIPE_SECRET_KEY`, `STRIPE_PRICE_ID`, and a positive integer `STRIPE_MONTHLY_SCAN_LIMIT` on the backend.
3. Add a webhook endpoint `https://qa-security-inspector.vercel.app/api/billing/webhook`. Subscribe to `checkout.session.completed`, `checkout.session.async_payment_succeeded`, `checkout.session.async_payment_failed`, `customer.subscription.created`, `customer.subscription.updated`, `customer.subscription.deleted`, `invoice.paid`, and `invoice.payment_failed`. Set `STRIPE_WEBHOOK_SECRET` to that endpoint's signing secret.
4. In Inspector Settings → Billing, complete a test checkout. Verify active status, the customer portal, cancellation, and a failed-payment case. Resend an event from Stripe and verify that it does not create a second event or revert current subscription state.
5. Only after review, configure the corresponding live key, live recurring price, and live webhook secret. Set `BILLING_ENFORCED=1` when ready to require subscriptions. Existing workspaces are not silently grandfathered; enabling enforcement applies to all new scan submissions. Results and reports stay readable.

The price comes from Stripe. Subscription status is reconciled directly with Stripe; the checkout return URL never grants access. One submitted job counts against the calendar-month UTC allowance, including failed submissions that reached the queue; automatic retries do not add usage. Daily/weekly scheduled jobs use the same entitlement checks. Billing enforcement defaults off during setup. Changing an existing price requires a planned subscription migration; this release supports one configured recurring offering.

### Google PageSpeed Insights

1. In Google Cloud, enable the PageSpeed Insights API and create an API key with the appropriate API restriction. Confirm billing/quota settings in your Google project.
2. In Inspector's Performance settings, save the key (encrypted per workspace), or set backend `PAGESPEED_API_KEY` for a platform-wide key.
3. From a target you own, select Mobile & desktop speed and authorize sending its public URL to Google.
4. Settings → Performance & storage must show completed mobile **and** desktop measurements. A 429, timeout, or only one completed device is not a successful verification.

On October 13, 2026, the deployed backend had no email/Stripe/PageSpeed environment configuration, and the existing workspace had no PageSpeed key. Direct mobile and desktop provider checks both returned HTTP 429 RESOURCE_EXHAUSTED. These live provider gates remain open until configuration and successful real verification.

## Storage, load and recovery

`002_commercial.sql` atomically backfills all five scan types into `inspector_scan_history`, indexes workspace/time/target/project, and removes the duplicated arrays from workspace metadata. Evidence is not deleted. Changed scan records are upserted individually. The authenticated `/api/history` endpoint uses bounded cursor pages and fetches complete evidence on demand. Active workspace readers now load 25 recent results plus latest results per target/profile. A transactional current-risk index retains older findings independently of the recent history window. Scan workers use metadata and exact/latest scan lookups; workflow updates operate in SQL, and reports fetch a selected historical scan directly or use current risks. No active application path loads the entire scan archive into JavaScript. Capacity still depends on current assets/findings and evidence size; this is not an unlimited-capacity claim.

CI uses an isolated PostgreSQL 17 service, never the production database. It tests concurrent quota enforcement, exclusive job claiming, expired-lease recovery, stale-write rejection, retry exhaustion, transaction rollback, 3,000 evidence records, 50 concurrent bounded history reads, and exact evidence export/restore into another test workspace. Timings appear in CI logs. This measures database paths, not scanner throughput or a production disaster-recovery SLA. An isolated restore of a real production snapshot passed on October 13; see RECOVERY_DRILL_2026-10-13.md. Production traffic cutover and external engine saturation testing are separate operational exercises.

Schema changes and frontend/backend must be released together. Rolling the backend back to a version predating history hydration requires a data-compatible rollback migration; do not deploy old code against compacted workspace state. Existing scan records remain in the history table and can be exported. Before a major release, confirm the managed database's backup retention and rehearse restore into an isolated environment.
