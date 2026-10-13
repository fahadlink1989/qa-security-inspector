# Customer workflow release — 2026-10-13

This release addresses correctness and customer lifecycle. It is not a declaration of enterprise readiness.

## Customer value

- One risk per fingerprint and target across standard/deep scan profiles. Different authentication contexts and different targets stay distinct.
- Findings absent from a later scan remain visible with their last observed evidence. Only a reviewed workflow decision or complete explicit retest closes them.
- Resolved findings observed again reopen with a recorded event. Owner, notes, first seen and earlier decisions carry forward even across a scan with no matching observation.
- Scan writers no longer silently discard older web, authenticated, repository, network or performance results. Previously pruned records cannot be recovered by this release.
- Dashboard, Scans and Risks include all target groups in the current workspace. Reports and target configuration remain scoped to the selected group.
- Repository-only users can start without supplying an unrelated website.
- Owners can invite members/viewers by a one-use email-bound link, change non-owner roles, revoke invitations and remove members. Access changes are recorded. Removed members lose workspace sessions.
- Registration and invitation onboarding display a random recovery code once. Existing users generate a replacement in Settings after confirming their password. Codes are hashed, single use and rotated explicitly. Password reset/change revokes sessions.
- Login, recovery and account settings have responsive layouts and explicit loading/error states.
- Webhook requests use public HTTPS destinations, validate all resolved addresses and pin the selected address to prevent DNS rebinding; redirects are not followed. Delivery outcome is visible in scan details. Scanner confidence defaults to “Not supplied” rather than claiming high confidence.
- Opening a historical PageSpeed scan selects that exact measurement.

## Operating details

Schema additions are backward compatible and applied by the existing backend startup migration transaction. No existing customer records are deleted. The Vercel frontend forwards API requests to the Railway backend, so both must be released.

Invitation delivery is manual: the owner shares the generated link with the invited person. Inspector does not claim an email was sent. Recovery is code-based; automated email recovery and mailbox verification require a transactional mail provider and further integration. Do not promise email recovery to users who have not saved a code.

History remains stored in transactional workspace JSON. Removing silent truncation prevents further loss but does not deliver scalable archival/pagination. A separate immutable observation store and paginated retrieval remain necessary before high-volume usage. Restored or previously pruned history is not fabricated.

## Verification

- `node --test tests/*.test.mjs`: risk identity, lifecycle, coverage, public-address policy and PageSpeed normalization regression checks.
- `tests/account-journey.mjs`: run ONLY against an isolated QA server/database; covers registration, invitations, member/viewer authorization, tenant isolation, removal, recovery replay/rotation and session revocation.
- `tests/browser-journey.mjs`: isolated browser flow for signup, saved recovery code, repository-only wizard, Settings/invitation, sign-out and mobile layout.
- `npm run build`: production build, including new team API and account screens.

The local API suite uses a PostgreSQL-compatible PGlite database, not production data. It does not establish production concurrency or disaster-recovery behavior.

## Remaining commercial gates

- Transactional email verification/recovery, notification delivery and monitored failures.
- Scalable historical storage, defined retention/export policy and tested restoration.
- Load-tested queue capacity and engine isolation, independent security assessment and benchmark detection/false-positive evaluation.
- Successful PageSpeed mobile/desktop run with a configured provider key/quota.
- Billing, entitlements, terms/privacy/support journey and pilot feedback.

Sell only against validated scope. No scan proves the absence of vulnerabilities, and this release does not turn reviewed passive checks into a comprehensive penetration test.
