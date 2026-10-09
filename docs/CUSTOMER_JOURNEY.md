# Customer journey release

| Area | Gap found | Implemented |
|---|---|---|
| Navigation | Scanner-specific destination | Six main destinations; internal network configuration in Settings |
| Dashboard | Zero findings could imply safety | Next action, target coverage, unscanned and incomplete counts; score excludes incomplete results |
| Targets | Nonfunctional expansion affordance | Target details with scan history and current risk navigation |
| Scans | No inspectable result | Scan details, engine execution, gaps, timestamps and scan-specific PDF |
| Scan selection | Unsupported network option looked usable | Unavailable profile disabled; scope and live engine availability explained |
| Risks | No owner or engineering notes | Transactional owner/notes, history, cross-rescan persistence and search |
| Verification | Closed retest could disappear | Explicitly closed records retained for audit; manual vs verified resolution copy |
| Reports | Score and scope misleading | Selected scan export, point-in-time coverage limitations, complete remediation text |

Verification: production build, pure lifecycle regression checks, browser signup/workspace isolation and authorized real scan journey; report exports checked via authenticated requests.

Remaining capabilities are not represented as complete: private network deployment, email/invitations/MFA/recovery, scheduled report delivery, fully configurable scan policies. Ownership is a persisted label, not a notification or member assignment. Current UI scope is the selected target group. No third-party target was scanned for QA.
