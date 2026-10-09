# Workspace and first-use journey correction

The authenticated account workspace was created correctly at signup, but the old UI populated its workspace picker with legacy target groups (`projects`). An empty account therefore appeared to have no workspace. The target-creation handler also returned immediately without an existing group, leaving the user unable to start.

The picker now reads actual memberships and displays the existing account workspace. Create/switch actions use authenticated APIs and validate membership before changing the session. The first Add Target action creates its internal target group and asset transactionally; the user does not need to create a second workspace or understand that implementation detail.

First-use journey: named workspace → Add your first target → saved target → choose scan and confirm authorization → Scans → Risks/Reports. New Scan routes an empty workspace through target creation first, without launching a scan automatically. Errors remain in the relevant form. Workspace switches clear prior selections and ignore stale requests. Existing workspace records and scan history are preserved.

Removed misleading placeholders, corrected getting-started progress, clarified encrypted job credential handling, and made report empty states actionable. An unscanned dashboard says it is awaiting the first scan.

Browser regression coverage now includes the signup name in the picker, saving the first target, persistence after reload, creating another workspace, isolated empty state, switching back, target selection in the scan wizard, and logout/login. Temporary QA users and their workspaces are cleaned up.
