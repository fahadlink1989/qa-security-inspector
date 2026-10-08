// Scope findings to their target and scanner profile so one scan cannot erase another.
export function currentScanRecords(state, project) {
  const records = [
    ...(state.scans || []).filter(s => s.projectId === project.id),
    ...(project.authScans || []).map(s => ({...s, kind:'auth'})),
    ...(project.codeScans || []).map(s => ({...s, kind:'code'})),
    ...(project.networkScans || []).map(s => ({...s, kind:'network'}))
  ].sort((a,b) => String(b.completedAt || b.scannedAt || b.startedAt || '').localeCompare(String(a.completedAt || a.scannedAt || a.startedAt || '')));
  const latest = new Map();
  for (const s of records) {
    const key = [s.kind || 'web', s.assetId || s.networkTargetId || s.repository?.url || s.url || s.target || s.id, s.mode || s.type || 'standard'].join('|');
    if (!latest.has(key)) latest.set(key,s);
  }
  return [...latest.values()];
}
export function currentRiskRows(state, project) {
  const unique = new Map();
  for (const scan of currentScanRecords(state,project)) {
    for (const finding of scan.findings || []) {
      const key = [scan.assetId || scan.networkTargetId || scan.repository?.url || scan.url || scan.target || scan.id, finding.fingerprint || finding.id].join('|');
      if (!unique.has(key)) unique.set(key, {...finding, _scan:scan, _scanId:scan.id, _kind:scan.kind || 'web'});
    }
  }
  return [...unique.values()];
}
export function filterReportRows(rows, filters={}) {
  return rows.filter(f => (!filters.scanId || f._scanId === filters.scanId) &&
    (!filters.assetId || f._scan?.assetId === filters.assetId) &&
    (!filters.severity || f.severity === filters.severity) &&
    (!filters.status || (f.workflowStatus || 'open') === filters.status));
}
export function updateRiskInState(state, scanId, fingerprint, patch) {
  const scans = [...(state.scans || []), ...state.projects.flatMap(p => [...(p.authScans || []), ...(p.codeScans || []), ...(p.networkScans || [])])];
  const scan = scans.find(s => s.id === scanId);
  const finding = scan?.findings?.find(f => (f.fingerprint || f.id) === fingerprint);
  if (!finding) throw new Error('Finding not found.');
  const statuses = ['open','in_progress','resolved','accepted','false_positive'];
  if (patch.status && !statuses.includes(patch.status)) throw new Error('Invalid finding status.');
  const at = new Date().toISOString();
  const history = [...(finding.actionHistory || []), {at, status:patch.status || finding.workflowStatus || 'open', owner:String(patch.owner ?? finding.owner ?? '').slice(0,120)}].slice(-50);
  // Apply the workflow to matching observations of the same target across profiles.
  for (const record of scans.filter(s => s.projectId === scan.projectId && (s.assetId || s.networkTargetId || s.repository?.url || s.id) === (scan.assetId || scan.networkTargetId || scan.repository?.url || scan.id))) {
    for (const f of record.findings || []) if ((f.fingerprint || f.id) === fingerprint) {
      if (patch.status) f.workflowStatus = patch.status;
      if (patch.owner !== undefined) f.owner = String(patch.owner).slice(0,120);
      f.statusUpdatedAt = at; f.actionHistory = history;
    }
  }
  return finding;
}
