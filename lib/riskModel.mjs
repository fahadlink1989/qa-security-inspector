const rank = {Critical:5,High:4,Medium:3,Low:2,Informational:1};
export const workflowStatuses = ['open','in_progress','resolved','accepted','false_positive'];
export function scanScope(scan, kind='web') {
  return JSON.stringify([kind,scan.projectId,scan.assetId||scan.networkTargetId||scan.repositoryUrl||scan.repository||scan.url,kind==='web'?scan.mode||'standard':kind==='auth'?scan.auth?.method:'']);
}
export function currentRiskRows(scans, project) {
  const groups = [
    ['web',scans||[]],['auth',project?.authScans||[]],
    ['code',project?.codeScans||[]],['network',project?.networkScans||[]]
  ];
  const rows=[];
  for(const [kind, history] of groups){
    const latest=new Map();
    for(const scan of [...history].sort((a,b)=>String(b.completedAt||b.scannedAt||b.startedAt||'').localeCompare(String(a.completedAt||a.scannedAt||a.startedAt||'')))){
      if(scan.status==='failed') continue;
      const scope=scanScope(scan,kind);
      if(!latest.has(scope)) latest.set(scope,scan);
    }
    for(const [scope,scan] of latest){
      for(const finding of scan.findings||[]) rows.push({...finding,
        _riskKey:JSON.stringify([scope,finding.fingerprint||finding.id]),_scan:scan,
        ...(kind==='web'?{_scanId:scan.id}:kind==='auth'?{_auth:true,_authScanId:scan.id}:kind==='code'?{_code:true,_codeScanId:scan.id}:{_network:true,_networkScanId:scan.id})});
    }
  }
  return rows.sort((a,b)=>(rank[b.severity]||0)-(rank[a.severity]||0));
}
export function retestOutcome(scan, fingerprint) {
  if((scan.findings||[]).some(f=>f.fingerprint===fingerprint)) return 'still_present';
  // Absence is not proof of a fix when any required coverage is missing.
  if(scan.status!=='completed'||(scan.coverageGaps||[]).length||
    (scan.engineRuns||[]).some(run=>run.status!=='completed')) return 'inconclusive';
  return 'resolved';
}
export function applyWorkflow(finding,status,now=new Date().toISOString()) {
  if(!workflowStatuses.includes(status)) throw new Error('Invalid finding status.');
  const previous=finding.workflowStatus||'open';
  if(previous!==status){
    finding.workflowHistory=[...(finding.workflowHistory||[]),{from:previous,to:status,at:now}];
    finding.workflowStatus=status;
    finding.statusUpdatedAt=now;
  }
  return finding;
}
export function carryRiskLifecycle(scan, previous) {
  const prior=new Map((previous?.findings||[]).map(f=>[f.fingerprint||f.id,f]));
  const now=scan.completedAt||scan.scannedAt||new Date().toISOString();
  scan.findings=(scan.findings||[]).map(f=>{
    const old=prior.get(f.fingerprint||f.id);
    return {...f,firstSeen:old?.firstSeen||f.firstSeen||(old?(previous?.completedAt||previous?.scannedAt):null)||now,
      lastSeen:now,workflowStatus:old?.workflowStatus==='resolved'?'open':old?.workflowStatus||f.workflowStatus||'open',
      workflowHistory:old?.workflowHistory||f.workflowHistory||[],
      statusUpdatedAt:old?.statusUpdatedAt||f.statusUpdatedAt||null};
  });
  return scan;
}
