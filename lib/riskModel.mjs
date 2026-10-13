const rank = {Critical:5,High:4,Medium:3,Low:2,Informational:1};
export const workflowStatuses = ['open','in_progress','resolved','accepted','false_positive'];
export function scanScope(scan, kind='web') {
  return JSON.stringify([kind,scan.projectId,scan.assetId||scan.networkTargetId||scan.repositoryUrl||scan.repository||scan.url,kind==='auth'?scan.auth?.method:'']);
}
const time = scan => scan.completedAt||scan.scannedAt||scan.startedAt||'';
const identity = finding => finding.fingerprint||finding.id;
export function currentRiskRows(scans, project) {
  const groups=[['web',scans||[]],['auth',project?.authScans||[]],['code',project?.codeScans||[]],['network',project?.networkScans||[]]];
  const rows=[];
  for(const [kind,history] of groups) {
    const scopes=new Map();
    for(const scan of [...history].filter(s=>!['queued','running','failed'].includes(s.status)).sort((a,b)=>String(time(b)).localeCompare(String(time(a))))) {
      const scope=scanScope(scan,kind);
      if(!scopes.has(scope)) scopes.set(scope,[]);
      scopes.get(scope).push(scan);
    }
    for(const [scope,history] of scopes) {
      const seen=new Map();
      for(const [index,scan] of history.entries()) for(const finding of scan.findings||[]) {
        const key=identity(finding);
        if(!key) continue;
        if(seen.has(key)) {
          const row=seen.get(key);
          const first=finding.firstSeen||time(scan);
          if(first&&(!row.firstSeen||first<row.firstSeen)) row.firstSeen=first;
          continue;
        }
        // A later scan's absence is not proof of remediation or equivalent coverage.
        // Keep the last observed evidence until an explicit workflow/retest closes it.
        const row={...finding,firstSeen:finding.firstSeen||time(scan),lastSeen:finding.lastSeen||time(scan),coverageUnverified:index>0,
          _riskKey:JSON.stringify([scope,key]),_scan:scan,
          ...(kind==='web'?{_scanId:scan.id}:kind==='auth'?{_auth:true,_authScanId:scan.id}:kind==='code'?{_code:true,_codeScanId:scan.id}:{_network:true,_networkScanId:scan.id})};
        seen.set(key,row); rows.push(row);
      }
    }
  }
  return rows.sort((a,b)=>(rank[b.severity]||0)-(rank[a.severity]||0));
}
// Select the latest observation of every risk, not only the previous scan's findings.
export function priorRiskSnapshot(history,scan,kind='web') {
  const scope=scanScope(scan,kind),seen=new Set(),findings=[];
  for(const old of [...history].filter(s=>s.id!==scan.id&&s.status!=='failed'&&scanScope(s,kind)===scope).sort((a,b)=>String(time(b)).localeCompare(String(time(a))))) {
    for(const f of old.findings||[]) if(!seen.has(identity(f))) {
      seen.add(identity(f)); findings.push({...f,firstSeen:f.firstSeen||time(old)});
    }
  }
  return {findings};
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
    return {...f,lifecycle:old?'open':'new',firstSeen:old?.firstSeen||f.firstSeen||(old?(previous?.completedAt||previous?.scannedAt):null)||now,
      lastSeen:now,workflowStatus:old?.workflowStatus==='resolved'?'open':old?.workflowStatus||f.workflowStatus||'open',
      workflowHistory:old?.workflowStatus==='resolved'?[...(old.workflowHistory||[]),{from:'resolved',to:'open',at:now,action:'Reopened after scanner observed the finding again'}]:old?.workflowHistory||f.workflowHistory||[],
      owner:old?.owner||f.owner||'',notes:old?.notes||f.notes||'',retests:old?.retests||f.retests||[],
      statusUpdatedAt:old?.workflowStatus==='resolved'?now:old?.statusUpdatedAt||f.statusUpdatedAt||null};
  });
  return scan;
}

export function coverageState(scan) {
  if(!scan) return {label:'Not scanned',complete:false,gaps:[]};
  const gaps=[...(scan.coverageGaps||[]).map(g=>typeof g==='string'?g:JSON.stringify(g)),...(scan.engineRuns||[]).filter(r=>r.status!=='completed').map(r=>(r.name||r.engine)+': '+(r.error||r.status))];
  return {label:scan.status==='failed'?'Failed':scan.status==='completed'&&!gaps.length?'Complete':'Incomplete',complete:scan.status==='completed'&&!gaps.length,gaps};
}
export function updateRiskDetails(state,input,actor,now=new Date().toISOString()) {
  const project=state.projects.find(p=>p.id===input.projectId);
  if(!project) throw new Error('Target group not found.');
  const histories={web:(state.scans||[]).filter(s=>s.projectId===project.id),auth:project.authScans||[],code:project.codeScans||[],network:project.networkScans||[]};
  const history=histories[input.kind];
  const source=history?.find(s=>s.id===input.scanId);
  if(!source) throw new Error('Scan not found.');
  const finding=source.findings?.find(f=>(f.fingerprint||f.id)===input.fingerprint);
  if(!finding) throw new Error('Finding not found.');
  const owner=String(input.owner??finding.owner??'').trim();
  const notes=String(input.notes??finding.notes??'').trim();
  if(owner.length>120||notes.length>4000) throw new Error('Owner or notes exceed the allowed length.');
  if(input.status&&!workflowStatuses.includes(input.status)) throw new Error('Invalid finding status.');
  const scope=scanScope(source,input.kind);
  for(const scan of history.filter(s=>scanScope(s,input.kind)===scope)){
    for(const f of (scan.findings||[]).filter(f=>(f.fingerprint||f.id)===input.fingerprint)){
      if(f.owner!==owner||f.notes!==notes) f.workflowHistory=[...(f.workflowHistory||[]),{at:now,actor,action:'Remediation details updated',owner}];
      f.owner=owner;f.notes=notes;
      if(input.status) applyWorkflow(f,input.status,now);
    }
  }
  return finding;
}

