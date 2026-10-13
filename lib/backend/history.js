export const historyFields={auth:'authScans',code:'codeScans',network:'networkScans',performance:'performanceScans'};
export function scanRecords(state){return [...(state.scans||[]).map(data=>({kind:'web',data})),...state.projects.flatMap(p=>Object.entries(historyFields).flatMap(([kind,field])=>(p[field]||[]).map(s=>({kind,data:{...s,projectId:s.projectId||p.id}}))))];}
export function withoutHistory(state){const copy={...state,scans:[]};delete copy.risks;copy.projects=state.projects.map(p=>{const next={...p};for(const key of Object.values(historyFields))next[key]=[];return next;});return copy;}
export async function hydrateHistory(client,workspaceId,state,options={}){
 const out=withoutHistory(structuredClone(state));
 if(options.history===false)return out;
 const params=[workspaceId],filter=options.projectId?' AND project_id=$2':'';if(options.projectId)params.push(options.projectId);
 // Recent activity plus latest per target/profile. Size grows with assets, never past runs.
 const {rows}=await client.query(`WITH selected AS (
   (SELECT kind,id FROM inspector_scan_history WHERE workspace_id=$1 ${filter} ORDER BY recorded_at DESC,kind DESC,id DESC LIMIT 25)
   UNION SELECT l.kind,l.scan_id FROM inspector_latest_scans l JOIN inspector_scan_history h ON (h.workspace_id,h.kind,h.id)=(l.workspace_id,l.kind,l.scan_id) WHERE l.workspace_id=$1 ${options.projectId?'AND h.project_id=$2':''}
  ) SELECT h.kind,h.data||jsonb_build_object('_latest',EXISTS(SELECT 1 FROM inspector_latest_scans l WHERE l.workspace_id=h.workspace_id AND l.kind=h.kind AND l.scan_id=h.id)) AS data FROM selected s JOIN inspector_scan_history h ON h.workspace_id=$1 AND h.kind=s.kind AND h.id=s.id ORDER BY h.recorded_at DESC,h.kind,h.id`,params);
 for(const {kind,data} of rows){if(kind==='web')out.scans.push(data);else{const p=out.projects.find(p=>p.id===data.projectId);if(p)(p[historyFields[kind]]??=[]).push(data);}}
 const risks=await client.query(`SELECT r.*,h.data-'findings'-'evidence' AS scan,
   EXISTS(SELECT 1 FROM inspector_latest_scans l JOIN inspector_scan_history n ON (n.workspace_id,n.kind,n.id)=(l.workspace_id,l.kind,l.scan_id) WHERE l.workspace_id=r.workspace_id AND l.kind=r.kind AND l.scope_key=r.scope_key AND l.recorded_at>r.observed_at AND n.data->>'status' NOT IN ('failed','queued','running')) AS stale
   FROM inspector_current_risks r JOIN inspector_scan_history h ON (h.workspace_id,h.kind,h.id)=(r.workspace_id,r.kind,r.scan_id) WHERE r.workspace_id=$1 ${options.projectId?'AND h.project_id=$2':''}`,params);
 out.risks=risks.rows.map(r=>({...r.data,firstSeen:r.first_seen.toISOString(),lastSeen:r.data.lastSeen||r.observed_at.toISOString(),coverageUnverified:r.stale,_riskKey:JSON.stringify([r.scope_key,r.fingerprint]),_scan:r.scan,...(r.kind==='web'?{_scanId:r.scan_id}:r.kind==='auth'?{_auth:true,_authScanId:r.scan_id}:r.kind==='code'?{_code:true,_codeScanId:r.scan_id}:{_network:true,_networkScanId:r.scan_id})}));
 return out;
}
export async function persistHistory(client,workspaceId,state,previous=new Map()){
 for(const {kind,data} of scanRecords(state)){
  const serialized=JSON.stringify(data);if(previous.get(kind+':'+data.id)===serialized)continue;
  const time=data.completedAt||data.scannedAt||data.startedAt||state.updatedAt||new Date().toISOString();
  await client.query(`INSERT INTO inspector_scan_history(workspace_id,kind,id,project_id,asset_id,recorded_at,data) VALUES($1,$2,$3,$4,$5,$6,$7)
   ON CONFLICT(workspace_id,kind,id) DO UPDATE SET data=excluded.data,recorded_at=excluded.recorded_at,asset_id=excluded.asset_id`,[workspaceId,kind,data.id,data.projectId,data.assetId||data.networkTargetId||null,time,serialized]);
 }
}
