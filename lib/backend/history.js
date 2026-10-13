// Evidence is stored per scan; metadata updates no longer rewrite every historical result.
export const historyFields={auth:'authScans',code:'codeScans',network:'networkScans',performance:'performanceScans'};
export function scanRecords(state){
  return [...(state.scans||[]).map(data=>({kind:'web',data})),...state.projects.flatMap(p=>Object.entries(historyFields).flatMap(([kind,field])=>(p[field]||[]).map(s=>({kind,data:{...s,projectId:s.projectId||p.id}}))))];
}
export function withoutHistory(state){
  const copy={...state,scans:[]};copy.projects=state.projects.map(p=>{const next={...p};for(const key of Object.values(historyFields))next[key]=[];return next;});return copy;
}
export async function hydrateHistory(client,workspaceId,state){
  const out=structuredClone(state),seen=new Set(scanRecords(out).map(s=>s.kind+':'+s.data.id));
  const {rows}=await client.query('SELECT kind,data FROM inspector_scan_history WHERE workspace_id=$1 ORDER BY recorded_at DESC,kind,id',[workspaceId]);
  for(const {kind,data} of rows){if(seen.has(kind+':'+data.id))continue;if(kind==='web')out.scans.push(data);else{const p=out.projects.find(p=>p.id===data.projectId);if(p)(p[historyFields[kind]]??=[]).push(data);}}
  return out;
}
export async function persistHistory(client,workspaceId,state,previous=new Map()){
  for(const {kind,data} of scanRecords(state)){
    const serialized=JSON.stringify(data);if(previous.get(kind+':'+data.id)===serialized)continue;
    const time=data.completedAt||data.scannedAt||data.startedAt||state.updatedAt||new Date().toISOString();
    await client.query(`INSERT INTO inspector_scan_history(workspace_id,kind,id,project_id,asset_id,recorded_at,data)
      VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(workspace_id,kind,id) DO UPDATE SET data=excluded.data,recorded_at=excluded.recorded_at,asset_id=excluded.asset_id`,
      [workspaceId,kind,data.id,data.projectId,data.assetId||data.networkTargetId||null,time,serialized]);
  }
}
