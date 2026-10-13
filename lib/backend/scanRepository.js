import {database} from './db';
import {workspaceContext} from './context';
import {mutateState} from '../store';
import {historyFields} from './history';
import {carryRiskLifecycle,workflowStatuses} from '../riskModel.mjs';
export async function getScan(kind,id,client=database()){
 const {rows}=await client.query('SELECT data FROM inspector_scan_history WHERE workspace_id=$1 AND kind=$2 AND id=$3',[workspaceContext().workspaceId,kind,id]);return rows[0]?.data||null;
}
export async function getScanById(id){const {rows}=await database().query('SELECT data FROM inspector_scan_history WHERE workspace_id=$1 AND id=$2 LIMIT 1',[workspaceContext().workspaceId,id]);return rows[0]?.data||null;}
export async function latestStoredScan(kind,projectId,filter={}){
 const {mode,...fields}=filter;
 const {rows}=await database().query("SELECT data FROM inspector_scan_history WHERE workspace_id=$1 AND kind=$2 AND project_id=$3 AND data @> $4::jsonb AND ($6::text IS NULL OR asset_id=$6) AND ($5::text IS NULL OR coalesce(data->>'mode','standard')=$5) AND data->>'status' NOT IN ('failed','queued','running') ORDER BY recorded_at DESC,id DESC LIMIT 1",[workspaceContext().workspaceId,kind,projectId,JSON.stringify(fields),mode||null,fields.assetId||fields.networkTargetId||null]);return rows[0]?.data||null;
}
export async function saveScan(kind,scan){
 await mutateState(async(state,client)=>{
  const project=state.projects.find(p=>p.id===scan.projectId);if(!project)throw new Error('Project not found.');
  if(kind!=='performance'){
   const {rows}=await client.query('SELECT data||jsonb_build_object(\'firstSeen\',first_seen) AS data FROM inspector_current_risks WHERE workspace_id=$1 AND kind=$2 AND scope_key=inspector_scan_scope($2,$3::jsonb)',[workspaceContext().workspaceId,kind,JSON.stringify(scan)]);
   carryRiskLifecycle(scan,{findings:rows.map(r=>r.data)});
  }
  if(kind==='web')state.scans=[scan];else project[historyFields[kind]]=[scan];return state;
 });return scan;
}
export async function patchScan(kind,id,patch){
 await mutateState(async(state,client)=>{const scan=await getScan(kind,id,client);if(!scan)throw new Error('Scan not found.');Object.assign(scan,patch);if(kind==='web')state.scans=[scan];else state.projects.find(p=>p.id===scan.projectId)[historyFields[kind]]=[scan];return state;});
}
export async function updateStoredRisk(input,actor,retest=null){
 let result;
 await mutateState(async(state,client)=>{
  const source=await getScan(input.kind,input.scanId,client);
  if(!source||source.projectId!==input.projectId)throw new Error('Scan not found.');
  const finding=source.findings?.find(f=>(f.fingerprint||f.id)===input.fingerprint);if(!finding)throw new Error('Finding not found.');
  const owner=String(input.owner??finding.owner??'').trim(),notes=String(input.notes??finding.notes??'').trim();
  if(owner.length>120||notes.length>4000)throw new Error('Owner or notes exceed the allowed length.');
  if(input.status&&!workflowStatuses.includes(input.status))throw new Error('Invalid finding status.');
  const now=new Date().toISOString();
  const event={at:now,actor,action:input.status?'Risk status changed':'Remediation details updated',...(input.status?{from:finding.workflowStatus||'open',to:input.status}:{owner})};
  const patch={owner,notes,...(input.status?{workflowStatus:input.status,statusUpdatedAt:now}:{})};
  // Update matching observations in SQL. Historical evidence never travels through
  // the request or changes scope; array order and scanner fields are preserved.
  await client.query(`UPDATE inspector_scan_history h SET data=jsonb_set(h.data,'{findings}',
    (SELECT jsonb_agg(CASE WHEN coalesce(f->>'fingerprint',f->>'id')=$4 THEN
      f||$5::jsonb||jsonb_build_object('workflowHistory',coalesce(f->'workflowHistory','[]')||jsonb_build_array($6::jsonb))
      ||CASE WHEN $7::jsonb IS NOT NULL THEN jsonb_build_object('retests',coalesce((SELECT jsonb_agg(t) FROM jsonb_array_elements(coalesce(f->'retests','[]')) t WHERE t->>'scanId'<>$7::jsonb->>'scanId'),'[]')||jsonb_build_array($7::jsonb)) ELSE '{}'::jsonb END
     ELSE f END ORDER BY n) FROM jsonb_array_elements(h.data->'findings') WITH ORDINALITY x(f,n)))
    WHERE h.workspace_id=$1 AND h.kind=$2 AND h.scope_key=inspector_scan_scope($2,$3::jsonb)
     AND EXISTS(SELECT 1 FROM jsonb_array_elements(coalesce(h.data->'findings','[]')) f WHERE coalesce(f->>'fingerprint',f->>'id')=$4)`,
    [workspaceContext().workspaceId,input.kind,JSON.stringify(source),input.fingerprint,JSON.stringify(patch),JSON.stringify(event),retest?JSON.stringify(retest):null]);
  result={...finding,...patch,workflowHistory:[...(finding.workflowHistory||[]),event]};return state;
 });return result;
}
