import crypto from 'node:crypto';
import { database, transaction } from './db';
import { workspaceContext } from './context';
import { encryptPayload } from './crypto';
export async function enqueueJob(fields,payload={},dedupeKey=null) {
  const {workspaceId,userId}=workspaceContext();
  const id='job_'+crypto.randomUUID();
  const data={...fields,id,trigger:fields.trigger||'manual',authorizedBy:userId||'schedule',
    status:'queued',stage:'Queued',progress:0,createdAt:new Date().toISOString(),startedAt:null,completedAt:null,scanId:null,error:null};
  return transaction(async client=>{
    // Serialize submissions for quota enforcement and target lookup within this workspace.
    const workspace=await client.query('SELECT state FROM inspector_workspaces WHERE id=$1 FOR UPDATE',[workspaceId]);
    const project=workspace.rows[0]?.state.projects.find(p=>p.id===fields.projectId);
    if(!project) throw new Error('Project not found.');
    if(fields.assetId&&!project.assets.some(a=>a.id===fields.assetId&&a.status==='active')) throw new Error('Active target not found.');
    if(dedupeKey){const old=await client.query('SELECT data FROM inspector_jobs WHERE workspace_id=$1 AND dedupe_key=$2',[workspaceId,dedupeKey]);if(old.rowCount)return old.rows[0].data;}
    const pending=await client.query("SELECT count(*)::int AS count FROM inspector_jobs WHERE workspace_id=$1 AND status IN ('queued','running')",[workspaceId]);
    if(pending.rows[0].count>=20) throw new Error('This workspace already has 20 pending scans.');
    await client.query('INSERT INTO inspector_jobs(id,workspace_id,data,payload,dedupe_key) VALUES($1,$2,$3,$4,$5)',
      [id,workspaceId,JSON.stringify(data),encryptPayload(payload,workspaceId+':'+id),dedupeKey]);
    return data;
  });
}
export async function getJob(id) {
  const {workspaceId}=workspaceContext();
  const {rows}=await database().query('SELECT data FROM inspector_jobs WHERE id=$1 AND workspace_id=$2',[id,workspaceId]);
  return rows[0]?.data||null;
}
export async function claimJob() {
  return transaction(async client=>{
    // Expired leases eventually become terminal, even after the last consumer crashed.
    await client.query(`UPDATE inspector_jobs SET status='failed',payload=NULL,lease_token=NULL,lease_until=NULL,
      data=data||jsonb_build_object('status','failed','stage','Failed','error','Worker stopped before completion; retry limit reached.','completedAt',now())
      WHERE status='running' AND lease_until<now() AND attempts>=max_attempts`);
    const {rows}=await client.query(`SELECT * FROM inspector_jobs WHERE
      ((status='queued' AND available_at<=now()) OR (status='running' AND lease_until<now()))
      AND attempts<max_attempts ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1`);
    const job=rows[0];if(!job)return null;
    const token=crypto.randomUUID();
    await client.query(`UPDATE inspector_jobs SET status='running',attempts=attempts+1,lease_token=$2,lease_until=now()+interval '90 seconds',
      data=data||jsonb_build_object('status','running','stage','Starting scanner','attempts',attempts+1,'startedAt',now(),'progress',5) WHERE id=$1`,[job.id,token]);
    return {...job,lease_token:token,attempts:job.attempts+1};
  });
}
export async function heartbeat(job) {
  await database().query("INSERT INTO inspector_worker_heartbeats(id) VALUES('consumer') ON CONFLICT(id) DO UPDATE SET last_seen=now()");
  const result=await database().query("UPDATE inspector_jobs SET lease_until=now()+interval '90 seconds' WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_until>now()",[job.id,job.lease_token]);
  return result.rowCount===1;
}
export async function progressJob(progress,stage) {
  const {jobId,leaseToken}=workspaceContext();
  await database().query("UPDATE inspector_jobs SET data=data||$3::jsonb WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_until>now()",
    [jobId,leaseToken,JSON.stringify({progress:Math.max(5,Math.min(98,Number(progress)||5)),stage:String(stage).slice(0,120)})]);
}
export async function finishJob(job,result) {
  const status=result.status==='failed'?'failed':result.status==='completed_with_gaps'?'completed_with_gaps':'completed';
  const data={status,stage:status==='completed_with_gaps'?'Completed with gaps':status==='failed'?'Failed':'Completed',progress:100,
    scanId:result.id,findings:result.findings?.length||0,summary:result.summary||{},coverageGaps:result.coverageGaps||[],completedAt:new Date().toISOString(),error:result.error||null};
  await database().query("UPDATE inspector_jobs SET status=$3,data=data||$4::jsonb,payload=NULL,lease_until=NULL,lease_token=NULL WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_until>now()",[job.id,job.lease_token,status,JSON.stringify(data)]);
}
export async function failJob(job,error) {
  const terminal=job.attempts>=job.max_attempts,status=terminal?'failed':'queued';
  // Never persist exception text: upstream messages can contain supplied credentials.
  const patch={status,stage:terminal?'Failed':'Retry scheduled',progress:0,error:'Scanner execution failed. '+(terminal?'Retry limit reached.':'The job will retry automatically.'),completedAt:terminal?new Date().toISOString():null};
  await database().query(`UPDATE inspector_jobs SET status=$3,data=data||$4::jsonb,available_at=now()+interval '30 seconds',
    payload=CASE WHEN $5 THEN NULL ELSE payload END,lease_until=NULL,lease_token=NULL
    WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_until>now()`,[job.id,job.lease_token,status,JSON.stringify(patch),terminal]);
}
