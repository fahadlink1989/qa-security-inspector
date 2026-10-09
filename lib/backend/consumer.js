import { database } from './db';
import { inWorkspace } from './context';
import { decryptPayload } from './crypto';
import { claimJob,heartbeat,progressJob,finishJob,failJob,enqueueJob } from './queue';
import { readState } from '../store';
import { runProjectScan,retestFinding } from '../scanService';
import { runAuthenticatedTask } from '../auth-scanTask';
import { runCodeTask } from '../code-scanTask';
import { runPerformanceTask } from '../performance';
import { runNetworkTask } from '../network-scanTask';
export async function scheduleDueJobs() {
  const {rows}=await database().query('SELECT id,state FROM inspector_workspaces');
  for(const workspace of rows) await inWorkspace({workspaceId:workspace.id},async()=>{
    for(const project of workspace.state.projects||[]) {
      for(const asset of project.assets||[]) {
        if(asset.status!=='active')continue;
        const frequency=asset.schedule??project.schedule;
        if(!['daily','weekly'].includes(frequency)||!(asset.scheduleAuthorizedAt||project.scheduleAuthorizedAt))continue;
        const period=frequency==='daily'?86400000:604800000;
        const slot=Math.floor(Date.now()/period);
        const mode=asset.scheduledMode||project.scheduledMode||'standard';
        try {
          await enqueueJob({type:'web-scan',projectId:project.id,assetId:asset.id,target:asset.url,
            mode,scanType:mode==='deep'?'Attack Surface Scan':'Web App Scan',trigger:'schedule'}, {},
            [project.id,asset.id,frequency,slot].join(':'));
        }catch{/* Full workspace queues are retried on the next scheduler tick. */}
      }
    }
  });
}
export async function consumeOne() {
  await database().query("INSERT INTO inspector_worker_heartbeats(id) VALUES('consumer') ON CONFLICT(id) DO UPDATE SET last_seen=now()");
  const job=await claimJob();if(!job)return {idle:true};
  const timer=setInterval(()=>heartbeat(job).catch(()=>{}),20000);
  try {
    await inWorkspace({workspaceId:job.workspace_id,jobId:job.id,leaseToken:job.lease_token},async()=>{
      const state=await readState();
      const saved=[...state.scans,...state.projects.flatMap(p=>[...(p.authScans||[]),...(p.codeScans||[]),...(p.networkScans||[]),...(p.performanceScans||[])])].find(s=>s.id===job.id);
      if(saved&&job.data.type!=='retest'){await finishJob(job,saved);return;}
      const project=state.projects.find(p=>p.id===job.data.projectId);
      if(!project)throw new Error('Project was removed.');
      if(job.data.assetId&&!project.assets.some(a=>a.id===job.data.assetId&&a.status==='active'&&a.url===job.data.target))throw new Error('Target changed after authorization. Submit a new scan.');
      const payload=decryptPayload(job.payload,job.workspace_id+':'+job.id);
      let result;
      if(job.data.type==='web-scan')result=await runProjectScan(job.data.projectId,job.data.assetId,job.data.trigger,job.data.mode,p=>progressJob(p.progress,p.stage),job.data.target);
      else if(job.data.type==='authenticated-scan')result=await runAuthenticatedTask(payload,progressJob);
      else if(job.data.type==='code-scan')result=await runCodeTask(payload,progressJob);
      else if(job.data.type==='network-scan')result=await runNetworkTask(payload,progressJob);
      else if(job.data.type==='performance')result=await runPerformanceTask(job.data.projectId,job.data.assetId,progressJob);
      else if(job.data.type==='retest')result=(await retestFinding(payload.scanId,payload.fingerprint)).scan;
      else throw new Error('Unknown job type');
      await finishJob(job,result);
    });
    return {processed:true};
  }catch(error){await failJob(job,error);return {retry:true};}
  finally{clearInterval(timer);}
}
