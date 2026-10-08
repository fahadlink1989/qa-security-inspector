import crypto from 'node:crypto';
import { mutateState, readState } from './store';
import { runProjectScan } from './scanService';

export async function createScanJob({projectId,assetId,mode='standard',trigger='manual',engines=[],type='web',repositoryUrl='',networkTargetId=''}){
  const state=await readState();
  const project=state.projects.find((item)=>item.id===projectId);
  if(!project) throw new Error('Project not found.');
  const asset=project.assets.find((item)=>item.id===assetId);
  if(['web','authenticated'].includes(type)&&!asset) throw new Error('Asset not found.');
  const network=(project.networks||[]).find(n=>n.id===networkTargetId);
  if(type==='network'&&!network) throw new Error('Network not found.');
  if(type==='code'&&!repositoryUrl) throw new Error('Repository is required.');

  const job={
    id:'job_'+crypto.randomUUID(),
    type,repositoryUrl,networkTargetId,
    projectId,
    assetId,
    target:asset?.url||network?.cidr||repositoryUrl,
    engines,
    mode:mode==='deep'?'deep':'standard',
    scanType:type==='code'?'Code & Dependencies':type==='authenticated'?'Authenticated Scan':type==='network'?'Internal Network Scan':mode==='deep'?'Attack Surface Scan':'Web App Scan',
    trigger,
    status:'queued',
    stage:'Queued',
    progress:0,
    createdAt:new Date().toISOString(),
    startedAt:null,
    completedAt:null,
    scanId:null,
    error:null
  };

  await mutateState((next)=>{
    next.jobs=[job,...(next.jobs||[])].slice(0,40);
    return next;
  });
  return job;
}

export async function updateScanJob(jobId,patch){
  let output=null;
  await mutateState((state)=>{
    const job=(state.jobs||[]).find((item)=>item.id===jobId);
    if(!job) throw new Error('Scan job not found.');
    Object.assign(job,patch);
    output={...job};
    return state;
  });
  return output;
}

export async function getScanJob(jobId){
  const state=await readState();
  return (state.jobs||[]).find((item)=>item.id===jobId)||null;
}

export async function executeScanJob(jobId, ephemeralInput={}){
  const job=await getScanJob(jobId);
  if(!job) throw new Error('Scan job not found.');
  await updateScanJob(jobId,{status:'running',stage:'Starting scanner',progress:5,startedAt:new Date().toISOString()});

  try{
    let scan;
    if(job.type!=='web' && job.type!=='web-scan'){
      const route=job.type==='code'?await import('../app/api/code-scan/route'):job.type==='authenticated'?await import('../app/api/auth-scan/route'):await import('../app/api/network-scan/route');
      await updateScanJob(jobId,{progress:15,stage:'Running '+job.scanType});
      const response=await route.POST(new Request('http://localhost/api/internal',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({...ephemeralInput,projectId:job.projectId,assetId:job.assetId,repositoryUrl:job.repositoryUrl,networkTargetId:job.networkTargetId,authorized:true})}));
      scan=await response.json();
      if(!response.ok) throw new Error(scan.error||'Scan failed.');
    }else scan=await runProjectScan(
      job.projectId,
      job.assetId,
      job.trigger||'manual',
      job.mode,
      async(progress)=>{
        await updateScanJob(jobId,{
          status:'running',
          stage:progress.stage,
          progress:Math.max(5,Math.min(98,Number(progress.progress)||5))
        });
      },
      job.engines
    );

    return await updateScanJob(jobId,{
      status:scan.status==='failed'?'failed':'completed',
      stage:'Completed',
      progress:100,
      scanId:scan.id,
      completedAt:new Date().toISOString()
    });
  }catch(error){
    await updateScanJob(jobId,{
      status:'failed',
      stage:'Failed',
      progress:100,
      error:String(error?.message||error).slice(0,1000),
      completedAt:new Date().toISOString()
    });
    throw error;
  }
}
