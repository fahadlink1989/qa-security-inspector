import { scannerWorkerHealth } from '../../../lib/workerClient';
import { readState } from '../../../lib/store';
import { waitUntil } from '@vercel/functions';
import { createScanJob, executeScanJob, getScanJob } from '../../../lib/jobs';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 300;

export async function GET(request) {
  try {
    const jobId = new URL(request.url).searchParams.get('jobId');
    if (!jobId) return Response.json({ error:'jobId is required.' }, { status:400 });
    const job = await getScanJob(jobId);
    if (!job) return Response.json({ error:'Scan job not found.' }, { status:404 });
    return Response.json(job, { headers:{'cache-control':'no-store'} });
  } catch (error) {
    return Response.json({ error:error?.message || 'Could not read scan job.' }, { status:400 });
  }
}

export async function POST(request) {
  try {
    const body = await request.json();

    if (body.authorized !== true) {
      return Response.json({ error: 'Authorization confirmation is required.' }, { status: 400 });
    }
    const type=body.type||'web';
    if(!['web','code','authenticated','network'].includes(type)) throw new Error('Unsupported scan type.');
    if(!body.projectId) throw new Error('Project is required.');
    if(type==='authenticated'&&!body.credential) throw new Error('Authorized test session is required.');
    const engines=body.engines===undefined?[]:body.engines;
    if(!Array.isArray(engines)||engines.some(e=>!['zap','nuclei'].includes(e))) throw new Error('Unsupported web scan engine.');
    if(engines.length){const health=await scannerWorkerHealth();if(!health.reachable||engines.some(e=>health.capabilities[e]!==true)) throw new Error('Selected scanner engine is unavailable.');}
    const mode=body.mode==='deep'?'deep':'standard';
    const ids=type==='web'?(body.assetIds||[body.assetId]):[body.assetId];
    if(!Array.isArray(ids)||!ids.length||ids.length>10||new Set(ids).size!==ids.length) throw new Error('Select between 1 and 10 distinct targets.');
    if(type==='web'){
      const state=await readState();const project=state.projects.find(p=>p.id===body.projectId);
      if(!project||ids.some(id=>!project.assets.some(a=>a.id===id))) throw new Error('Target not found in this workspace.');
    }
    const jobs=[];
    for(const assetId of ids) jobs.push(await createScanJob({projectId:body.projectId,assetId,trigger:'manual',mode,engines,type,repositoryUrl:body.repositoryUrl,networkTargetId:body.networkTargetId}));
    const job=jobs[0];

    waitUntil((async()=>{
      for(const item of jobs) await executeScanJob(item.id,{credential:body.credential,authType:body.authType,token:body.token}).catch(error=>console.error('background scan failed',error.message));
    })());

    return Response.json({...job,jobs}, {
      status:202,
      headers:{'cache-control':'no-store'}
    });
  } catch (error) {
    return Response.json({ error: error.message || 'Scan failed.' }, { status: 400 });
  }
}
