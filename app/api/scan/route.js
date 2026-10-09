import { withWorkspace } from '../../../lib/backend/auth';
import { enqueueJob, getJob } from '../../../lib/backend/queue';
import { readState } from '../../../lib/store';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export const GET=withWorkspace(async request=>{
  const job=await getJob(new URL(request.url).searchParams.get('jobId'));
  return Response.json(job||{error:'Scan job not found.'},{status:job?200:404,headers:{'cache-control':'no-store'}});
});
export const POST=withWorkspace(async request=>{
  try {
    const body=await request.json();
    if(body.authorized!==true) throw new Error('Authorization confirmation is required.');
    const state=await readState(),project=state.projects.find(p=>p.id===body.projectId);
    const asset=project?.assets.find(a=>a.id===body.assetId&&a.status==='active');
    if(!asset) throw new Error('Active target not found.');
    const mode=body.mode==='deep'?'deep':'standard';
    const job=await enqueueJob({type:'web-scan',projectId:project.id,assetId:asset.id,target:asset.url,mode,
      scanType:mode==='deep'?'Attack Surface Scan':'Web App Scan'},{});
    return Response.json(job,{status:202});
  }catch(error){return Response.json({error:error.message},{status:400});}
});
