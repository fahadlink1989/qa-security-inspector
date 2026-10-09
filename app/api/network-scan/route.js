import { withWorkspace } from '../../../lib/backend/auth';
import { enqueueJob } from '../../../lib/backend/queue';
import { readState } from '../../../lib/store';
import { scannerWorkerHealth } from '../../../lib/workerClient';
export const runtime='nodejs';
export const dynamic='force-dynamic';
async function handlePOST(request){
  try{
    const body=await request.json();
    if(body.authorized!==true) throw new Error('Authorization confirmation is required.');
    if(!body.projectId||!body.networkTargetId) throw new Error('Project and network target are required.');
    const worker=await scannerWorkerHealth();
    if(!worker.connected||!worker.health?.allowPrivateTargets) throw new Error('Internal scanner worker is not reachable. Connect an authorized internal worker before starting a network scan.');
    const state=await readState();
    const project=state.projects.find(item=>item.id===body.projectId);
    if(!project) throw new Error('Project not found.');
    const target=(project.networks||[]).find(item=>item.id===body.networkTargetId);
    if(!target) throw new Error('Network target not found.');
    const job=await enqueueJob({projectId:project.id,type:'network-scan',scanType:'Internal Network Scan',target:target.cidr},body);
    return Response.json(job,{status:202});
  }catch(error){return Response.json({error:error.message},{status:400});}
}
export const POST=withWorkspace(handlePOST);
