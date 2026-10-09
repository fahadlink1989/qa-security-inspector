import { withWorkspace } from '../../../lib/backend/auth';
import { enqueueJob } from '../../../lib/backend/queue';
import { readState } from '../../../lib/store';
import { scannerWorkerHealth } from '../../../lib/workerClient';
export const runtime='nodejs';
export const dynamic='force-dynamic';
async function handlePOST(request) {
  try {
    const body = await request.json();
    if (body.authorized !== true) throw new Error('Authorization confirmation is required.');
    if (!body.projectId || !body.assetId) throw new Error('Project and asset are required.');
    if (!['bearer','cookie'].includes(body.authType) || !body.credential) {
      throw new Error('Authenticated Scan requires a bearer token or cookie header.');
    }

    const state = await readState();
    const project = state.projects.find((item) => item.id === body.projectId);
    if (!project) throw new Error('Project not found.');
    const asset = project.assets.find((item) => item.id === body.assetId);
    if (!asset) throw new Error('Asset not found.');
    const job=await enqueueJob({projectId:project.id,type:'authenticated-scan',scanType:'Authenticated Scan',target:asset.url,assetId:asset.id},body);
    return Response.json(job,{status:202});
  }catch(error){return Response.json({error:error.message},{status:400});}
}
export const POST=withWorkspace(handlePOST);
