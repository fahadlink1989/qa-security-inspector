import { withWorkspace } from '../../../lib/backend/auth';
import { enqueueJob } from '../../../lib/backend/queue';
import { readState } from '../../../lib/store';
import { scannerWorkerHealth } from '../../../lib/workerClient';
export const runtime='nodejs';
export const dynamic='force-dynamic';
async function handlePOST(request) {
  try {
    const body = await request.json();
    if (!body.projectId) throw new Error('Project is required.');
    if (body.authorized !== true) throw new Error('Authorization confirmation is required.');
    if (!body.repositoryUrl) throw new Error('GitHub repository URL is required.');

    const repository = new URL(body.repositoryUrl);
    if (repository.protocol !== 'https:' || !['github.com','www.github.com'].includes(repository.hostname.toLowerCase())) {
      throw new Error('Only HTTPS GitHub repository URLs are supported.');
    }
    const state = await readState();
    const project = state.projects.find((item) => item.id === body.projectId);
    if (!project) throw new Error('Project not found.');
    const job=await enqueueJob({projectId:project.id,type:'code-scan',scanType:'Code & Dependencies',target:repository.href},body);
    return Response.json(job,{status:202});
  }catch(error){return Response.json({error:error.message},{status:400});}
}
export const POST=withWorkspace(handlePOST);
