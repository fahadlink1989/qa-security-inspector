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
    if (!body.projectId || !body.assetId) {
      return Response.json({ error: 'Project and asset are required.' }, { status: 400 });
    }

    const mode = body.mode === 'deep' ? 'deep' : 'standard';
    const job = await createScanJob({
      projectId:body.projectId,
      assetId:body.assetId,
      trigger:body.trigger || 'manual',
      mode
    });

    waitUntil(
      executeScanJob(job.id).catch((error)=>{
        console.error('background scan job failed', error);
      })
    );

    return Response.json(job, {
      status:202,
      headers:{'cache-control':'no-store'}
    });
  } catch (error) {
    return Response.json({ error: error.message || 'Scan failed.' }, { status: 400 });
  }
}
