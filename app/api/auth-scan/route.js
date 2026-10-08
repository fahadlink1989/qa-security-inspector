import { waitUntil } from '@vercel/functions';
import { createTaskJob, executeTaskJob } from '../../../lib/jobs';
import { mutateState, readState } from '../../../lib/store';
import { runAuthenticatedScan } from '../../../lib/authenticatedScan';
import { generateIntelligence } from '../../../lib/intelligence';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 300;

export async function POST(request) {
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
    const job = await createTaskJob({
      projectId:project.id,
      type:'authenticated-scan',
      scanType:'Authenticated Scan',
      target:asset.url
    });

    // Credentials remain in this request's memory and are never written to Blob/job state.
    waitUntil(executeTaskJob(job.id, async (progress) => {
      await progress(12, 'Preparing authorized test session');
      const sourceScan = [...state.scans]
        .filter((item) => item.projectId === project.id && item.assetId === asset.id &&
          ['completed','completed_with_gaps','partial'].includes(item.status))
        .sort((a,b) => (a.mode === 'deep' ? -1 : 0) - (b.mode === 'deep' ? -1 : 0) ||
          String(b.completedAt || '').localeCompare(String(a.completedAt || '')))[0] || null;
      const previous = [...(project.authScans || [])]
        .filter((item) => item.assetId === asset.id && item.auth?.method === body.authType)
        .sort((a,b) => String(b.completedAt || '').localeCompare(String(a.completedAt || '')))[0] || null;

      await progress(40, 'Running authenticated browser and API checks');
      const authScan = await runAuthenticatedScan({
        url:asset.url,
        sourceScan,
        previousScan:previous,
        auth:{type:body.authType,value:String(body.credential)}
      });
      authScan.projectId = project.id;
      authScan.assetId = asset.id;
      authScan.scanType = 'Authenticated Scan';
      authScan.status = authScan.status || 'completed';

      await progress(78, 'Generating evidence-based remediation');
      try {
        const intelligence = await generateIntelligence(authScan);
        authScan.intelligence = {
          mode:intelligence?.mode || 'rules',
          provider:intelligence?.provider || null,
          model:intelligence?.model || null,
          generatedAt:intelligence?.generatedAt || new Date().toISOString(),
          aiError:intelligence?.aiError || null
        };
        authScan.remediationPlan = intelligence;
        if (intelligence?.executiveSummary) authScan.executiveSummary = intelligence.executiveSummary;
      } catch (error) {
        authScan.intelligence = {mode:'rules',aiError:String(error?.message || error).slice(0,300)};
      }

      await progress(92, 'Saving authenticated scan results');
      await mutateState((next) => {
        const target = next.projects.find((item) => item.id === project.id);
        if (!target) throw new Error('Project not found.');
        target.authScans = [authScan, ...(target.authScans || [])].slice(0, 10);
        return next;
      });
      return authScan;
    }).catch((error)=>console.error('authenticated scan job failed',error)));

    return Response.json(job,{status:202,headers:{'cache-control':'no-store'}});
  } catch (error) {
    return Response.json({error:error?.message || 'Authenticated Scan failed.'},{status:400});
  }
}
