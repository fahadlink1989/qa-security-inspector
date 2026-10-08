import { latestScanForProject, readState } from '../../../lib/store';
import { dueForSchedule } from '../../../lib/scanner';
import { runProjectScan } from '../../../lib/scanService';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 300;

export async function GET(request) {
  const auth = request.headers.get('authorization');
  if (!process.env.CRON_SECRET || auth !== 'Bearer ' + process.env.CRON_SECRET) {
    return new Response('Unauthorized', { status: 401 });
  }

  const state = await readState();
  const due = state.projects.filter((project) => project.scheduleAuthorized===true && dueForSchedule(project, latestScanForProject(state, project.id)));
  const results = [];

  for (const project of due.slice(0, 2)) {
    const assets=(project.assets||[]).filter((item)=>item.status==='active'&&(!project.scheduledAssetIds||project.scheduledAssetIds.includes(item.id))).slice(0,2);
    if(!assets.length) continue;
    for(const asset of assets){
      try {
        const scan = await runProjectScan(
          project.id,
          asset.id,
          'schedule',
          project.scheduledMode==='deep'?'deep':'standard',null,project.scheduledEngines||[]
        );
        results.push({ projectId: project.id, assetId:asset.id, scanId: scan.id, status: 'completed', mode:scan.mode });
      } catch (error) {
        results.push({ projectId: project.id, assetId:asset.id, status: 'failed', error: error.message });
      }
    }
  }

  return Response.json({ checked: state.projects.length, due: due.length, results });
}
