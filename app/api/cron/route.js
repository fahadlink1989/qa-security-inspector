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
  const due = state.projects.filter((project) => dueForSchedule(project, latestScanForProject(state, project.id)));
  const results = [];

  for (const project of due.slice(0, 2)) {
    const asset = project.assets?.find((item) => item.status === 'active') || project.assets?.[0];
    if (!asset) continue;
    try {
      const scan = await runProjectScan(project.id, asset.id, 'schedule');
      results.push({ projectId: project.id, scanId: scan.id, status: 'completed' });
    } catch (error) {
      results.push({ projectId: project.id, status: 'failed', error: error.message });
    }
  }

  return Response.json({ checked: state.projects.length, due: due.length, results });
}
