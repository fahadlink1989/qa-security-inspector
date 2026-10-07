import { addAsset, createProject, getWorkspaceView, updateFindingStatus, updateProject } from '../../../lib/platform';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 30;

export async function GET() {
  const data = await getWorkspaceView();
  return Response.json(data, { headers: { 'cache-control': 'no-store' } });
}

export async function POST(request) {
  try {
    const body = await request.json();
    let result;

    if (body.action === 'create_project') {
      if (!body.url) throw new Error('Project URL is required.');
      result = await createProject(body);
    } else if (body.action === 'update_project') {
      result = await updateProject(body.projectId, body.patch || {});
    } else if (body.action === 'add_asset') {
      result = await addAsset(body.projectId, body);
    } else if (body.action === 'finding_status') {
      result = await updateFindingStatus(body.scanId, body.fingerprint, body.status);
    } else {
      throw new Error('Unknown action.');
    }

    return Response.json({ ok: true, result });
  } catch (error) {
    return Response.json({ error: error.message || 'Request failed.' }, { status: 400 });
  }
}
