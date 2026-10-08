import { runProjectScan } from '../../../lib/platform';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 300;

export async function POST(request) {
  try {
    const body = await request.json();

    if (body.authorized !== true) {
      return Response.json({ error: 'Authorization confirmation is required.' }, { status: 400 });
    }

    if (!body.projectId || !body.assetId) {
      return Response.json({ error: 'Project and asset are required.' }, { status: 400 });
    }

    const scan = await runProjectScan(body.projectId, body.assetId, body.trigger || 'manual');
    return Response.json(scan, { headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    return Response.json({ error: error.message || 'Scan failed.' }, { status: 400 });
  }
}
