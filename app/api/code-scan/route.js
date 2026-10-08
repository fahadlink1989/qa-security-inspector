import { runProjectCodeScan } from '../../../lib/platform';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 300;

export async function POST(request) {
  try {
    const body = await request.json();
    if (!body.projectId) throw new Error('Project is required.');
    const result = await runProjectCodeScan(body.projectId, body);
    return Response.json(result, { headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    return Response.json({ error: error.message || 'Code scan failed.' }, { status: 400 });
  }
}
