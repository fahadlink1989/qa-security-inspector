import { mutateState, readState } from '../../../lib/store';
import { runAuthenticatedScan } from '../../../lib/authenticatedScan';
import { generateIntelligence } from '../../../lib/intelligence';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 300;

export async function POST(request) {
  try {
    const body = await request.json();

    if (body.authorized !== true) {
      throw new Error('Authorization confirmation is required.');
    }
    if (!body.projectId || !body.assetId) {
      throw new Error('Project and asset are required.');
    }
    if (!body.authType || !body.credential) {
      throw new Error('Authenticated Scan requires a bearer token or cookie header.');
    }

    const state = await readState();
    const project = state.projects.find((item) => item.id === body.projectId);
    if (!project) throw new Error('Project not found.');
    const asset = project.assets.find((item) => item.id === body.assetId);
    if (!asset) throw new Error('Asset not found.');

    const sourceScan = [...state.scans]
      .filter((item) =>
        item.projectId === body.projectId &&
        item.assetId === body.assetId &&
        ['completed','completed_with_gaps','partial'].includes(item.status)
      )
      .sort((a,b) => {
        const aDeep = a.mode === 'deep' ? 1 : 0;
        const bDeep = b.mode === 'deep' ? 1 : 0;
        if (aDeep !== bDeep) return bDeep - aDeep;
        return String(b.completedAt || '').localeCompare(String(a.completedAt || ''));
      })[0] || null;

    const previous = [...(project.authScans || [])]
      .filter((item) => item.assetId === body.assetId && item.auth?.method === body.authType)
      .sort((a,b) => String(b.completedAt || '').localeCompare(String(a.completedAt || '')))[0] || null;

    const authScan = await runAuthenticatedScan({
      url: asset.url,
      sourceScan,
      previousScan: previous,
      auth: {
        type: body.authType === 'cookie' ? 'cookie' : 'bearer',
        value: String(body.credential || '')
      }
    });

    authScan.projectId = body.projectId;
    authScan.assetId = body.assetId;

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
      authScan.intelligence = {
        mode:'rules',
        generatedAt:new Date().toISOString(),
        aiError:String(error?.message || error).slice(0,300)
      };
    }

    await mutateState((next) => {
      const target = next.projects.find((item) => item.id === body.projectId);
      if (!target) throw new Error('Project not found.');
      target.authScans = [authScan, ...(target.authScans || [])].slice(0, 10);
      return next;
    });

    return Response.json(authScan, {
      headers: { 'cache-control': 'no-store' }
    });
  } catch (error) {
    return Response.json(
      { error: error?.message || 'Authenticated Scan failed.' },
      { status: 400 }
    );
  }
}
