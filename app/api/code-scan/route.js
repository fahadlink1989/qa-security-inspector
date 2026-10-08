import { mutateState, readState } from '../../../lib/store';
import { scanGitHubRepository } from '../../../lib/codeSecurity';
import { generateCodeIntelligence } from '../../../lib/intelligence';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 300;

export async function POST(request) {
  try {
    const body = await request.json();

    if (!body.projectId) throw new Error('Project is required.');
    if (body.authorized !== true) throw new Error('Authorization confirmation is required.');
    if (!body.repositoryUrl) throw new Error('GitHub repository URL is required.');

    const state = await readState();
    const project = state.projects.find((item) => item.id === body.projectId);
    if (!project) throw new Error('Project not found.');

    const codeScan = await scanGitHubRepository({
      repositoryUrl: body.repositoryUrl,
      token: body.token || ''
    });

    codeScan.projectId = body.projectId;
    codeScan.remediationPlan = await generateCodeIntelligence(codeScan);

    await mutateState((next) => {
      const target = next.projects.find((item) => item.id === body.projectId);
      if (!target) throw new Error('Project not found.');
      target.codeScans = [codeScan, ...(target.codeScans || [])].slice(0, 10);
      return next;
    });

    return Response.json(codeScan, {
      headers: { 'cache-control': 'no-store' }
    });
  } catch (error) {
    return Response.json(
      { error: error?.message || 'Code Security scan failed.' },
      { status: 400 }
    );
  }
}
