import crypto from 'node:crypto';
import { latestScanForProject, makeProject, mutateState, readState } from '../../../lib/store';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 30;

function publicProject(project) {
  return {
    ...project,
    webhookUrl: project.webhookUrl ? 'configured' : ''
  };
}

async function getWorkspaceView() {
  const state = await readState();
  const projects = state.projects.map((project) => {
    const latest = latestScanForProject(state, project.id);
    return {
      ...publicProject(project),
      latestScan: latest ? {
        id: latest.id,
        completedAt: latest.completedAt,
        score: latest.score,
        status: latest.status,
        summary: latest.summary,
        url: latest.url
      } : null
    };
  });

  return {
    version: state.version,
    workspace: {
      ...state.workspace,
      webhookUrl: state.workspace.webhookUrl ? 'configured' : ''
    },
    projects,
    scans: state.scans,
    updatedAt: state.updatedAt
  };
}

async function createProject(input) {
  const project = makeProject(input);
  await mutateState((state) => {
    state.projects.unshift(project);
    return state;
  });
  return project;
}

async function updateProject(projectId, patch) {
  let output = null;
  await mutateState((state) => {
    const project = state.projects.find((item) => item.id === projectId);
    if (!project) throw new Error('Project not found.');
    if (typeof patch.name === 'string' && patch.name.trim()) project.name = patch.name.trim();
    if (['manual','daily','weekly'].includes(patch.schedule)) project.schedule = patch.schedule;
    if (typeof patch.description === 'string') project.description = patch.description.slice(0,500);
    if (typeof patch.webhookUrl === 'string') project.webhookUrl = patch.webhookUrl.trim();
    output = project;
    return state;
  });
  return output;
}

async function addAsset(projectId, input) {
  let asset = null;
  const url = new URL(String(input.url || '').trim());
  if (!['http:','https:'].includes(url.protocol)) throw new Error('Only HTTP(S) assets are supported.');

  await mutateState((state) => {
    const project = state.projects.find((item) => item.id === projectId);
    if (!project) throw new Error('Project not found.');
    asset = {
      id: crypto.randomUUID(),
      type: 'web',
      url: url.href,
      label: String(input.label || url.hostname).slice(0,100),
      status: 'active',
      createdAt: new Date().toISOString()
    };
    project.assets.push(asset);
    return state;
  });

  return asset;
}

async function updateFindingStatus(scanId, fingerprint, status) {
  if (!['open','in_progress','resolved','accepted','false_positive'].includes(status)) {
    throw new Error('Invalid finding status.');
  }

  let changed = null;
  await mutateState((state) => {
    const scan = state.scans.find((item) => item.id === scanId);
    if (!scan) throw new Error('Scan not found.');
    const finding = scan.findings.find((item) => item.fingerprint === fingerprint);
    if (!finding) throw new Error('Finding not found.');
    finding.workflowStatus = status;
    finding.statusUpdatedAt = new Date().toISOString();
    changed = finding;
    return state;
  });
  return changed;
}

export async function GET() {
  try {
    const data = await getWorkspaceView();
    return Response.json(data, { headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    return Response.json({ error: error?.message || 'Could not load workspace.' }, { status: 500 });
  }
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
    } else if (body.action === 'retest_finding') {
      const { retestFinding } = await import('../../../lib/scanService');
      result = await retestFinding(body.scanId, body.fingerprint);
    } else {
      throw new Error('Unknown action.');
    }

    return Response.json({ ok: true, result }, { headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    return Response.json({ error: error?.message || 'Request failed.' }, { status: 400 });
  }
}
