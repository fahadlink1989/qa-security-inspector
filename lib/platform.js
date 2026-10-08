import crypto from 'node:crypto';
import { capHistory, latestScanForProject, makeProject, mutateState, readState } from './store';
import { buildExecutiveSummary, runFullScan } from './scanner';
import { runDeepScan } from './deepScan';
import { generateIntelligence } from './intelligence';

function publicProject(project) {
  return {
    ...project,
    webhookUrl: project.webhookUrl ? 'configured' : ''
  };
}

export async function getWorkspaceView() {
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
    workspace: { ...state.workspace, webhookUrl: state.workspace.webhookUrl ? 'configured' : '' },
    projects,
    scans: state.scans,
    updatedAt: state.updatedAt
  };
}

export async function createProject(input) {
  const project = makeProject(input);
  await mutateState((state) => {
    state.projects.unshift(project);
    return state;
  });
  return project;
}

export async function updateProject(projectId, patch) {
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

export async function addAsset(projectId, input) {
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

async function notifyWebhook(project, scan) {
  const webhookUrl = project.webhookUrl;
  if (!webhookUrl) return;
  const urgent = scan.findings.filter((f) => ['Critical','High'].includes(f.severity) && f.lifecycle === 'new');
  if (!urgent.length) return;
  try {
    const parsed = new URL(webhookUrl);
    if (parsed.protocol !== 'https:') return;
    await fetch(parsed, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        text: `Inspector: ${urgent.length} new high-priority findings on ${scan.host} (score ${scan.score}/100)`,
        scan: {
          id: scan.id,
          url: scan.url,
          score: scan.score,
          summary: scan.summary,
          newHighPriority: urgent.map((f) => ({ title:f.title, severity:f.severity, checkId:f.checkId }))
        }
      }),
      signal: AbortSignal.timeout(5000)
    });
  } catch (error) {
    console.error('webhook delivery failed', error);
  }
}

export async function runProjectScan(projectId, assetId, trigger = 'manual', mode = 'standard') {
  const before = await readState();
  const project = before.projects.find((item) => item.id === projectId);
  if (!project) throw new Error('Project not found.');
  const asset = project.assets.find((item) => item.id === assetId) || project.assets[0];
  if (!asset) throw new Error('Asset not found.');
  const normalizedMode = mode === 'deep' ? 'deep' : 'standard';
  const previous = before.scans
    .filter((item) =>
      item.projectId === projectId &&
      item.assetId === asset.id &&
      (item.mode || 'standard') === normalizedMode &&
      ['completed','completed_with_gaps','partial'].includes(item.status)
    )
    .sort((a,b) => String(b.completedAt).localeCompare(String(a.completedAt)))[0] || null;

  const scan = normalizedMode === 'deep'
    ? await runDeepScan({ url: asset.url, previousScan: previous })
    : await runFullScan({ url: asset.url, previousScan: previous });
  scan.mode = normalizedMode;
  scan.scanType = normalizedMode === 'deep' ? 'Deep Scan' : 'Standard Scan';
  scan.projectId = projectId;
  scan.assetId = asset.id;
  scan.trigger = trigger;
  scan.executiveSummary = buildExecutiveSummary(scan);
  try {
    const intelligence = await generateIntelligence(scan);
    scan.intelligence = {
      mode:intelligence?.mode || 'rules',
      model:intelligence?.model || null,
      generatedAt:intelligence?.generatedAt || new Date().toISOString(),
      aiError:intelligence?.aiError || null
    };
    scan.remediationPlan = intelligence;
    if (intelligence?.executiveSummary) scan.executiveSummary = intelligence.executiveSummary;
  } catch (error) {
    console.error('AI intelligence unavailable', error);
    scan.intelligence = { mode:'rules', generatedAt:new Date().toISOString(), error:String(error?.message || error).slice(0,200) };
    scan.remediationPlan = null;
  }

  await mutateState((state) => {
    state.scans = capHistory([scan, ...state.scans], 60);
    return state;
  });

  await notifyWebhook(project, scan);
  return scan;
}

export async function updateFindingStatus(scanId, fingerprint, status) {
  if (!['open','in_progress','resolved','accepted','false_positive'].includes(status)) throw new Error('Invalid finding status.');
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


export async function retestFinding(scanId, fingerprint) {
  const state = await readState();
  const original = state.scans.find((item) => item.id === scanId);
  if (!original) throw new Error('Scan not found.');
  const sourceFinding = original.findings.find((item) => item.fingerprint === fingerprint);
  if (!sourceFinding) throw new Error('Finding not found.');

  const scan = await runProjectScan(original.projectId, original.assetId, 'retest', original.mode === 'deep' ? 'deep' : 'standard');
  const current = scan.findings.find((item) => item.fingerprint === fingerprint) || null;

  return {
    status: current ? 'still_present' : 'resolved',
    sourceFinding: {
      fingerprint,
      title: sourceFinding.title,
      severity: sourceFinding.severity,
      checkId: sourceFinding.checkId
    },
    currentFinding: current,
    scan
  };
}
