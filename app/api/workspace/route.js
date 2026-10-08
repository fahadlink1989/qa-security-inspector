import crypto from 'node:crypto';
import net from 'node:net';
import { updateRiskInState } from '../../../lib/riskModel';
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
    jobs: state.jobs || [],
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
    if (['standard','deep'].includes(patch.scheduledMode)) project.scheduledMode = patch.scheduledMode;
    if(Array.isArray(patch.scheduledEngines)){
      if(patch.scheduledEngines.some(e=>!['zap','nuclei'].includes(e))) throw new Error('Unsupported scheduled engine.');
      project.scheduledEngines=patch.scheduledEngines;
    }
    if(patch.scheduleAuthorized===true) project.scheduleAuthorized=true;
    if(Array.isArray(patch.scheduledAssetIds)) {
      if(patch.scheduledAssetIds.some(id=>!project.assets.some(a=>a.id===id))) throw new Error('Scheduled target not found.');
      project.scheduledAssetIds=patch.scheduledAssetIds;
    }
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
    if(project.assets.some(a=>a.url===url.href)) throw new Error('This target is already registered.');
    project.assets.push(asset);
    return state;
  });

  return asset;
}

async function manageAsset(projectId, assetId, patch, remove=false) {
  let result;
  await mutateState(state => {
    const project=state.projects.find(p=>p.id===projectId);
    const asset=project?.assets.find(a=>a.id===assetId);
    if(!asset) throw new Error('Target not found.');
    if((state.jobs||[]).some(j=>j.assetId===assetId&&['queued','running'].includes(j.status))) throw new Error('Wait for the active scan before changing this target.');
    if(remove) { project.assets=project.assets.filter(a=>a.id!==assetId); result={id:assetId,removed:true}; }
    else {
      if(patch.url && patch.url!==asset.url) throw new Error('Add a new target to change its URL and preserve scan history.');
      if(patch.label!==undefined) asset.label=String(patch.label).trim().slice(0,100)||new URL(asset.url).hostname;
      result=asset;
    }
    return state;
  });
  return result;
}

function privateIpv4(ip){
  const parts=String(ip||'').split('.').map(Number);
  if(parts.length!==4||parts.some((n)=>!Number.isInteger(n)||n<0||n>255)) return false;
  return parts[0]===10 ||
    (parts[0]===172&&parts[1]>=16&&parts[1]<=31) ||
    (parts[0]===192&&parts[1]===168);
}

function validatePrivateCidr(value){
  const [ip,prefixRaw]=String(value||'').trim().split('/');
  const prefix=Number(prefixRaw);
  if(net.isIP(ip)!==4 || !privateIpv4(ip) || !Number.isInteger(prefix) || prefix<24 || prefix>32){
    throw new Error('Internal networks must be an RFC1918 IPv4 CIDR between /24 and /32.');
  }
  return ip+'/'+prefix;
}

async function addNetworkTarget(projectId,input){
  const cidr=validatePrivateCidr(input.cidr);
  let target=null;
  await mutateState((state)=>{
    const project=state.projects.find((item)=>item.id===projectId);
    if(!project) throw new Error('Project not found.');
    project.networks=Array.isArray(project.networks)?project.networks:[];
    if(project.networks.some((item)=>item.cidr===cidr)) throw new Error('This network is already registered.');
    target={
      id:crypto.randomUUID(),
      cidr,
      label:String(input.label||cidr).slice(0,100),
      status:'active',
      createdAt:new Date().toISOString()
    };
    project.networks.push(target);
    return state;
  });
  return target;
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

async function updateNetworkFindingStatus(projectId, networkScanId, fingerprint, status) {
  if (!['open','in_progress','resolved','accepted','false_positive'].includes(status)) {
    throw new Error('Invalid finding status.');
  }

  let changed = null;
  await mutateState((state) => {
    const project = state.projects.find((item) => item.id === projectId);
    if (!project) throw new Error('Project not found.');
    const scan = (project.networkScans || []).find((item) => item.id === networkScanId);
    if (!scan) throw new Error('Network scan not found.');
    const finding = (scan.findings || []).find((item) => item.fingerprint === fingerprint);
    if (!finding) throw new Error('Finding not found.');
    finding.workflowStatus = status;
    finding.statusUpdatedAt = new Date().toISOString();
    changed = finding;
    return state;
  });
  return changed;
}

async function updateAuthFindingStatus(projectId, authScanId, fingerprint, status) {
  if (!['open','in_progress','resolved','accepted','false_positive'].includes(status)) {
    throw new Error('Invalid finding status.');
  }

  let changed = null;
  await mutateState((state) => {
    const project = state.projects.find((item) => item.id === projectId);
    if (!project) throw new Error('Project not found.');
    const authScan = (project.authScans || []).find((item) => item.id === authScanId);
    if (!authScan) throw new Error('Authenticated Scan not found.');
    const finding = (authScan.findings || []).find((item) => item.fingerprint === fingerprint);
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

    if (body.action === 'risk_update') {
      await mutateState(state=>{result=updateRiskInState(state,body.scanId,body.fingerprint,body.patch||{});return state;});
    } else if (body.action === 'update_asset' || body.action === 'remove_asset') {
      result=await manageAsset(body.projectId,body.assetId,body.patch||{},body.action==='remove_asset');
    } else if (body.action === 'create_project') {
      if (!body.url) throw new Error('Project URL is required.');
      result = await createProject(body);
    } else if (body.action === 'update_project') {
      result = await updateProject(body.projectId, body.patch || {});
    } else if (body.action === 'add_asset') {
      result = await addAsset(body.projectId, body);
    } else if (body.action === 'add_network_target') {
      result = await addNetworkTarget(body.projectId, body);
    } else if (body.action === 'finding_status') {
      result = await updateFindingStatus(body.scanId, body.fingerprint, body.status);
    } else if (body.action === 'retest_finding') {
      const { retestFinding } = await import('../../../lib/scanService');
      result = await retestFinding(body.scanId, body.fingerprint);
    } else if (body.action === 'network_finding_status') {
      result = await updateNetworkFindingStatus(
        body.projectId,
        body.networkScanId,
        body.fingerprint,
        body.status
      );
    } else if (body.action === 'auth_finding_status') {
      result = await updateAuthFindingStatus(
        body.projectId,
        body.authScanId,
        body.fingerprint,
        body.status
      );
    } else {
      throw new Error('Unknown action.');
    }

    return Response.json({ ok: true, result }, { headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    return Response.json({ error: error?.message || 'Request failed.' }, { status: 400 });
  }
}
