import crypto from 'node:crypto';
import { database, transaction } from './backend/db';
import { workspaceContext } from './backend/context';

export function initialState(id, name='Inspector Workspace') {
  return {version:4,workspace:{id,name,webhookUrl:'',createdAt:new Date().toISOString()},projects:[],scans:[],jobs:[],updatedAt:new Date().toISOString()};
}
export async function readState() {
  const {workspaceId}=workspaceContext();
  const {rows}=await database().query('SELECT state FROM inspector_workspaces WHERE id=$1',[workspaceId]);
  if(!rows.length) throw new Error('Workspace not found.');
  const jobs=await database().query('SELECT data FROM inspector_jobs WHERE workspace_id=$1 ORDER BY created_at DESC LIMIT 200',[workspaceId]);
  return {...rows[0].state,jobs:jobs.rows.map(r=>r.data)};
}
export async function mutateState(mutator) {
  const {workspaceId,jobId,leaseToken}=workspaceContext();
  return transaction(async client=>{
    const {rows}=await client.query('SELECT state FROM inspector_workspaces WHERE id=$1 FOR UPDATE',[workspaceId]);
    if(!rows.length) throw new Error('Workspace not found.');
    if(jobId) {
      const lease=await client.query("SELECT id FROM inspector_jobs WHERE id=$1 AND workspace_id=$2 AND lease_token=$3 AND status='running' AND lease_until>now() FOR UPDATE",[jobId,workspaceId,leaseToken]);
      if(!lease.rowCount) throw new Error('Scan lease expired; stale results were rejected.');
    }
    const draft=structuredClone(rows[0].state);
    const next=await mutator(draft)||draft;
    next.jobs=[]; next.updatedAt=new Date().toISOString(); next.version=4;
    await client.query('UPDATE inspector_workspaces SET state=$2,revision=revision+1 WHERE id=$1',[workspaceId,JSON.stringify(next)]);
    return next;
  });
}
export async function writeState() { throw new Error('Use transactional mutateState; whole-state replacement is disabled.'); }

export function makeProject(input = {}) {
  const id = crypto.randomUUID();
  const url = String(input.url || '').trim();
  const parsed = new URL(url);

  return {
    id,
    name: String(input.name || parsed.hostname || 'Project'),
    description: String(input.description || ''),
    schedule: input.schedule === 'daily' || input.schedule === 'weekly' ? input.schedule : 'manual',
    scheduledMode: input.scheduledMode === 'deep' ? 'deep' : 'standard',
    webhookUrl: String(input.webhookUrl || ''),
    networks: [],
    networkScans: [],
    createdAt: new Date().toISOString(),
    assets: [
      {
        id: crypto.randomUUID(),
        type: 'web',
        url: parsed.href,
        label: parsed.hostname,
        status: 'active',
        createdAt: new Date().toISOString()
      }
    ]
  };
}

export function latestScanForProject(state, projectId) {
  return state.scans
    .filter((scan) => scan.projectId === projectId)
    .sort((a, b) => String(b.completedAt || b.startedAt).localeCompare(String(a.completedAt || a.startedAt)))[0] || null;
}

export function capHistory(scans, max = 60) {
  return [...scans]
    .sort((a, b) => String(b.completedAt || b.startedAt).localeCompare(String(a.completedAt || a.startedAt)))
    .slice(0, max);
}

