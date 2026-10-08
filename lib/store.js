import crypto from 'node:crypto';
import { get, list, put } from '@vercel/blob';

const LEGACY_STATE_PATH = 'inspector/state.json';
const STATE_PREFIX = 'inspector/state/';

function initialState() {
  return {
    version: 2,
    workspace: {
      id: 'default',
      name: 'Inspector Workspace',
      webhookUrl: '',
      createdAt: new Date().toISOString()
    },
    projects: [],
    scans: [],
    jobs: [],
    updatedAt: new Date().toISOString()
  };
}

async function readBlobText(url) {
  const result = await get(url, { access: 'private', useCache: false });
  if (!result) return null;
  return await new Response(result.stream).text();
}

async function latestVersionedStateBlob() {
  let cursor;
  const blobs = [];

  do {
    const page = await list({ prefix: STATE_PREFIX, cursor, limit: 100 });
    blobs.push(...page.blobs);
    cursor = page.cursor;
  } while (cursor && blobs.length < 1000);

  return blobs
    .filter((item) => item.pathname.startsWith(STATE_PREFIX))
    .sort((a, b) => new Date(b.uploadedAt || 0).getTime() - new Date(a.uploadedAt || 0).getTime())[0] || null;
}

async function legacyStateBlob() {
  const result = await list({ prefix: LEGACY_STATE_PATH, limit: 10 });
  return result.blobs.find((item) => item.pathname === LEGACY_STATE_PATH) || null;
}

export async function readState() {
  try {
    const blob = (await latestVersionedStateBlob()) || (await legacyStateBlob());
    if (!blob) return initialState();

    const text = await readBlobText(blob.url);
    if (!text) return initialState();

    const parsed = JSON.parse(text);
    return {
      ...initialState(),
      ...parsed,
      version: 2,
      workspace: {
        ...initialState().workspace,
        ...(parsed.workspace || {})
      },
      projects: Array.isArray(parsed.projects) ? parsed.projects.map((project)=>({
        ...project,
        scheduledMode:project.scheduledMode==='deep'?'deep':'standard',
        networks:Array.isArray(project.networks)?project.networks:[],
        networkScans:Array.isArray(project.networkScans)?project.networkScans:[]
      })) : [],
      scans: Array.isArray(parsed.scans) ? parsed.scans : [],
      jobs: Array.isArray(parsed.jobs) ? parsed.jobs : []
    };
  } catch (error) {
    console.error('state read failed', error);
    return initialState();
  }
}

export async function writeState(state) {
  const now = new Date();
  const next = {
    ...state,
    version: 2,
    updatedAt: now.toISOString()
  };

  const pathname =
    STATE_PREFIX +
    String(now.getTime()).padStart(13, '0') +
    '-' +
    crypto.randomUUID() +
    '.json';

  await put(pathname, JSON.stringify(next), {
    access: 'private',
    addRandomSuffix: false,
    contentType: 'application/json',
    cacheControlMaxAge: 60
  });

  return next;
}

export async function mutateState(mutator) {
  const state = await readState();
  const next = await mutator(structuredClone(state));
  return writeState(next || state);
}

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
