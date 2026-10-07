import crypto from 'node:crypto';
import { get, list, put } from '@vercel/blob';

const STATE_PATH = 'inspector/state.json';

function initialState() {
  return {
    version: 1,
    workspace: {
      id: 'default',
      name: 'Inspector Workspace',
      webhookUrl: '',
      createdAt: new Date().toISOString()
    },
    projects: [],
    scans: [],
    updatedAt: new Date().toISOString()
  };
}

async function readBlobText(url) {
  const result = await get(url, { access: 'private' });
  if (!result) return null;
  return await new Response(result.stream).text();
}

export async function readState() {
  try {
    const result = await list({ prefix: STATE_PATH, limit: 1 });
    const blob = result.blobs.find((item) => item.pathname === STATE_PATH);
    if (!blob) return initialState();
    const text = await readBlobText(blob.url);
    if (!text) return initialState();
    const parsed = JSON.parse(text);
    return { ...initialState(), ...parsed };
  } catch (error) {
    console.error('state read failed', error);
    return initialState();
  }
}

export async function writeState(state) {
  const next = { ...state, updatedAt: new Date().toISOString() };
  await put(STATE_PATH, JSON.stringify(next), {
    access: 'private',
    addRandomSuffix: false,
    allowOverwrite: true,
    contentType: 'application/json',
    cacheControlMaxAge: 0
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
  return {
    id,
    name: String(input.name || new URL(url).hostname || 'Project'),
    description: String(input.description || ''),
    schedule: input.schedule === 'daily' || input.schedule === 'weekly' ? input.schedule : 'manual',
    webhookUrl: String(input.webhookUrl || ''),
    createdAt: new Date().toISOString(),
    assets: [
      {
        id: crypto.randomUUID(),
        type: 'web',
        url,
        label: new URL(url).hostname,
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
