import { capHistory, mutateState, readState } from './store';
import { buildExecutiveSummary, runFullScan } from './scanner';
import { runDeepScan } from './deepScan';
import { generateIntelligence } from './intelligence';

async function notifyWebhook(project, scan) {
  const webhookUrl = project.webhookUrl;
  if (!webhookUrl) return;
  const urgent = (scan.findings || []).filter(
    (finding) => ['Critical','High'].includes(finding.severity) && finding.lifecycle === 'new'
  );
  if (!urgent.length) return;

  try {
    const parsed = new URL(webhookUrl);
    if (parsed.protocol !== 'https:') return;
    await fetch(parsed, {
      method:'POST',
      headers:{'content-type':'application/json'},
      body:JSON.stringify({
        text:`Inspector: ${urgent.length} new high-priority findings on ${scan.host} (score ${scan.score}/100)`,
        scan:{
          id:scan.id,
          url:scan.url,
          score:scan.score,
          summary:scan.summary,
          newHighPriority:urgent.map((finding)=>({
            title:finding.title,
            severity:finding.severity,
            checkId:finding.checkId
          }))
        }
      }),
      signal:AbortSignal.timeout(5000)
    });
  } catch (error) {
    console.error('webhook delivery failed', error);
  }
}

export async function runProjectScan(projectId, assetId, trigger='manual', mode='standard') {
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
    .sort((a,b) => String(b.completedAt || '').localeCompare(String(a.completedAt || '')))[0] || null;

  const scan = normalizedMode === 'deep'
    ? await runDeepScan({url:asset.url,previousScan:previous})
    : await runFullScan({url:asset.url,previousScan:previous});

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
      provider:intelligence?.provider || null,
      model:intelligence?.model || null,
      generatedAt:intelligence?.generatedAt || new Date().toISOString(),
      aiError:intelligence?.aiError || null
    };
    scan.remediationPlan = intelligence;
    if (intelligence?.executiveSummary) scan.executiveSummary = intelligence.executiveSummary;
  } catch (error) {
    console.error('AI intelligence unavailable', error);
    scan.intelligence = {
      mode:'rules',
      generatedAt:new Date().toISOString(),
      aiError:String(error?.message || error).slice(0,300)
    };
    scan.remediationPlan = null;
  }

  await mutateState((state) => {
    state.scans = capHistory([scan, ...state.scans], 60);
    return state;
  });

  await notifyWebhook(project, scan);
  return scan;
}

export async function retestFinding(scanId, fingerprint) {
  const state = await readState();
  const original = state.scans.find((item) => item.id === scanId);
  if (!original) throw new Error('Scan not found.');

  const sourceFinding = original.findings.find((item) => item.fingerprint === fingerprint);
  if (!sourceFinding) throw new Error('Finding not found.');

  const scan = await runProjectScan(
    original.projectId,
    original.assetId,
    'retest',
    original.mode === 'deep' ? 'deep' : 'standard'
  );

  const current = scan.findings.find((item) => item.fingerprint === fingerprint) || null;

  return {
    status:current ? 'still_present' : 'resolved',
    sourceFinding:{
      fingerprint,
      title:sourceFinding.title,
      severity:sourceFinding.severity,
      checkId:sourceFinding.checkId
    },
    currentFinding:current,
    scan
  };
}
