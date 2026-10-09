import { workspaceContext } from './backend/context';
import { retestOutcome, applyWorkflow } from './riskModel.mjs';
import { capHistory, mutateState, readState } from './store';
import { buildExecutiveSummary, runFullScan } from './scanner';
import { runDeepScan } from './deepScan';
import { generateIntelligence } from './intelligence';
import { runWorkerEngine, scannerWorkerHealth } from './workerClient';
import { mergeEngineResults, failedEngineRun } from './engineMerge';

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

export async function runProjectScan(projectId, assetId, trigger='manual', mode='standard', onProgress=null) {
  const before = await readState();
  const project = before.projects.find((item) => item.id === projectId);
  if (!project) throw new Error('Project not found.');
  const reportProgress=async(progress,stage)=>{
    if(typeof onProgress==='function'){
      try{await onProgress({progress,stage});}catch{}
    }
  };
  await reportProgress(8,'Preparing target');

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

  await reportProgress(15,normalizedMode==='deep'?'Discovering attack surface':'Running Inspector web checks');
  const scan = normalizedMode === 'deep'
    ? await runDeepScan({url:asset.url,previousScan:previous})
    : await runFullScan({url:asset.url,previousScan:previous});
  await reportProgress(58,'Inspector core scan complete');

  scan.mode = normalizedMode;

  const workerStatus=await scannerWorkerHealth();
  const workerResults=[];
  const expectedEngines=normalizedMode==='deep'
    ? [
        {engine:'zap',name:'OWASP ZAP Passive',profile:'safe'},
        {engine:'nuclei',name:'Nuclei Safe',profile:'deep'}
      ]
    : [
        {engine:'zap',name:'OWASP ZAP Passive',profile:'safe'}
      ];
  if(workerStatus.connected){
    let completedEngines=0;
    const settled=await Promise.all(expectedEngines.map(async(item)=>{
      try{
        await reportProgress(60+Math.round((completedEngines/Math.max(1,expectedEngines.length))*20),'Running '+item.name);
        return await runWorkerEngine({
          engine:item.engine,
          target:asset.url,
          profile:item.profile,
          metadata:{projectId,assetId:asset.id,mode:normalizedMode}
        });
      }catch(error){
        return failedEngineRun(item.engine,item.name,error);
      }finally{
        completedEngines+=1;
        await reportProgress(60+Math.round((completedEngines/Math.max(1,expectedEngines.length))*22),item.name+' complete');
      }
    }));
    workerResults.push(...settled);
  } else {
    workerResults.push(...expectedEngines.map((item)=>({
      engine:item.engine,
      name:item.name,
      status:'skipped',
      findings:[],
      error:workerStatus.health?.error||'The isolated scanner worker is not connected. Built-in Inspector checks still ran; this engine produced no results.'
    })));
  }

  mergeEngineResults(scan,workerResults,previous);
  await reportProgress(85,'Normalizing findings');
  scan.scanType = normalizedMode === 'deep' ? 'Attack Surface Scan' : 'Web App Scan';
  scan.workerConfigured = workerStatus.connected;
  scan.projectId = projectId;
  scan.assetId = asset.id;
  scan.trigger = trigger;
  scan.executiveSummary = buildExecutiveSummary(scan);

  await reportProgress(90,'Building remediation guidance');
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

  await reportProgress(96,'Saving scan results');
  scan.id=workspaceContext().jobId||scan.id;
  await mutateState((state) => {
    state.scans = capHistory([scan, ...state.scans.filter(item=>item.id!==scan.id)], 60);
    return state;
  });

  await notifyWebhook(project, scan);
  await reportProgress(100,'Completed');
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

  const outcome=retestOutcome(scan,fingerprint);
  await mutateState(state=>{
    const saved=state.scans.find(item=>item.id===scanId)?.findings?.find(item=>item.fingerprint===fingerprint);
    if(saved){
      saved.retests=[...(saved.retests||[]),{scanId:scan.id,status:outcome,at:new Date().toISOString()}];
      if(outcome==='resolved') applyWorkflow(saved,'resolved');
    }
    return state;
  });
  return {
    status:outcome,
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

