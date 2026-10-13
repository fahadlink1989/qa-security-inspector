import {getScan,saveScan,patchScan,latestStoredScan,updateStoredRisk} from './backend/scanRepository';
import { deliverWebhook } from './webhook';
import { workspaceContext } from './backend/context';
import { retestOutcome } from './riskModel.mjs';
import { readState } from './store';
import { buildExecutiveSummary, runFullScan } from './scanner';
import { runDeepScan } from './deepScan';
import { generateIntelligence } from './intelligence';
import { runWorkerEngine, scannerWorkerHealth } from './workerClient';
import { mergeEngineResults, failedEngineRun } from './engineMerge';

async function notifyWebhook(project, scan) {
  if(!project.webhookUrl)return {status:'not_configured'};
  const urgent=(scan.findings||[]).filter(f=>['Critical','High'].includes(f.severity)&&f.lifecycle==='new');
  if(!urgent.length)return {status:'not_needed'};
  try { return {...await deliverWebhook(project.webhookUrl,{text:`Inspector: ${urgent.length} new high-priority findings`,scan:{id:scan.id,url:scan.url,newHighPriority:urgent.map(f=>({title:f.title,severity:f.severity,checkId:f.checkId}))}}),at:new Date().toISOString()}; }
  catch(error){return {status:'failed',error:error.message,at:new Date().toISOString()};}
}

export async function runProjectScan(projectId, assetId, trigger='manual', mode='standard', onProgress=null, expectedTarget=null) {
  const before = await readState({history:false});
  const project = before.projects.find((item) => item.id === projectId);
  if (!project) throw new Error('Project not found.');
  const reportProgress=async(progress,stage)=>{
    if(typeof onProgress==='function'){
      try{await onProgress({progress,stage});}catch{}
    }
  };
  await reportProgress(8,'Preparing target');

  const asset = project.assets.find((item) => item.id === assetId && item.status === 'active');
  if (!asset) throw new Error('Asset not found.');
  if(expectedTarget&&asset.url!==expectedTarget)throw new Error('Target changed after scan authorization.');

  const normalizedMode = mode === 'deep' ? 'deep' : 'standard';
  const previous=await latestStoredScan('web',projectId,{assetId:asset.id,mode:normalizedMode});

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
  await saveScan('web',scan);

  const notification=await notifyWebhook(project,scan);
  await patchScan('web',scan.id,{notification});
  scan.notification=notification;
  await reportProgress(100,'Completed');
  return scan;
}

export async function retestFinding(scanId, fingerprint) {
  const original = await getScan('web',scanId);
  if (!original) throw new Error('Scan not found.');

  const sourceFinding = original.findings.find((item) => item.fingerprint === fingerprint);
  if (!sourceFinding) throw new Error('Finding not found.');

  const jobId=workspaceContext().jobId;
  const savedResult=jobId?await getScan('web',jobId):null;
  const scan = savedResult || await runProjectScan(
    original.projectId,
    original.assetId,
    'retest',
    original.mode === 'deep' ? 'deep' : 'standard'
  );

  const current = scan.findings.find((item) => item.fingerprint === fingerprint) || null;

  const outcome=retestOutcome(scan,fingerprint);
  await updateStoredRisk({projectId:original.projectId,kind:'web',scanId,fingerprint,...(outcome==='resolved'?{status:'resolved'}:{})},'verified-retest',{scanId:scan.id,status:outcome,at:new Date().toISOString()});

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



