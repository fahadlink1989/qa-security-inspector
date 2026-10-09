import { readState,mutateState,capHistory } from './store';
import { workspaceContext } from './backend/context';
import { decryptPayload } from './backend/crypto';
import { assertPublicTarget } from './net';
import { normalizePageSpeed,providerError } from './performanceModel.mjs';
export async function runPerformanceTask(projectId,assetId,progress){
  const state=await readState();
  const project=state.projects.find(p=>p.id===projectId),asset=project?.assets.find(a=>a.id===assetId);
  if(!asset)throw new Error('Target not found');
  const url=new URL(asset.url);
  if(!['http:','https:'].includes(url.protocol)||url.username||url.password)throw new Error('Invalid public URL');
  await assertPublicTarget(url);
  const {workspaceId,jobId}=workspaceContext();
  const key=state.workspace.performanceKey?decryptPayload(state.workspace.performanceKey,workspaceId+':pagespeed').key:process.env.PAGESPEED_API_KEY;
  const scan={id:jobId,projectId,assetId,url:url.href,type:'performance',scanType:'Website Performance',provider:'Google PageSpeed Insights',startedAt:new Date().toISOString(),devices:{},findings:[],summary:{}};
  for(const [index,strategy] of ['mobile','desktop'].entries()){
    await progress(10+index*45,'Google PageSpeed: '+strategy+' measurement');
    const endpoint=new URL('https://pagespeedonline.googleapis.com/pagespeedonline/v5/runPagespeed');
    endpoint.searchParams.set('url',url.href);endpoint.searchParams.set('strategy',strategy);endpoint.searchParams.set('category','performance');
    if(key)endpoint.searchParams.set('key',key);
    try{
      const response=await fetch(endpoint,{signal:AbortSignal.timeout(150000),redirect:'error'});
      if(!response.ok){scan.devices[strategy]={strategy,status:'failed',httpStatus:response.status,error:providerError(response.status)};continue;}
      const data=await response.json();
      scan.devices[strategy]=normalizePageSpeed(data,strategy);
    }catch{scan.devices[strategy]={strategy,status:'failed',error:'Google could not measure this page (timeout, navigation failure, or invalid result). No score is available. Try again after checking that the public page loads.'};}
  }
  const completed=Object.values(scan.devices).filter(d=>d.status==='completed').length;
  scan.status=completed===2?'completed':completed?'completed_with_gaps':'failed';
  scan.completedAt=new Date().toISOString();scan.coverageGaps=Object.values(scan.devices).filter(d=>d.status!=='completed').map(d=>d.strategy+': '+d.error);
  scan.error=completed===0?scan.coverageGaps.join(' '):null;
  scan.engineRuns=Object.values(scan.devices).map(d=>({engine:'pagespeed-'+d.strategy,name:'Google PageSpeed '+d.strategy,status:d.status,error:d.error||null}));
  await mutateState(draft=>{const p=draft.projects.find(p=>p.id===projectId);p.performanceScans=capHistory([scan,...(p.performanceScans||[]).filter(s=>s.id!==scan.id)],40);return draft;});
  return scan;
}
