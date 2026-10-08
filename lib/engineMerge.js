import crypto from 'node:crypto';
import { scoreFindings } from './scanner';

const severityRank={Critical:5,High:4,Medium:3,Low:2,Informational:1};

function summarize(findings){
  const out={critical:0,high:0,medium:0,low:0,informational:0};
  for(const finding of findings||[]){
    const key=String(finding.severity||'Informational').toLowerCase();
    if(key in out) out[key]+=1;
  }
  return out;
}
function stableFingerprint(item){
  if(item.fingerprint) return item.fingerprint;
  return crypto.createHash('sha256').update([
    item.engine||'worker',item.checkId||'',item.title||'',item.location||''
  ].join('|')).digest('hex').slice(0,20);
}
function normalizeFinding(item,engineName){
  const severity=['Critical','High','Medium','Low','Informational'].includes(item.severity)?item.severity:'Informational';
  const location=item.location||item.affectedLocations?.[0]||'';
  return {
    id:item.id||crypto.randomUUID(),
    fingerprint:stableFingerprint({...item,location}),
    checkId:item.checkId||'ENGINE-FINDING',
    category:item.category||'Security',
    severity,
    title:item.title||'Scanner finding',
    summary:item.summary||'Scanner finding.',
    impact:item.impact||item.summary||'',
    evidence:item.evidence||'',
    remediation:item.remediation||'Review the finding and apply the upstream remediation guidance.',
    confidence:item.confidence||'High',
    evidenceQuality:item.evidenceQuality||'scanner-validation',
    location,
    affectedLocations:item.affectedLocations?.length?item.affectedLocations:[location].filter(Boolean),
    engine:item.engine||engineName||'worker',
    lifecycle:item.lifecycle||'new',
    workflowStatus:item.workflowStatus||'open'
  };
}

export function mergeEngineResults(scan,engineResults=[],previousScan=null){
  const previous=new Map((previousScan?.findings||[]).map(item=>[item.fingerprint,item]));
  const map=new Map();

  for(const raw of scan.findings||[]){
    const item=normalizeFinding(raw,raw.engine);
    map.set(item.fingerprint,item);
  }

  const engineRuns=[
    {
      engine:'inspector',
      name:scan.mode==='deep'?'Inspector Deep Engine':'Inspector Web Engine',
      status:['completed','completed_with_gaps'].includes(scan.status)?scan.status:'completed_with_gaps',
      findingCount:(scan.findings||[]).length,
      startedAt:scan.startedAt||null,
      completedAt:scan.completedAt||null,
      source:'built-in'
    }
  ];

  for(const result of engineResults){
    if(!result) continue;
    const run={
      engine:result.engine||'worker',
      name:result.name||result.engine||'Worker engine',
      status:result.status||'completed',
      findingCount:(result.findings||[]).length,
      startedAt:result.startedAt||null,
      completedAt:result.completedAt||null,
      metrics:result.metrics||{},
      error:result.error||result.stderr||null,
      source:'worker'
    };
    engineRuns.push(run);

    for(const raw of result.findings||[]){
      const item=normalizeFinding(raw,result.name||result.engine);
      const prior=previous.get(item.fingerprint);
      if(prior){
        item.lifecycle='open';
        item.workflowStatus=prior.workflowStatus||'open';
        item.firstSeen=prior.firstSeen||prior._scan?.completedAt||previousScan?.completedAt||null;
      }else{
        item.lifecycle='new';
        item.firstSeen=scan.completedAt||new Date().toISOString();
      }
      item.lastSeen=scan.completedAt||new Date().toISOString();

      const existing=map.get(item.fingerprint);
      if(!existing || (severityRank[item.severity]||0)>(severityRank[existing.severity]||0)) map.set(item.fingerprint,item);
    }
  }

  const findings=[...map.values()].sort((a,b)=>(severityRank[b.severity]||0)-(severityRank[a.severity]||0));
  scan.findings=findings;
  scan.summary=summarize(findings);
  scan.score=scoreFindings(findings);
  scan.engineRuns=engineRuns;
  scan.priorities=findings.filter(item=>['Critical','High','Medium'].includes(item.severity)).slice(0,10).map(item=>({
    title:item.title,severity:item.severity,checkId:item.checkId,engine:item.engine,affected:item.affectedLocations?.length||1
  }));

  scan.engineStatus={...(scan.engineStatus||{})};
  for(const run of engineRuns.filter(item=>item.source==='worker')){
    scan.engineStatus[run.engine]={
      status:run.status,
      findings:run.findingCount,
      error:run.error||null
    };
    if(run.status==='failed' || run.status==='completed_with_gaps' || run.status==='skipped'){
      scan.coverageGaps=[...new Set([...(scan.coverageGaps||[]),run.engine])];
    }
  }
  if((scan.coverageGaps||[]).length && scan.status==='completed') scan.status='completed_with_gaps';
  if((scan.coverageGaps||[]).length) scan.scoreConfidence=scan.scoreConfidence==='low'?'low':'medium';

  scan.metrics={...(scan.metrics||{}),workerFindings:engineResults.reduce((sum,item)=>sum+(item?.findings?.length||0),0),engineRuns:engineRuns.length};
  return scan;
}

export function failedEngineRun(engine,name,error){
  return {
    engine,name,status:'failed',startedAt:new Date().toISOString(),completedAt:new Date().toISOString(),
    findings:[],metrics:{},error:String(error?.message||error).slice(0,1000)
  };
}

