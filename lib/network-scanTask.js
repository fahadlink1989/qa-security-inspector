import { workspaceContext } from './backend/context';
import crypto from 'node:crypto';
import { mutateState, readState } from './store';
import { runWorkerEngine, scannerWorkerHealth } from './workerClient';
import { scoreFindings } from './scanner';
import { generateIntelligence } from './intelligence';
const rank={Critical:5,High:4,Medium:3,Low:2,Informational:1};
function summarize(findings){
  const out={critical:0,high:0,medium:0,low:0,informational:0};
  for(const item of findings||[]){const key=String(item.severity||'Informational').toLowerCase();if(key in out)out[key]+=1;}
  return out;
}
function lifecycle(findings,previous){
  const prior=new Map((previous?.findings||[]).map(item=>[item.fingerprint,item]));
  return findings.map(item=>{
    const old=prior.get(item.fingerprint);
    return {...item,lifecycle:old?'open':'new',workflowStatus:old?.workflowStatus||item.workflowStatus||'open',
      firstSeen:old?.firstSeen||previous?.completedAt||new Date().toISOString(),lastSeen:new Date().toISOString()};
  });
}


export async function runNetworkTask(body,progress){
    const worker=await scannerWorkerHealth();
    if(!worker.connected) throw new Error('Internal scanner worker is not reachable. Connect an authorized internal worker before starting a network scan.');
    const state=await readState();
    const project=state.projects.find(item=>item.id===body.projectId);
    if(!project) throw new Error('Project not found.');
    const target=(project.networks||[]).find(item=>item.id===body.networkTargetId);
    if(!target) throw new Error('Network target not found.');

      const previous=(project.networkScans||[]).filter(item=>item.networkTargetId===target.id)
        .sort((a,b)=>String(b.completedAt||'').localeCompare(String(a.completedAt||'')))[0]||null;
      const startedAt=new Date().toISOString();
      const engines=[{engine:'naabu',name:'Naabu Port Discovery'},{engine:'openvas',name:'Greenbone / OpenVAS'}];
      await progress(12,'Starting authorized network checks');
      const results=await Promise.all(engines.map(async(item,index)=>{
        await progress(18+index*20,'Running '+item.name);
        try{
          return await runWorkerEngine({engine:item.engine,target:target.cidr,profile:'network',metadata:{projectId:project.id,networkTargetId:target.id,label:target.label}});
        }catch(error){
          return {engine:item.engine,name:item.name,status:'failed',findings:[],metrics:{},error:String(error?.message||error).slice(0,1000)};
        }
      }));
      const map=new Map();
      for(const result of results)for(const finding of result.findings||[]){
        const key=finding.fingerprint||crypto.createHash('sha1').update([finding.engine,finding.checkId,finding.title,finding.location].join('|')).digest('hex').slice(0,20);
        if(!map.has(key)||(rank[finding.severity]||0)>(rank[map.get(key)?.severity]||0))map.set(key,{...finding,fingerprint:key});
      }
      const findings=lifecycle([...map.values()].sort((a,b)=>(rank[b.severity]||0)-(rank[a.severity]||0)),previous);
      const scan={
        id:crypto.randomUUID(),type:'network',scanType:'Internal Network Scan',projectId:project.id,networkTargetId:target.id,
        target:target.cidr,label:target.label,startedAt,completedAt:new Date().toISOString(),
        status:results.some(item=>item.status!=='completed')?'completed_with_gaps':'completed',
        score:scoreFindings(findings),scoreConfidence:results.some(item=>item.status!=='completed')?'medium':'high',
        summary:summarize(findings),findings,
        engineRuns:results.map(item=>({engine:item.engine,name:item.name||item.engine,status:item.status,findings:item.findings?.length||0,
          findingCount:item.findings?.length||0,metrics:item.metrics||{},error:item.error||null,startedAt:item.startedAt||startedAt,completedAt:item.completedAt||new Date().toISOString()})),
        metrics:{openPorts:results.find(item=>item.engine==='naabu')?.metrics?.openPorts||0,networkFindings:findings.length},
        coverageGaps:results.filter(item=>item.status!=='completed').map(item=>item.engine)
      };
      scan.executiveSummary='Internal network scan of '+target.cidr+' found '+scan.metrics.openPorts+' reachable top-100 TCP ports and '+findings.filter(item=>['Critical','High','Medium'].includes(item.severity)).length+' material findings.';
      await progress(76,'Generating evidence-based remediation');
      try{
        const intelligence=await generateIntelligence(scan);
        scan.remediationPlan=intelligence;
        scan.intelligence={mode:intelligence?.mode||'rules',provider:intelligence?.provider||null,model:intelligence?.model||null,
          generatedAt:intelligence?.generatedAt||new Date().toISOString(),aiError:intelligence?.aiError||null};
        if(intelligence?.executiveSummary)scan.executiveSummary=intelligence.executiveSummary;
      }catch(error){scan.intelligence={mode:'rules',aiError:String(error?.message||error).slice(0,300)};}
      await progress(92,'Saving network scan results');
      scan.id=workspaceContext().jobId||scan.id;
  await mutateState(next=>{
        const current=next.projects.find(item=>item.id===project.id);
        if(!current)throw new Error('Project not found.');
        current.networkScans=[scan,...(current.networkScans||[]).filter(item=>item.id!==scan.id)].slice(0,20);
        return next;
      });
      return scan;
    
}
