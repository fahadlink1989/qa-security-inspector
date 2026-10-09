import { workspaceContext } from './backend/context';
import { carryRiskLifecycle } from './riskModel.mjs';
import { mutateState, readState } from './store';
import { scanGitHubRepository } from './codeSecurity';
import { generateCodeIntelligence } from './intelligence';
import { runWorkerEngine, scannerWorkerHealth } from './workerClient';

export async function runCodeTask(body,progress){
    const repository = new URL(body.repositoryUrl);
    if (repository.protocol !== 'https:' || !['github.com','www.github.com'].includes(repository.hostname.toLowerCase())) {
      throw new Error('Only HTTPS GitHub repository URLs are supported.');
    }
    const state = await readState();
    const project = state.projects.find((item) => item.id === body.projectId);
    if (!project) throw new Error('Project not found.');

      await progress(10,'Preparing repository scan');
      const codeScan = await scanGitHubRepository({repositoryUrl:repository.href,token:body.token||''});
      codeScan.projectId = project.id;
      codeScan.scanType = 'Code & Dependencies';
      codeScan.engineRuns = [{
        engine:'inspector-code',name:'Inspector Code Security',status:'completed',
        findingCount:(codeScan.findings || []).length,source:'built-in'
      }];

      const worker=await scannerWorkerHealth();
      const engineItems=[{engine:'trivy',name:'Trivy Repository'},{engine:'gitleaks',name:'Gitleaks'}];
      if(worker.connected&&!codeScan.private){
        await progress(42,'Running Trivy and Gitleaks');
        const results=await Promise.all(engineItems.map(async(item)=>{
          try{
            return await runWorkerEngine({engine:item.engine,target:repository.href,profile:'code',metadata:{projectId:project.id}});
          }catch(error){
            return {engine:item.engine,name:item.name,status:'failed',findings:[],error:String(error?.message||error).slice(0,800)};
          }
        }));
        const map=new Map((codeScan.findings||[]).map(item=>[item.fingerprint||item.id,item]));
        for(const result of results){
          codeScan.engineRuns.push({
            engine:result.engine,name:result.name||result.engine,status:result.status||'completed',
            findingCount:(result.findings||[]).length,source:'worker',error:result.error||null,metrics:result.metrics||{}
          });
          for(const finding of result.findings||[]){
            const key=finding.fingerprint||finding.id;
            if(key&&!map.has(key)) map.set(key,{...finding,workflowStatus:finding.workflowStatus||'open'});
          }
        }
        codeScan.findings=[...map.values()];
        codeScan.stats={...(codeScan.stats||{}),findings:codeScan.findings.length,workerFindings:results.reduce((sum,item)=>sum+(item.findings?.length||0),0)};
        codeScan.coverageGaps=results.filter(item=>['failed','completed_with_gaps','skipped'].includes(item.status)).map(item=>item.engine);
      }else{
        codeScan.engineRuns.push(...engineItems.map(item=>({
          engine:item.engine,name:item.name,status:'skipped',findingCount:0,source:'worker',
          error:worker.connected?'Private repositories are scanned by Inspector only.':worker.health?.error||'Scanner worker is not connected; external repository engines were skipped.'
        })));
        codeScan.coverageGaps=engineItems.map(item=>item.engine);
      }
      codeScan.workerConfigured=worker.connected;
      codeScan.status=codeScan.coverageGaps.length?'completed_with_gaps':'completed';

      await progress(80,'Preparing remediation guidance');
      codeScan.remediationPlan=await generateCodeIntelligence(codeScan);
      await progress(92,'Saving code scan results');
      codeScan.id=workspaceContext().jobId||codeScan.id;
  await mutateState((next)=>{
        const target=next.projects.find((item)=>item.id===project.id);
        if(!target) throw new Error('Project not found.');
        const previous=(target.codeScans||[]).find(item=>JSON.stringify(item.repository)===JSON.stringify(codeScan.repository));
        carryRiskLifecycle(codeScan,previous);
        target.codeScans=[codeScan,...(target.codeScans||[]).filter(item=>item.id!==codeScan.id)].slice(0,10);
        return next;
      });
      return codeScan;
    
}
