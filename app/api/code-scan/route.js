import { mutateState, readState } from '../../../lib/store';
import { scanGitHubRepository } from '../../../lib/codeSecurity';
import { generateCodeIntelligence } from '../../../lib/intelligence';
import { scoreFindings } from '../../../lib/scanner';
import { runWorkerEngine, scannerWorkerStatus } from '../../../lib/workerClient';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 300;

export async function POST(request) {
  try {
    const body = await request.json();

    if (!body.projectId) throw new Error('Project is required.');
    if (body.authorized !== true) throw new Error('Authorization confirmation is required.');
    if (!body.repositoryUrl) throw new Error('GitHub repository URL is required.');

    const state = await readState();
    const project = state.projects.find((item) => item.id === body.projectId);
    if (!project) throw new Error('Project not found.');

    const startedAt=new Date().toISOString();
    const codeScan = await scanGitHubRepository({
      repositoryUrl: body.repositoryUrl,
      token: body.token || ''
    });

    codeScan.projectId = body.projectId;
    codeScan.engineRuns = [{
      engine:'inspector-code',
      name:'Inspector Code Security',
      status:'completed',
      findingCount:(codeScan.findings || []).length,
      source:'built-in'
    }];

    const worker=scannerWorkerStatus();
    if(worker.configured && !codeScan.private){
      const engines=[
        {engine:'trivy',name:'Trivy Repository'},
        {engine:'gitleaks',name:'Gitleaks'}
      ];
      const results=await Promise.all(engines.map(async(item)=>{
        try{
          return await runWorkerEngine({
            engine:item.engine,
            target:body.repositoryUrl,
            profile:'code',
            metadata:{projectId:body.projectId}
          });
        }catch(error){
          return {engine:item.engine,name:item.name,status:'failed',findings:[],error:String(error?.message||error).slice(0,800)};
        }
      }));

      const map=new Map((codeScan.findings||[]).map(item=>[item.fingerprint||item.id,item]));
      for(const result of results){
        codeScan.engineRuns.push({
          engine:result.engine,
          name:result.name||result.engine,
          status:result.status||'completed',
          findingCount:(result.findings||[]).length,
          source:'worker',
          error:result.error||null,
          metrics:result.metrics||{}
        });
        for(const finding of result.findings||[]){
          const key=finding.fingerprint||finding.id;
          if(!map.has(key)) map.set(key,{...finding,workflowStatus:finding.workflowStatus||'open'});
        }
      }
      codeScan.findings=[...map.values()];
      codeScan.stats={...(codeScan.stats||{}),findings:codeScan.findings.length,workerFindings:results.reduce((sum,item)=>sum+(item.findings?.length||0),0)};
    }

    const previous=(project.codeScans||[]).find(s=>s.repository?.url===codeScan.repository?.url);
    const prior=new Map((previous?.findings||[]).map(f=>[f.fingerprint,f]));
    for(const f of codeScan.findings||[]){const old=prior.get(f.fingerprint);f.workflowStatus=old?.workflowStatus||'open';f.owner=old?.owner||'';f.actionHistory=old?.actionHistory||[];f.firstSeen=old?.firstSeen||previous?.scannedAt||codeScan.scannedAt;f.lastSeen=codeScan.scannedAt;}
    codeScan.startedAt=startedAt;codeScan.completedAt=new Date().toISOString();
    codeScan.status=codeScan.engineRuns.some(r=>r.status!=='completed')?'completed_with_gaps':'completed';
    codeScan.summary={critical:0,high:0,medium:0,low:0,informational:0};
    for(const f of codeScan.findings||[]){const k=String(f.severity).toLowerCase();if(k in codeScan.summary)codeScan.summary[k]++;}
    codeScan.score=scoreFindings(codeScan.findings||[]);
    codeScan.workerConfigured=worker.configured;
    codeScan.remediationPlan = await generateCodeIntelligence(codeScan);

    await mutateState((next) => {
      const target = next.projects.find((item) => item.id === body.projectId);
      if (!target) throw new Error('Project not found.');
      target.codeScans = [codeScan, ...(target.codeScans || [])].slice(0, 10);
      return next;
    });

    return Response.json(codeScan, {
      headers: { 'cache-control': 'no-store' }
    });
  } catch (error) {
    return Response.json(
      { error: error?.message || 'Code Security scan failed.' },
      { status: 400 }
    );
  }
}
