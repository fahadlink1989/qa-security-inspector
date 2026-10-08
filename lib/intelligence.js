import { generateText } from 'ai';
import { createOpenAI } from '@ai-sdk/openai';

const GATEWAY_MODEL='openai/gpt-5.6-sol';
const OPENAI_MODEL='gpt-5.6-sol';
const rank={Critical:5,High:4,Medium:3,Low:2,Informational:1};

function compactFinding(finding) {
  return {
    fingerprint:finding.fingerprint,
    checkId:finding.checkId,
    category:finding.category,
    severity:finding.severity,
    title:finding.title,
    summary:finding.summary,
    impact:finding.impact,
    evidence:String(finding.evidence||'').slice(0,2200),
    remediation:finding.remediation,
    affectedLocations:(finding.affectedLocations||[]).slice(0,8),
    confidence:finding.confidence,
    evidenceQuality:finding.evidenceQuality,
    engine:finding.engine
  };
}

function compactScan(scan) {
  const top=[...(scan.findings||[])]
    .sort((a,b)=>(rank[b.severity]||0)-(rank[a.severity]||0))
    .slice(0,24)
    .map(compactFinding);

  const cves=(scan.evidence?.deep?.cves?.vulnerabilities||[]).slice(0,20).map((item)=>({
    id:item.id,
    technology:item.technology,
    version:item.version,
    cvss:item.cvss,
    description:item.description,
    cwes:item.cwes,
    references:(item.references||[]).slice(0,4)
  }));

  return {
    mode:scan.mode||'standard',
    score:scan.score,
    scoreConfidence:scan.scoreConfidence,
    summary:scan.summary,
    coverageGaps:scan.coverageGaps||[],
    metrics:scan.metrics,
    deepCoverage:scan.deepCoverage||null,
    technologies:scan.evidence?.inventory?.technologies||[],
    topFindings:top,
    cves
  };
}

function defaultOwner(finding) {
  if(finding.category==='Accessibility'||finding.category==='Quality'||finding.category==='Performance') return 'Frontend / Web Engineering';
  if(finding.category==='Vulnerability') return 'Security + Platform Engineering';
  if(finding.engine==='tls'||finding.engine==='dns'||finding.engine==='deep-headers') return 'Platform / DevOps';
  return 'Security / Web Engineering';
}

function defaultEffort(finding) {
  if(finding.severity==='Critical'||finding.severity==='High') return '1–3 days';
  if(finding.severity==='Medium') return '1 sprint';
  return 'Backlog / maintenance';
}

export function buildFallbackRemediationPlan(scan) {
  const top=[...(scan.findings||[])]
    .filter((item)=>['Critical','High','Medium'].includes(item.severity))
    .sort((a,b)=>(rank[b.severity]||0)-(rank[a.severity]||0))
    .slice(0,10);

  const actions=top.map((finding,index)=>({
    id:'action-'+String(index+1),
    priority:index<3?'P1':'P2',
    title:'Fix: '+finding.title,
    owner:defaultOwner(finding),
    effort:defaultEffort(finding),
    why:finding.impact||finding.summary,
    steps:[
      finding.remediation,
      'Apply the change first in a staging or controlled environment.',
      'Review all affected locations listed by Inspector so the fix is consistent.'
    ],
    verification:[
      'Rerun the individual finding retest.',
      'Run a Standard Scan after deployment.',
      scan.mode==='deep'?'Run Deep Scan again to confirm no equivalent issue remains on discovered hosts.':'Confirm the finding no longer appears.'
    ],
    relatedFindings:[finding.fingerprint],
    relatedCves:finding.category==='Vulnerability'?[finding.checkId]:[]
  }));

  return {
    mode:'rules',
    model:null,
    generatedAt:new Date().toISOString(),
    executiveSummary:`Focus first on ${scan.summary?.critical||0} Critical, ${scan.summary?.high||0} High and ${scan.summary?.medium||0} Medium findings. Fix validated high-impact issues before configuration hygiene. Retest every change against the affected locations.`,
    actions,
    findingGuidance:Object.fromEntries(top.map((finding)=>[
      finding.fingerprint,
      {
        fixSummary:finding.remediation,
        owner:defaultOwner(finding),
        effort:defaultEffort(finding),
        steps:[finding.remediation,'Deploy safely to the affected locations.'],
        verification:['Retest this finding in Inspector.']
      }
    ]))
  };
}

function parseJsonContent(content) {
  if(!content) return null;
  try{return JSON.parse(content);}catch{}
  const match=String(content).match(/\{[\s\S]*\}/);
  if(!match) return null;
  try{return JSON.parse(match[0]);}catch{return null;}
}

function validatePlan(parsed,scan) {
  const supplied=new Set((scan.findings||[]).map((item)=>item.fingerprint));
  const cveIds=new Set((scan.evidence?.deep?.cves?.vulnerabilities||[]).map((item)=>item.id));

  const actions=(parsed?.actions||[]).slice(0,10).map((action,index)=>({
    id:String(action.id||('action-'+String(index+1))),
    priority:['P0','P1','P2','P3'].includes(action.priority)?action.priority:'P2',
    title:String(action.title||'Remediation action').slice(0,180),
    owner:String(action.owner||'Engineering').slice(0,120),
    effort:String(action.effort||'Triage required').slice(0,80),
    why:String(action.why||'').slice(0,1200),
    steps:(Array.isArray(action.steps)?action.steps:[]).slice(0,7).map((item)=>String(item).slice(0,1000)),
    verification:(Array.isArray(action.verification)?action.verification:[]).slice(0,5).map((item)=>String(item).slice(0,800)),
    relatedFindings:(Array.isArray(action.relatedFindings)?action.relatedFindings:[]).filter((id)=>supplied.has(id)).slice(0,10),
    relatedCves:(Array.isArray(action.relatedCves)?action.relatedCves:[]).filter((id)=>cveIds.has(id)).slice(0,10)
  }));

  const guidanceEntries=(Array.isArray(parsed?.findingGuidance)?parsed.findingGuidance:[])
    .filter((item)=>supplied.has(item.fingerprint))
    .map((item)=>[item.fingerprint,{
      fixSummary:String(item.fixSummary||'').slice(0,1600),
      owner:String(item.owner||'Engineering').slice(0,120),
      effort:String(item.effort||'Triage required').slice(0,80),
      steps:(Array.isArray(item.steps)?item.steps:[]).slice(0,6).map((step)=>String(step).slice(0,900)),
      verification:(Array.isArray(item.verification)?item.verification:[]).slice(0,5).map((step)=>String(step).slice(0,800))
    }]);

  return {
    executiveSummary:String(parsed?.executiveSummary||'').slice(0,2400),
    actions,
    findingGuidance:Object.fromEntries(guidanceEntries)
  };
}


async function directOpenAI(system,prompt) {
  const apiKey=process.env.OPENAI_API_KEY;
  if(!apiKey) return null;

  const response=await fetch('https://api.openai.com/v1/responses',{
    method:'POST',
    headers:{
      authorization:'Bearer '+apiKey,
      'content-type':'application/json'
    },
    body:JSON.stringify({
      model:OPENAI_MODEL,
      instructions:system,
      input:prompt,
      max_output_tokens:3000
    }),
    signal:AbortSignal.timeout(35000)
  });

  if(!response.ok){
    const detail=await response.text().catch(()=>'');
    throw new Error('OpenAI Responses API returned '+response.status+(detail?' — '+detail.slice(0,220):''));
  }

  const data=await response.json();
  let text=typeof data.output_text==='string'?data.output_text:'';
  if(!text){
    for(const item of data.output||[]){
      for(const part of item.content||[]){
        if(part.type==='output_text'&&part.text){
          text=part.text;
          break;
        }
      }
      if(text) break;
    }
  }
  if(!text) throw new Error('OpenAI Responses API returned no output text.');
  return text;
}

export async function generateIntelligence(scan) {
  const fallback=buildFallbackRemediationPlan(scan);

  const system=[
    'You are the remediation copilot for an authorized web security and QA platform.',
    'Use ONLY the supplied evidence. Never invent a vulnerability, CVE, affected version, exploitability claim, endpoint, or remediation fact.',
    'CVE actions must be grounded in the supplied NVD records. If version applicability needs operator confirmation, say so.',
    'Prioritize validated evidence over observed or heuristic evidence.',
    'Do not tell the user to exploit, weaponize, brute force or bypass controls.',
    'Recommend defensive configuration, patching, code fixes, testing, ownership and verification.',
    'Be concrete enough that an engineering team can act: what to change, where, who should own it, and how to verify it.',
    'Treat analytics and telemetry failures as non-actionable unless the supplied findings explicitly classify them as product failures.',
    'Return JSON only with this shape: {"executiveSummary":"...","actions":[{"id":"...","priority":"P0|P1|P2|P3","title":"...","owner":"...","effort":"...","why":"...","steps":["..."],"verification":["..."],"relatedFindings":["fingerprint"],"relatedCves":["CVE-id"]}],"findingGuidance":[{"fingerprint":"...","fixSummary":"...","owner":"...","effort":"...","steps":["..."],"verification":["..."]}]}.'
  ].join(' ');

  const prompt=JSON.stringify(compactScan(scan));
  let directError=null;

  if(process.env.OPENAI_API_KEY){
    try{
      const text=await directOpenAI(system,prompt);
      const parsed=parseJsonContent(text);
      if(!parsed) throw new Error('OpenAI response could not be parsed');
      const validated=validatePlan(parsed,scan);
      return {
        mode:'ai',
        provider:'openai-direct',
        model:OPENAI_MODEL,
        generatedAt:new Date().toISOString(),
        executiveSummary:validated.executiveSummary||fallback.executiveSummary,
        actions:validated.actions.length?validated.actions:fallback.actions,
        findingGuidance:Object.keys(validated.findingGuidance).length?validated.findingGuidance:fallback.findingGuidance
      };
    }catch(error){
      directError=String(error?.message||error).slice(0,500);
    }
  }

  try {
    const result=await generateText({
      model:GATEWAY_MODEL,
      system,
      prompt,
      temperature:0.1,
      abortSignal:AbortSignal.timeout(35000)
    });

    const parsed=parseJsonContent(result.text);
    if(!parsed) throw new Error('AI Gateway OpenAI response could not be parsed');

    const validated=validatePlan(parsed,scan);
    return {
      mode:'ai',
      provider:'vercel-ai-gateway',
      model:GATEWAY_MODEL,
      generatedAt:new Date().toISOString(),
      executiveSummary:validated.executiveSummary||fallback.executiveSummary,
      actions:validated.actions.length?validated.actions:fallback.actions,
      findingGuidance:Object.keys(validated.findingGuidance).length?validated.findingGuidance:fallback.findingGuidance
    };
  } catch (error) {
    const gatewayError=String(error?.message||error).slice(0,500);
    return {
      ...fallback,
      aiError:[directError&&('Direct OpenAI: '+directError),'AI Gateway: '+gatewayError].filter(Boolean).join(' | ')
    };
  }
}
