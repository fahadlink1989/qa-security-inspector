const GATEWAY_URL='https://ai-gateway.vercel.sh/v1/chat/completions';
const MODEL='openai/gpt-5.6-sol';

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

export async function generateIntelligence(scan) {
  const fallback=buildFallbackRemediationPlan(scan);
  const token=process.env.AI_GATEWAY_API_KEY||process.env.VERCEL_OIDC_TOKEN;
  if(!token) return fallback;

  const schema={
    type:'object',
    additionalProperties:false,
    properties:{
      executiveSummary:{type:'string'},
      actions:{
        type:'array',
        maxItems:10,
        items:{
          type:'object',
          additionalProperties:false,
          properties:{
            id:{type:'string'},
            priority:{type:'string',enum:['P0','P1','P2','P3']},
            title:{type:'string'},
            owner:{type:'string'},
            effort:{type:'string'},
            why:{type:'string'},
            steps:{type:'array',items:{type:'string'},minItems:1,maxItems:7},
            verification:{type:'array',items:{type:'string'},minItems:1,maxItems:5},
            relatedFindings:{type:'array',items:{type:'string'},maxItems:10},
            relatedCves:{type:'array',items:{type:'string'},maxItems:10}
          },
          required:['id','priority','title','owner','effort','why','steps','verification','relatedFindings','relatedCves']
        }
      },
      findingGuidance:{
        type:'array',
        maxItems:24,
        items:{
          type:'object',
          additionalProperties:false,
          properties:{
            fingerprint:{type:'string'},
            fixSummary:{type:'string'},
            owner:{type:'string'},
            effort:{type:'string'},
            steps:{type:'array',items:{type:'string'},minItems:1,maxItems:6},
            verification:{type:'array',items:{type:'string'},minItems:1,maxItems:5}
          },
          required:['fingerprint','fixSummary','owner','effort','steps','verification']
        }
      }
    },
    required:['executiveSummary','actions','findingGuidance']
  };

  const response=await fetch(GATEWAY_URL,{
    method:'POST',
    headers:{
      authorization:'Bearer '+token,
      'content-type':'application/json'
    },
    body:JSON.stringify({
      model:MODEL,
      temperature:0.1,
      max_tokens:3000,
      messages:[
        {
          role:'system',
          content:[
            'You are the remediation copilot for an authorized web security and QA platform.',
            'Use ONLY the supplied evidence. Never invent a vulnerability, CVE, affected version, exploitability claim, endpoint, or remediation fact.',
            'CVE actions must be grounded in the supplied NVD records. If version applicability needs operator confirmation, say so.',
            'Prioritize validated evidence over observed/heuristic evidence.',
            'Do not tell the user to exploit, weaponize, brute force or bypass controls.',
            'Recommend defensive configuration, patching, code fixes, testing, ownership and verification.',
            'Be concrete enough that an engineering team can act: what to change, where, who should own it, and how to verify it.',
            'Treat analytics/telemetry failures as non-actionable unless the supplied findings explicitly classify them as product failures.'
          ].join(' ')
        },
        {
          role:'user',
          content:JSON.stringify(compactScan(scan))
        }
      ],
      response_format:{
        type:'json_schema',
        json_schema:{
          name:'inspector_remediation_plan',
          strict:true,
          schema
        }
      }
    }),
    signal:AbortSignal.timeout(35000)
  });

  if(!response.ok) return {
    ...fallback,
    aiError:'AI Gateway returned '+response.status
  };

  const data=await response.json();
  const parsed=parseJsonContent(data?.choices?.[0]?.message?.content);
  if(!parsed) return {...fallback,aiError:'AI response could not be parsed'};

  const supplied=new Set((scan.findings||[]).map((item)=>item.fingerprint));
  const cveIds=new Set((scan.evidence?.deep?.cves?.vulnerabilities||[]).map((item)=>item.id));

  const actions=(parsed.actions||[]).map((action)=>({
    ...action,
    relatedFindings:(action.relatedFindings||[]).filter((id)=>supplied.has(id)),
    relatedCves:(action.relatedCves||[]).filter((id)=>cveIds.has(id))
  }));

  const guidanceEntries=(parsed.findingGuidance||[])
    .filter((item)=>supplied.has(item.fingerprint))
    .map((item)=>[item.fingerprint,{
      fixSummary:item.fixSummary,
      owner:item.owner,
      effort:item.effort,
      steps:item.steps,
      verification:item.verification
    }]);

  return {
    mode:'ai',
    model:MODEL,
    generatedAt:new Date().toISOString(),
    executiveSummary:parsed.executiveSummary,
    actions,
    findingGuidance:Object.fromEntries(guidanceEntries)
  };
}
