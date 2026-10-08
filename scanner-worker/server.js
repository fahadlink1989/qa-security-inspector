import http from 'node:http';
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';
import { spawn } from 'node:child_process';

const PORT=Number(process.env.PORT||8080);
const SECRET=process.env.SCANNER_WORKER_SECRET||'';
const ALLOW_PRIVATE=String(process.env.ALLOW_PRIVATE_TARGETS||'false').toLowerCase()==='true';
const ZAP_API_URL=process.env.ZAP_API_URL||'';
const ZAP_API_KEY=process.env.ZAP_API_KEY||'';
const GREENBONE_ADAPTER_URL=process.env.GREENBONE_ADAPTER_URL||'';
const GREENBONE_ADAPTER_TOKEN=process.env.GREENBONE_ADAPTER_TOKEN||'';

const allowedEngines=new Set(['zap','nuclei','openvas','trivy','gitleaks']);
const allowedProfiles=new Set(['safe','deep','code','network']);

function json(res,status,body){
  const payload=JSON.stringify(body);
  res.writeHead(status,{'content-type':'application/json','content-length':Buffer.byteLength(payload),'cache-control':'no-store'});
  res.end(payload);
}
function safeEqual(a,b){
  const x=Buffer.from(String(a||'')); const y=Buffer.from(String(b||''));
  return x.length===y.length&&crypto.timingSafeEqual(x,y);
}
function verifySignature(req,raw){
  if(!SECRET) return false;
  const timestamp=req.headers['x-inspector-timestamp'];
  const signature=req.headers['x-inspector-signature'];
  if(!timestamp||!signature) return false;
  const age=Math.abs(Date.now()-Number(timestamp));
  if(!Number.isFinite(age)||age>5*60*1000) return false;
  const expected=crypto.createHmac('sha256',SECRET).update(String(timestamp)+'.'+raw).digest('hex');
  return safeEqual(expected,signature);
}
function privateV4(ip){
  const p=ip.split('.').map(Number);
  if(p.length!==4||p.some(Number.isNaN)) return true;
  return p[0]===10||p[0]===127||p[0]===0||
    (p[0]===169&&p[1]===254)||
    (p[0]===172&&p[1]>=16&&p[1]<=31)||
    (p[0]===192&&p[1]===168)||
    p[0]>=224;
}
function privateV6(ip){
  const v=ip.toLowerCase();
  return v==='::'||v==='::1'||v.startsWith('fc')||v.startsWith('fd')||
    v.startsWith('fe8')||v.startsWith('fe9')||v.startsWith('fea')||v.startsWith('feb');
}
function isPrivateAddress(ip){
  const family=net.isIP(ip);
  if(family===4) return privateV4(ip);
  if(family===6) return privateV6(ip);
  return true;
}
function isPrivateCidr(value){
  const [ip,prefixRaw]=String(value||'').split('/');
  const prefix=Number(prefixRaw);
  if(net.isIP(ip)!==4||!Number.isInteger(prefix)||prefix<16||prefix>32) return false;
  return privateV4(ip);
}
async function assertSafeTarget(engine,target){
  if(engine==='trivy'||engine==='gitleaks'){
    const u=new URL(target);
    if(u.protocol!=='https:'||!['github.com','www.github.com'].includes(u.hostname.toLowerCase())) throw new Error('Repository scans only support HTTPS GitHub URLs.');
    return;
  }
  if(engine==='openvas'&&String(target).includes('/')){
    if(!ALLOW_PRIVATE) throw new Error('Private network scanning is disabled on this worker.');
    if(!isPrivateCidr(target)) throw new Error('Internal network scans require an RFC1918 IPv4 CIDR between /16 and /32.');
    return;
  }
  const u=new URL(target);
  if(!['http:','https:'].includes(u.protocol)) throw new Error('Only HTTP(S) targets are supported.');
  if(['localhost','localhost.localdomain'].includes(u.hostname.toLowerCase())) throw new Error('Local targets are blocked.');
  const records=await dns.lookup(u.hostname,{all:true,verbatim:true});
  if(!records.length) throw new Error('Target did not resolve.');
  if(!ALLOW_PRIVATE&&records.some(r=>isPrivateAddress(r.address))) throw new Error('Private/reserved targets are blocked on this worker.');
}

function fingerprint(engine,title,location,checkId=''){
  return crypto.createHash('sha1').update([engine,checkId,title,location].join('|')).digest('hex').slice(0,24);
}
function makeFinding({engine,checkId,category='Security',severity='Informational',title,summary,impact='',evidence='',location='',remediation='',confidence='High',evidenceQuality='validated'}){
  return {
    id:crypto.randomUUID(),
    fingerprint:fingerprint(engine,title,location,checkId),
    engine,checkId,category,severity,title,summary,impact,evidence,
    location,affectedLocations:location?[location]:[],
    remediation,confidence,evidenceQuality,workflowStatus:'open'
  };
}
function mapSeverity(value){
  const v=String(value||'').toLowerCase();
  if(v.includes('critical')) return 'Critical';
  if(v.includes('high')) return 'High';
  if(v.includes('medium')||v.includes('moderate')||v.includes('warn')) return 'Medium';
  if(v.includes('low')) return 'Low';
  return 'Informational';
}
function runCommand(command,args,{cwd,timeoutMs=180000,env={}}={}){
  return new Promise((resolve,reject)=>{
    const child=spawn(command,args,{cwd,env:{...process.env,...env},stdio:['ignore','pipe','pipe']});
    let stdout='',stderr='';
    const timer=setTimeout(()=>{child.kill('SIGKILL');reject(new Error(command+' timed out'));},timeoutMs);
    child.stdout.on('data',d=>{stdout+=d.toString(); if(stdout.length>30_000_000) child.kill('SIGKILL');});
    child.stderr.on('data',d=>{stderr+=d.toString(); if(stderr.length>5_000_000) stderr=stderr.slice(-5_000_000);});
    child.on('error',error=>{clearTimeout(timer);reject(error);});
    child.on('close',code=>{clearTimeout(timer);resolve({code,stdout,stderr});});
  });
}

async function zapGet(kind,component,action,params={}){
  if(!ZAP_API_URL) throw new Error('ZAP_API_URL is not configured on this worker.');
  const u=new URL('/JSON/'+component+'/'+kind+'/'+action+'/',ZAP_API_URL);
  if(ZAP_API_KEY) u.searchParams.set('apikey',ZAP_API_KEY);
  for(const [k,v] of Object.entries(params)) if(v!==undefined&&v!==null) u.searchParams.set(k,String(v));
  const response=await fetch(u,{signal:AbortSignal.timeout(15000)});
  if(!response.ok) throw new Error('ZAP API '+response.status);
  return response.json();
}
async function waitUntil(check,{timeoutMs=110000,intervalMs=1500}={}){
  const start=Date.now();
  while(Date.now()-start<timeoutMs){
    const result=await check();
    if(result.done) return result.value;
    await new Promise(r=>setTimeout(r,intervalMs));
  }
  throw new Error('Scanner stage timed out.');
}
async function runZap(target){
  const startedAt=new Date().toISOString();
  const spider=await zapGet('action','spider','scan',{url:target,maxChildren:40,recurse:true,subtreeOnly:true});
  const scanId=spider.scan;
  await waitUntil(async()=>{
    const status=await zapGet('view','spider','status',{scanId});
    const value=Number(status.status||0);
    return {done:value>=100,value};
  });
  await waitUntil(async()=>{
    const pending=await zapGet('view','pscan','recordsToScan');
    const count=Number(pending.recordsToScan||0);
    return {done:count===0,value:count};
  },{timeoutMs:90000,intervalMs:1200});

  const alerts=await zapGet('view','core','alerts',{baseurl:target,start:0,count:500});
  const findings=(alerts.alerts||[]).map(a=>makeFinding({
    engine:'OWASP ZAP',
    checkId:'ZAP-'+String(a.pluginId||a.alertRef||'ALERT'),
    category:'Web Application',
    severity:mapSeverity(a.risk),
    title:a.alert||a.name||'ZAP passive alert',
    summary:(a.description||'Passive web application security alert.').replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim().slice(0,1200),
    impact:(a.other||'').replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim().slice(0,1000),
    evidence:['URL: '+(a.url||target),a.param?'Parameter: '+a.param:'',a.evidence?'Observed evidence: '+String(a.evidence).slice(0,500):''].filter(Boolean).join('\n'),
    location:a.url||target,
    remediation:(a.solution||'Review the alert and apply the corresponding application or configuration fix.').replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim().slice(0,1400),
    confidence:String(a.confidence||'Medium'),
    evidenceQuality:'passive-observation'
  }));
  return {engine:'zap',name:'OWASP ZAP Passive',status:'completed',startedAt,completedAt:new Date().toISOString(),findings,metrics:{alerts:findings.length,spiderId:String(scanId)}};
}

async function runNuclei(target){
  const startedAt=new Date().toISOString();
  const args=[
    '-u',target,'-jsonl','-silent',
    '-severity','info,low,medium,high,critical',
    '-tags','cve,misconfig,exposure',
    '-etags','fuzz,dos,bruteforce,intrusive,headless',
    '-rate-limit','5','-c','5','-timeout','8','-retries','1','-no-color'
  ];
  const result=await runCommand('nuclei',args,{timeoutMs:180000});
  const rows=result.stdout.split(/\r?\n/).filter(Boolean);
  const findings=[];
  for(const line of rows){
    try{
      const item=JSON.parse(line);
      const info=item.info||{};
      const location=item['matched-at']||item.host||item.url||target;
      findings.push(makeFinding({
        engine:'Nuclei',
        checkId:'NUCLEI-'+(item['template-id']||'TEMPLATE'),
        category:'Exposure / Vulnerability',
        severity:mapSeverity(info.severity),
        title:info.name||item['template-id']||'Nuclei finding',
        summary:(info.description||'Template-driven vulnerability or exposure match.').slice(0,1200),
        impact:Array.isArray(info.classification?.['cve-id'])?'CVE: '+info.classification['cve-id'].join(', '):'',
        evidence:['Template: '+(item['template-id']||''),'Matcher: '+(item['matcher-name']||''),'URL: '+location].filter(Boolean).join('\n'),
        location,
        remediation:(info.remediation||'Confirm the exposed condition and apply the vendor or configuration remediation.').slice(0,1400),
        confidence:'High',
        evidenceQuality:'template-match'
      }));
    }catch{}
  }
  return {engine:'nuclei',name:'Nuclei Safe',status:result.code===0||findings.length?'completed':'completed_with_gaps',startedAt,completedAt:new Date().toISOString(),findings,metrics:{matches:findings.length},stderr:result.code&& !findings.length?result.stderr.slice(0,1200):undefined};
}

async function runTrivy(target){
  const startedAt=new Date().toISOString();
  const result=await runCommand('trivy',['repo','--quiet','--format','json','--scanners','vuln,misconfig,secret',target],{timeoutMs:180000});
  let parsed={};
  try{parsed=JSON.parse(result.stdout||'{}');}catch{}
  const findings=[];
  for(const entry of parsed.Results||[]){
    for(const v of entry.Vulnerabilities||[]){
      const location='dependency:'+(v.PkgName||entry.Target||'package');
      findings.push(makeFinding({
        engine:'Trivy',checkId:v.VulnerabilityID||'TRIVY-VULN',category:'Code & Dependencies',severity:mapSeverity(v.Severity),
        title:(v.VulnerabilityID||'Vulnerability')+' affects '+(v.PkgName||'dependency')+' '+(v.InstalledVersion||''),
        summary:(v.Title||v.Description||'Dependency vulnerability.').slice(0,1200),
        impact:v.PrimaryURL||'',evidence:['Target: '+(entry.Target||''),'Installed: '+(v.InstalledVersion||''),'Fixed: '+(v.FixedVersion||'not listed')].join('\n'),
        location,remediation:v.FixedVersion?'Upgrade '+v.PkgName+' to '+v.FixedVersion+' or later.':'Review the upstream advisory and apply the recommended mitigation or upgrade.',
        confidence:'High',evidenceQuality:'matched-version'
      }));
    }
    for(const m of entry.Misconfigurations||[]){
      findings.push(makeFinding({
        engine:'Trivy',checkId:m.ID||m.AVDID||'TRIVY-MISCONFIG',category:'Code & IaC',severity:mapSeverity(m.Severity),
        title:m.Title||'Infrastructure misconfiguration',summary:(m.Description||m.Message||'Configuration issue.').slice(0,1200),
        evidence:['Target: '+(entry.Target||''),'Cause: '+(m.CauseMetadata?.Provider||'')].join('\n'),location:entry.Target||target,
        remediation:(m.Resolution||'Apply the recommended secure configuration and rescan.').slice(0,1400),confidence:'High',evidenceQuality:'static-analysis'
      }));
    }
    for(const s of entry.Secrets||[]){
      findings.push(makeFinding({
        engine:'Trivy',checkId:'TRIVY-SECRET-'+(s.RuleID||'SECRET'),category:'Code & Secrets',severity:mapSeverity(s.Severity||'High'),
        title:(s.Title||s.RuleID||'Secret')+' appears in source control',
        summary:'A secret pattern was detected. Inspector intentionally does not return the secret value.',
        evidence:['Target: '+(entry.Target||''),'Start line: '+(s.StartLine||'unknown')].join('\n'),location:(entry.Target||target)+':'+(s.StartLine||''),
        remediation:'Revoke or rotate the credential, remove it from source control and history where required, and move it to a managed secret store.',
        confidence:'High',evidenceQuality:'static-analysis'
      }));
    }
  }
  return {engine:'trivy',name:'Trivy Repository',status:result.code===0||findings.length?'completed':'completed_with_gaps',startedAt,completedAt:new Date().toISOString(),findings,metrics:{findings:findings.length},stderr:result.code&& !findings.length?result.stderr.slice(0,1200):undefined};
}

async function runGitleaks(target){
  const startedAt=new Date().toISOString();
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'inspector-gitleaks-'));
  const repoDir=path.join(dir,'repo');
  try{
    const clone=await runCommand('git',['clone','--depth','1',target,repoDir],{timeoutMs:60000});
    if(clone.code!==0) throw new Error('Repository clone failed: '+clone.stderr.slice(0,500));
    const report=path.join(dir,'gitleaks.json');
    const result=await runCommand('gitleaks',['git',repoDir,'--no-banner','--redact','--report-format','json','--report-path',report],{timeoutMs:120000});
    let rows=[];
    try{rows=JSON.parse(await fs.readFile(report,'utf8'));}catch{}
    const findings=rows.map(item=>makeFinding({
      engine:'Gitleaks',checkId:'GITLEAKS-'+(item.RuleID||'SECRET'),category:'Code & Secrets',severity:'High',
      title:(item.Description||item.RuleID||'Secret')+' detected in repository',
      summary:'A high-confidence secret pattern was detected. Secret values are redacted and are not returned to Inspector.',
      evidence:['File: '+(item.File||''),'Line: '+(item.StartLine||''),'Commit: '+String(item.Commit||'').slice(0,12)].join('\n'),
      location:(item.File||target)+':'+(item.StartLine||''),remediation:'Revoke or rotate the credential, remove it from repository history if needed, and store it in a managed secret store.',
      confidence:'High',evidenceQuality:'static-analysis'
    }));
    return {engine:'gitleaks',name:'Gitleaks',status:result.code===0||result.code===1?'completed':'completed_with_gaps',startedAt,completedAt:new Date().toISOString(),findings,metrics:{secrets:findings.length}};
  }finally{await fs.rm(dir,{recursive:true,force:true}).catch(()=>{});}
}

async function runOpenvas(target,metadata={}){
  if(!GREENBONE_ADAPTER_URL) throw new Error('GREENBONE_ADAPTER_URL is not configured on this worker.');
  const startedAt=new Date().toISOString();
  const response=await fetch(new URL('/v1/scan',GREENBONE_ADAPTER_URL),{
    method:'POST',
    headers:{'content-type':'application/json',...(GREENBONE_ADAPTER_TOKEN?{'authorization':'Bearer '+GREENBONE_ADAPTER_TOKEN}:{})},
    body:JSON.stringify({target,metadata}),
    signal:AbortSignal.timeout(280000)
  });
  const body=await response.json().catch(()=>({}));
  if(!response.ok) throw new Error(body.error||('Greenbone adapter returned '+response.status));
  const findings=(body.findings||[]).map(item=>makeFinding({
    engine:'Greenbone / OpenVAS',
    checkId:item.checkId||item.oid||'OPENVAS',
    category:'Network Vulnerability',
    severity:mapSeverity(item.severity||item.cvssSeverity),
    title:item.title||item.name||'OpenVAS finding',
    summary:String(item.summary||item.description||'Network vulnerability finding.').slice(0,1200),
    impact:String(item.impact||'').slice(0,1000),
    evidence:String(item.evidence||item.host||target).slice(0,1600),
    location:item.location||item.host||target,
    remediation:String(item.remediation||item.solution||'Apply the vendor patch or hardening guidance and rescan.').slice(0,1400),
    confidence:item.confidence||'High',evidenceQuality:'scanner-validation'
  }));
  return {engine:'openvas',name:'Greenbone / OpenVAS',status:body.status||'completed',startedAt,completedAt:new Date().toISOString(),findings,metrics:{findings:findings.length,...(body.metrics||{})}};
}

async function execute(body){
  const {engine,target,profile='safe',jobId,metadata={}}=body||{};
  if(!allowedEngines.has(engine)) throw new Error('Unsupported scanner engine.');
  if(!allowedProfiles.has(profile)) throw new Error('Unsupported scanner profile.');
  if(!target) throw new Error('Target is required.');
  await assertSafeTarget(engine,target);
  if(engine==='zap') return runZap(target);
  if(engine==='nuclei') return runNuclei(target);
  if(engine==='trivy') return runTrivy(target);
  if(engine==='gitleaks') return runGitleaks(target);
  if(engine==='openvas') return runOpenvas(target,metadata);
  throw new Error('Unsupported engine.');
}

const server=http.createServer(async(req,res)=>{
  if(req.method==='GET'&&req.url==='/health'){
    return json(res,200,{
      ok:true,
      service:'inspector-scanner-worker',
      engines:{
        zap:Boolean(ZAP_API_URL),
        nuclei:true,
        trivy:true,
        gitleaks:true,
        openvas:Boolean(GREENBONE_ADAPTER_URL)
      },
      allowPrivateTargets:ALLOW_PRIVATE
    });
  }
  if(req.method!=='POST'||req.url!=='/v1/scan') return json(res,404,{error:'Not found'});
  let raw='';
  req.on('data',chunk=>{raw+=chunk.toString(); if(raw.length>2_000_000) req.destroy();});
  req.on('end',async()=>{
    if(!verifySignature(req,raw)) return json(res,401,{error:'Invalid worker signature.'});
    try{
      const body=JSON.parse(raw||'{}');
      const result=await execute(body);
      return json(res,200,{jobId:body.jobId||null,...result});
    }catch(error){
      return json(res,400,{error:error?.message||'Scanner worker failed.'});
    }
  });
});

server.listen(PORT,'0.0.0.0',()=>console.log('Inspector scanner worker listening on '+PORT));
