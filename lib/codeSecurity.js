import crypto from 'node:crypto';

const MAX_FILES=90;
const MAX_BYTES=3_000_000;

function repoParts(url){
  const parsed=new URL(String(url||'').trim());
  if(parsed.hostname!=='github.com'&&parsed.hostname!=='www.github.com') throw new Error('Code Security currently supports GitHub repository URLs.');
  const parts=parsed.pathname.replace(/^\/+|\/+$/g,'').replace(/\.git$/,'').split('/');
  if(parts.length<2) throw new Error('Enter a GitHub repository URL such as https://github.com/org/repo.');
  return {owner:parts[0],repo:parts[1],url:'https://github.com/'+parts[0]+'/'+parts[1]};
}

async function gh(path,token){
  const response=await fetch('https://api.github.com'+path,{
    headers:{
      accept:'application/vnd.github+json',
      'user-agent':'InspectorCodeSecurity/1.0',
      ...(token?{authorization:'Bearer '+token}:{})
    },
    signal:AbortSignal.timeout(10000)
  });
  if(!response.ok){
    if(response.status===404) throw new Error('Repository not found or token does not have access.');
    if(response.status===401||response.status===403) throw new Error('GitHub denied repository access. Check token permissions or API rate limits.');
    throw new Error('GitHub API returned '+response.status+'.');
  }
  return response.json();
}

function lineNumber(text,index){
  return text.slice(0,index).split('\n').length;
}

const secretPatterns=[
  {id:'CODE-SECRET-GITHUB',name:'GitHub token',re:/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b/g,severity:'High'},
  {id:'CODE-SECRET-GITHUB-PAT',name:'GitHub fine-grained token',re:/\bgithub_pat_[A-Za-z0-9_]{30,}\b/g,severity:'High'},
  {id:'CODE-SECRET-AWS',name:'AWS access key ID',re:/\bAKIA[0-9A-Z]{16}\b/g,severity:'Medium'},
  {id:'CODE-SECRET-STRIPE',name:'Stripe live secret key',re:/\bsk_live_[A-Za-z0-9]{20,}\b/g,severity:'High'},
  {id:'CODE-SECRET-SLACK',name:'Slack token',re:/\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g,severity:'High'},
  {id:'CODE-SECRET-PRIVATE-KEY',name:'Private key material',re:/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,severity:'Critical'},
  {id:'CODE-SECRET-OPENAI',name:'OpenAI-style API key',re:/\bsk-[A-Za-z0-9_-]{28,}\b/g,severity:'High'},
  {id:'CODE-SECRET-CONNECTION',name:'Credential-bearing database URL',re:/\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s:@/]+:[^\s@/]+@[^\s"'<>]+/gi,severity:'High'}
];

const sinkPatterns=[
  {id:'CODE-SINK-EVAL',title:'Dynamic code execution sink requires review',re:/\beval\s*\(/g,language:/\.(?:js|jsx|ts|tsx)$/i,remediation:'Avoid eval for untrusted or externally influenced input. Prefer explicit parsing or a constrained interpreter.'},
  {id:'CODE-SINK-CHILD-PROCESS',title:'Shell command execution sink requires review',re:/\b(?:exec|execSync)\s*\(/g,language:/\.(?:js|ts|mjs|cjs)$/i,remediation:'Avoid building shell commands from user-controlled strings. Prefer argument arrays and strict allowlists.'},
  {id:'CODE-SINK-PY-SHELL',title:'Python subprocess shell execution requires review',re:/subprocess\.(?:run|Popen|call)\([^\n]{0,300}shell\s*=\s*True/g,language:/\.py$/i,remediation:'Avoid shell=True when input can be influenced externally. Pass an argument list and validate allowed values.'}
];

function finding(id,severity,title,summary,file,line,remediation,confidence='High',evidenceQuality='validated'){
  return {
    id:crypto.randomUUID(),
    fingerprint:crypto.createHash('sha1').update([id,file,line,title].join('|')).digest('hex').slice(0,20),
    checkId:id,
    category:'Code Security',
    severity,
    title,
    summary,
    location:file+(line?':'+line:''),
    affectedLocations:[file+(line?':'+line:'')],
    remediation,
    confidence,
    evidenceQuality,
    engine:'code-security',
    workflowStatus:'open'
  };
}

function highRiskPathFindings(paths){
  const out=[];
  for(const path of paths){
    if(/(^|\/)\.env(?:\.|$)/i.test(path)){
      out.push(finding('CODE-ENV-FILE','High','Environment file is committed to the repository','A .env-style file is present in the repository tree.',path,null,'Remove committed environment files, rotate any secrets they contained, add them to .gitignore, and use a secrets manager.'));
    }else if(/(?:^|\/)(?:id_rsa|id_ed25519|[^/]+\.(?:pem|key|p12|pfx))$/i.test(path)){
      out.push(finding('CODE-KEY-FILE','High','Key/certificate material is committed to the repository','A filename associated with private key or credential material is present.',path,null,'Confirm whether the file contains private material. Remove and rotate any private key or credential, then purge sensitive history if required.','Medium','observed'));
    }else if(/(?:backup|dump|database|prod|production).*(?:\.sql|\.zip|\.tar|\.gz|\.bak)$/i.test(path)){
      out.push(finding('CODE-BACKUP-FILE','Medium','Backup or export artifact is committed','A repository path looks like a database/site backup or production export.',path,null,'Confirm the artifact contains no sensitive data. Remove backups from source control and store them in access-controlled backup storage.','Medium','observed'));
    }
  }
  return out;
}

function scanText(path,text){
  const out=[];
  for(const pattern of secretPatterns){
    pattern.re.lastIndex=0;
    let match;
    while((match=pattern.re.exec(text))){
      const line=lineNumber(text,match.index);
      out.push(finding(pattern.id,pattern.severity,pattern.name+' appears in source control',
        'Inspector matched a high-confidence credential/secret pattern. The secret value is intentionally not stored or displayed.',
        path,line,'Revoke/rotate the credential immediately, remove it from the repository and history where appropriate, and move the secret to a managed secret store.'));
      if(out.length>=20) break;
    }
  }

  for(const sink of sinkPatterns){
    if(!sink.language.test(path)) continue;
    if(sink.id==='CODE-SINK-CHILD-PROCESS' && !/(?:node:)?child_process|from\s+['"]child_process['"]|require\(['"]child_process['"]\)/.test(text)) continue;
    sink.re.lastIndex=0;
    let match;
    while((match=sink.re.exec(text))){
      const start=text.lastIndexOf('\n',match.index)+1;
      const end=text.indexOf('\n',match.index);
      const lineText=text.slice(start,end<0?text.length:end).trim();
      if(/\bre\s*:\s*\//.test(lineText) || /new\s+RegExp\s*\(/.test(lineText) || /(?:secretPatterns|sinkPatterns)/.test(lineText)) continue;
      out.push(finding(sink.id,'Low',sink.title,
        'Inspector found a security-sensitive code sink. This is not proof of a vulnerability; review whether untrusted input can reach it.',
        path,lineNumber(text,match.index),sink.remediation,'Low','heuristic'));
      if(out.filter(x=>x.checkId===sink.id).length>=4) break;
    }
  }

  return out;
}

function dependenciesFromPackageLock(text){
  const out=[];
  try{
    const parsed=JSON.parse(text);
    if(parsed.packages&&typeof parsed.packages==='object'){
      for(const [path,item] of Object.entries(parsed.packages)){
        if(!path||!item?.version) continue;
        const name=item.name||path.replace(/^node_modules\//,'');
        if(name&&item.version) out.push({ecosystem:'npm',name,version:String(item.version)});
      }
    }else if(parsed.dependencies){
      for(const [name,item] of Object.entries(parsed.dependencies)){
        if(item?.version) out.push({ecosystem:'npm',name,version:String(item.version)});
      }
    }
  }catch{}
  return out;
}

function dependenciesFromPackageJson(text){
  const out=[];
  try{
    const parsed=JSON.parse(text);
    const groups=[parsed.dependencies||{},parsed.devDependencies||{},parsed.optionalDependencies||{}];
    for(const group of groups){
      for(const [name,versionRaw] of Object.entries(group)){
        const version=String(versionRaw||'').trim();
        if(/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(version)){
          out.push({ecosystem:'npm',name,version});
        }
      }
    }
  }catch{}
  return out;
}

function dependenciesFromRequirements(text){
  const out=[];
  for(const line of text.split(/\r?\n/)){
    const match=line.trim().match(/^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)$/);
    if(match) out.push({ecosystem:'PyPI',name:match[1],version:match[2]});
  }
  return out;
}

async function queryOsv(dependencies){
  const unique=[];
  const seen=new Set();
  for(const dep of dependencies){
    const key=dep.ecosystem+'|'+dep.name+'|'+dep.version;
    if(seen.has(key)) continue;
    seen.add(key); unique.push(dep);
    if(unique.length>=100) break;
  }
  if(!unique.length) return {dependencies:[],advisories:[]};

  const response=await fetch('https://api.osv.dev/v1/querybatch',{
    method:'POST',
    headers:{'content-type':'application/json'},
    body:JSON.stringify({queries:unique.map(d=>({package:{ecosystem:d.ecosystem,name:d.name},version:d.version}))}),
    signal:AbortSignal.timeout(15000)
  });
  if(!response.ok) throw new Error('OSV dependency lookup returned '+response.status+'.');
  const data=await response.json();
  const advisories=[];
  for(let i=0;i<(data.results||[]).length;i++){
    const dep=unique[i];
    for(const vuln of data.results[i]?.vulns||[]){
      advisories.push({
        id:vuln.id,
        dependency:dep,
        summary:vuln.summary||vuln.details?.slice(0,500)||'Dependency vulnerability',
        aliases:vuln.aliases||[],
        modified:vuln.modified||null
      });
      if(advisories.length>=150) break;
    }
  }
  return {dependencies:unique,advisories};
}

export async function scanGitHubRepository({repositoryUrl,token}){
  const repo=repoParts(repositoryUrl);
  const metadata=await gh('/repos/'+encodeURIComponent(repo.owner)+'/'+encodeURIComponent(repo.repo),token);
  const branch=metadata.default_branch||'main';
  const tree=await gh('/repos/'+encodeURIComponent(repo.owner)+'/'+encodeURIComponent(repo.repo)+'/git/trees/'+encodeURIComponent(branch)+'?recursive=1',token);
  const blobs=(tree.tree||[]).filter(item=>item.type==='blob'&&!item.path.includes('node_modules/'));
  const paths=blobs.map(x=>x.path);
  const findings=highRiskPathFindings(paths);

  const candidates=blobs.filter(item=>{
    if(item.size>350000) return false;
    return /(?:^|\/)(?:package-lock\.json|requirements(?:-[^/]+)?\.txt)$|\.(?:js|jsx|ts|tsx|mjs|cjs|py|go|java|rb|php|sh|yaml|yml|json|env|ini|conf|config|txt)$/i.test(item.path);
  }).sort((a,b)=>{
    const priority=(x)=>/package-lock\.json|requirements|\.env|\.pem|\.key/i.test(x.path)?0:1;
    return priority(a)-priority(b);
  }).slice(0,MAX_FILES);

  let bytesScanned=0;
  let filesScanned=0;
  const dependencies=[];
  let cursor=0;
  async function worker(){
    while(true){
      const index=cursor++;
      if(index>=candidates.length||bytesScanned>=MAX_BYTES) return;
      const item=candidates[index];
      try{
        const blob=await gh('/repos/'+encodeURIComponent(repo.owner)+'/'+encodeURIComponent(repo.repo)+'/git/blobs/'+item.sha,token);
        const text=blob.encoding==='base64'?Buffer.from(blob.content||'','base64').toString('utf8'):String(blob.content||'');
        if(bytesScanned+text.length>MAX_BYTES) continue;
        bytesScanned+=text.length; filesScanned+=1;
        findings.push(...scanText(item.path,text));
        if(/package-lock\.json$/i.test(item.path)) dependencies.push(...dependenciesFromPackageLock(text));
        if(/(^|\/)package\.json$/i.test(item.path)) dependencies.push(...dependenciesFromPackageJson(text));
        if(/requirements(?:-[^/]+)?\.txt$/i.test(item.path)) dependencies.push(...dependenciesFromRequirements(text));
      }catch{}
    }
  }
  await Promise.all(Array.from({length:5},()=>worker()));

  let dependencyData={dependencies:[],advisories:[],error:null};
  try{
    dependencyData=await queryOsv(dependencies);
  }catch(error){
    dependencyData={dependencies:dependencies.slice(0,100),advisories:[],error:String(error?.message||error).slice(0,300)};
  }

  for(const advisory of dependencyData.advisories.slice(0,80)){
    findings.push(finding('CODE-DEPENDENCY-VULN','Medium',
      advisory.id+' affects '+advisory.dependency.name+' '+advisory.dependency.version,
      advisory.summary,
      'dependency:'+advisory.dependency.name,
      null,
      'Upgrade the dependency to a non-affected version based on the upstream advisory, run the project test suite, and rerun Code Security.',
      'High','matched-version'));
  }

  const severityRank={Critical:5,High:4,Medium:3,Low:2,Informational:1};
  findings.sort((a,b)=>(severityRank[b.severity]||0)-(severityRank[a.severity]||0));

  return {
    id:'code_'+crypto.randomUUID(),
    type:'code-security',
    repository:repo,
    defaultBranch:branch,
    private:Boolean(metadata.private),
    scannedAt:new Date().toISOString(),
    stats:{
      repositoryFiles:blobs.length,
      filesScanned,
      bytesScanned,
      dependenciesChecked:dependencyData.dependencies.length,
      advisories:dependencyData.advisories.length,
      findings:findings.length
    },
    findings:findings.slice(0,180),
    dependencies:dependencyData.dependencies,
    advisories:dependencyData.advisories,
    dependencyLookupError:dependencyData.error,
    note:'Repository credentials are used only for this request and are not included in the returned scan object.'
  };
}
