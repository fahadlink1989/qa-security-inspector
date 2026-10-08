import crypto from 'node:crypto';

function id(parts){
  return 'path_'+crypto.createHash('sha1').update(parts.join('|')).digest('hex').slice(0,14);
}

function path(title,risk,confidence,summary,steps,impact,remediation,status='needs_validation'){
  return {id:id([title,...steps.map(s=>s.label)]),title,risk,confidence,summary,steps,impact,remediation,status};
}

export function buildAttackPaths(scan){
  const findings=scan.findings||[];
  const deep=scan.evidence?.deep||{};
  const paths=[];
  const has=(id)=>findings.filter(f=>f.checkId===id);
  const sourceMaps=(deep.hosts||[]).flatMap(h=>(h.sourceMaps||[]).map(m=>({host:h.hostname,url:m.url||m})));
  const endpoints=deep.endpoints||[];
  const staging=(deep.liveHosts||[]).filter(h=>/staging|dev|test|uat|qa/i.test(h.hostname));
  const authHosts=(deep.liveHosts||[]).filter(h=>/auth|login|sso|identity/i.test(h.hostname));
  const highCves=findings.filter(f=>f.engine==='cve-nvd'&&['Critical','High'].includes(f.severity));
  const exposedArtifacts=findings.filter(f=>/^EXP-(?:GIT|ENV|BACKUP|SITE|SQL|PHPINFO|ACTUATOR-ENV)/.test(f.checkId));
  const dangling=has('EXP-DANGLING-DNS');
  const apiExposure=findings.filter(f=>/^API-(?:AUTH-EXPECTED-200|PUBLIC-SENSITIVE-DATA)/.test(f.checkId));

  for(const f of exposedArtifacts.slice(0,4)){
    paths.push(path(
      'Public deployment artifact → internal information exposure',
      f.severity==='High'?'High':'Medium','High',
      'Inspector validated an internet-accessible deployment/debug artifact that can reveal information useful for follow-on access.',
      [
        {type:'observed',label:'Public host',evidence:f.location},
        {type:'observed',label:f.title,evidence:String(f.evidence||'').slice(0,500)},
        {type:'impact',label:'Credential/configuration reconnaissance',evidence:'Artifact contents may reveal code, configuration, paths or credentials depending on what is exposed.'}
      ],
      'An attacker may gain information that lowers the cost of targeting authentication, APIs or infrastructure.',
      f.remediation,
      'validated'
    ));
  }

  for(const f of apiExposure.slice(0,4)){
    paths.push(path(
      'Public API → missing/unclear authorization boundary → data exposure',
      'High',f.confidence||'Medium',
      'A first-party API returned a successful unauthenticated response where authentication or sensitive account data may be expected.',
      [
        {type:'observed',label:'Internet-reachable API',evidence:f.location},
        {type:'observed',label:'Unauthenticated successful response',evidence:String(f.evidence||'').slice(0,600)},
        {type:'impact',label:'Potential unauthorized data access',evidence:'Requires owner validation to distinguish intended public data from broken authorization.'}
      ],
      'If the response is not intentionally public, this can expose user/account information or enable unauthorized application access.',
      f.remediation,
      'needs_validation'
    ));
  }

  for(const f of dangling.slice(0,3)){
    paths.push(path(
      'Dangling DNS → third-party resource claim → trusted subdomain control',
      'High','Medium',
      'A public subdomain points at a provider hostname that did not resolve during validation.',
      [
        {type:'observed',label:'Public DNS record',evidence:f.location},
        {type:'correlated',label:'Unresolved third-party CNAME target',evidence:String(f.evidence||'').slice(0,500)},
        {type:'impact',label:'Potential trusted subdomain takeover',evidence:'Actual exploitability depends on provider-specific resource claiming behavior.'}
      ],
      'If claimable, an attacker could host content under a trusted company subdomain and abuse brand trust, cookies or OAuth assumptions.',
      f.remediation
    ));
  }

  for(const f of highCves.slice(0,4)){
    paths.push(path(
      'Internet-facing component → matched high-severity CVE → service compromise risk',
      f.severity,'High',
      'Inspector matched an exact detected product/version to a high-severity NVD vulnerability.',
      [
        {type:'observed',label:'Versioned public technology',evidence:f.location},
        {type:'correlated',label:f.checkId,evidence:String(f.evidence||'').slice(0,700)},
        {type:'impact',label:'Vendor-defined vulnerability impact',evidence:f.impact||f.summary}
      ],
      'Actual exploitability depends on configuration and reachable vulnerable functionality, but the component should be prioritized for patch validation.',
      f.remediation,
      'validated'
    ));
  }

  if(sourceMaps.length && endpoints.length){
    paths.push(path(
      'Public source maps → client-code visibility → API reconnaissance',
      'Medium','High',
      'Public source maps can reveal original client code and implementation context while Inspector also observed first-party API endpoints.',
      [
        {type:'observed',label:'Public source map',evidence:sourceMaps[0].url},
        {type:'correlated',label:endpoints.length+' discovered API endpoints',evidence:endpoints.slice(0,6).map(e=>(e.method||'OBSERVE')+' '+e.hostname+e.path).join('\n')},
        {type:'modeled',label:'Expanded application reconnaissance',evidence:'Source context may reveal route names, feature flags, internal assumptions or API usage.'}
      ],
      'This does not prove compromise, but it can reduce reconnaissance effort and make exposed APIs easier to understand.',
      'Confirm whether production source maps are required. Remove or restrict them if they expose proprietary implementation detail, then review discovered API authorization boundaries.'
    ));
  }

  if(staging.length){
    const stagingEndpoints=endpoints.filter(e=>/staging|dev|test|uat|qa/i.test(e.hostname||''));
    paths.push(path(
      'Public non-production host → application/API surface → weaker-control risk',
      stagingEndpoints.length?'Medium':'Low','Medium',
      'Inspector found publicly reachable staging/test-style hosts'+(stagingEndpoints.length?' with discoverable API routes':'')+'.',
      [
        {type:'observed',label:staging.length+' public non-production host(s)',evidence:staging.slice(0,8).map(h=>h.hostname+' HTTP '+h.status).join('\n')},
        ...(stagingEndpoints.length?[{type:'correlated',label:stagingEndpoints.length+' API endpoint(s) on non-production hosts',evidence:stagingEndpoints.slice(0,8).map(e=>e.hostname+e.path).join('\n')}]:[]),
        {type:'modeled',label:'Potential weaker authentication/configuration',evidence:'Non-production systems often receive less hardening; Inspector has not assumed that is true without validation.'}
      ],
      'If controls differ from production, these hosts can become an alternate path to code, credentials, APIs or internal services.',
      'Confirm each non-production hostname is required publicly. Prefer identity-aware access, IP restrictions or removal from public DNS; ensure secrets and data are isolated from production.'
    ));
  }

  if(authHosts.length){
    paths.push(path(
      'Public identity surface → authentication attack surface',
      'Medium','High',
      'Inspector identified internet-facing authentication/login-related hosts and related API/application surfaces.',
      [
        {type:'observed',label:authHosts.length+' identity-related host(s)',evidence:authHosts.slice(0,8).map(h=>h.hostname+' HTTP '+h.status).join('\n')},
        {type:'correlated',label:'Authentication-classified endpoints',evidence:endpoints.filter(e=>e.classification==='Authentication').slice(0,8).map(e=>e.hostname+e.path).join('\n')||'No explicit auth endpoints extracted'}
      ],
      'These surfaces are expected for many products, but they deserve stronger monitoring, MFA, rate limiting and authorization testing because compromise affects account access.',
      'Verify MFA coverage, rate limiting, session security, recovery flows and negative authorization tests across the identified identity surfaces.',
      'observed'
    ));
  }

  return paths.slice(0,12);
}
