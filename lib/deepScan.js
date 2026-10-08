import * as cheerio from 'cheerio';
import { safeFetch, assertPublicTarget } from './net';
import {
  crawlPages,
  discoverCertificateSubdomains,
  discoverCommonSubdomains,
  extractApiHints,
  fingerprintTechnologies,
  inspectJavaScriptBundles,
  classifyEndpoint
} from './discovery';
import { enrichTechnologiesWithCves } from './cve';
import { finding, runFullScan, scoreFindings } from './scanner';
import { validatePublicExposures } from './exposure';
import { assessApiSecurity } from './apiSecurity';
import { buildAttackPaths } from './attackPaths';

const severityRank={Critical:5,High:4,Medium:3,Low:2,Informational:1};

function rootDomain(hostname) {
  const host=String(hostname||'').toLowerCase().replace(/\.$/,'');
  const parts=host.split('.');
  if(parts.length<=2) return host;
  const commonSecondLevel=new Set(['co.uk','org.uk','ac.uk','gov.uk','com.au','net.au','org.au','co.nz','co.jp','com.sg','com.hk','com.br','com.mx','co.in']);
  const last2=parts.slice(-2).join('.');
  if(commonSecondLevel.has(last2) && parts.length>=3) return parts.slice(-3).join('.');
  return parts.slice(-2).join('.');
}

function headerObject(headers) {
  return Object.fromEntries(headers.entries());
}

function pageHeader(page,name) {
  return page.headers?.[name.toLowerCase()] || '';
}

function summarize(findings) {
  const out={critical:0,high:0,medium:0,low:0,informational:0};
  for(const item of findings){
    const key=String(item.severity||'').toLowerCase();
    if(key in out) out[key]+=1;
  }
  return out;
}

async function mapLimit(items,limit,worker) {
  const output=new Array(items.length);
  let cursor=0;
  async function runner(){
    while(true){
      const index=cursor++;
      if(index>=items.length) return;
      try{output[index]=await worker(items[index],index);}
      catch(error){output[index]={error:String(error?.message||error).slice(0,300),input:items[index]};}
    }
  }
  await Promise.all(Array.from({length:Math.min(limit,items.length)},()=>runner()));
  return output;
}

async function resolveLiveHost(hostname) {
  for(const protocol of ['https:','http:']){
    try{
      const url=new URL(protocol+'//'+hostname+'/');
      await assertPublicTarget(url);
      const response=await safeFetch(url.href,{
        method:'GET',
        headers:{accept:'text/html,application/json,text/plain,*/*'}
      },5000);
      const contentType=response.headers.get('content-type')||'';
      const body=(await response.text()).slice(0,1200000);
      return {
        hostname,
        url:response.url||url.href,
        protocol,
        status:response.status,
        contentType,
        body,
        headers:headerObject(response.headers)
      };
    }catch{}
  }
  return null;
}

async function discoverOpenApi(host) {
  const candidates=['/openapi.json','/swagger.json','/v3/api-docs','/api/openapi.json','/api-docs'];
  const endpoints=[];
  const specs=[];

  for(const path of candidates){
    try{
      const target=new URL(path,host.url);
      if(target.hostname!==host.hostname) continue;
      const response=await safeFetch(target.href,{
        method:'GET',
        headers:{accept:'application/json,application/yaml,text/yaml,*/*'}
      },4500);

      if(!(response.status>=200&&response.status<300)) continue;
      const contentType=response.headers.get('content-type')||'';
      const text=(await response.text()).slice(0,1500000);
      let parsed=null;
      try{ parsed=JSON.parse(text); }catch{}
      if(!parsed || !(parsed.openapi||parsed.swagger) || !parsed.paths || typeof parsed.paths!=='object') continue;

      specs.push({
        url:target.href,
        version:parsed.openapi||parsed.swagger,
        title:parsed.info?.title||null,
        pathCount:Object.keys(parsed.paths).length
      });

      for(const [apiPath,methods] of Object.entries(parsed.paths)){
        if(!methods || typeof methods!=='object') continue;
        for(const method of Object.keys(methods)){
          if(!['get','post','put','patch','delete','head','options'].includes(method.toLowerCase())) continue;
          const operation=methods[method] || {};
          const security=operation.security === undefined ? parsed.security : operation.security;
          const classified=classifyEndpoint({
            method:method.toUpperCase(),
            path:apiPath,
            host:host.hostname,
            source:'openapi'
          },host.hostname);
          endpoints.push({
            ...classified,
            authExpected:Array.isArray(security) && security.length>0,
            operationId:operation.operationId || null,
            summary:operation.summary || null
          });
          if(endpoints.length>=300) return {specs,endpoints};
        }
      }
    }catch{}
  }

  return {specs,endpoints};
}

function subdomainHeaderFindings(host,pages) {
  const findings=[];
  const htmlPages=pages.filter((p)=>p.html&&p.status>=200&&p.status<400);
  if(!htmlPages.length) return findings;

  const missingCsp=htmlPages.filter((p)=>!pageHeader(p,'content-security-policy')).map((p)=>p.url);
  if(missingCsp.length){
    findings.push(finding('DEEP-CSP','Security','Medium','CSP missing on discovered host',
      `Content-Security-Policy was absent on ${missingCsp.length} of ${htmlPages.length} sampled pages for ${host.hostname}.`,
      ['Host: '+host.hostname,...missingCsp.slice(0,10)].join('\n'),
      'Deploy a tested Content Security Policy consistently on this host.',
      {location:missingCsp[0],affectedLocations:missingCsp,engine:'deep-headers',evidenceQuality:'validated'}));
  }

  const missingFrame=htmlPages.filter((p)=>{
    const csp=pageHeader(p,'content-security-policy');
    return !pageHeader(p,'x-frame-options')&&!/frame-ancestors/i.test(csp);
  }).map((p)=>p.url);
  if(missingFrame.length){
    findings.push(finding('DEEP-FRAME','Security','Medium','Framing protection missing on discovered host',
      `${missingFrame.length} sampled pages on ${host.hostname} had no X-Frame-Options or CSP frame-ancestors restriction.`,
      ['Host: '+host.hostname,...missingFrame.slice(0,10)].join('\n'),
      'Set CSP frame-ancestors to the intended embedding origins.',
      {location:missingFrame[0],affectedLocations:missingFrame,engine:'deep-headers',evidenceQuality:'validated'}));
  }

  const powered=host.headers?.['x-powered-by'];
  if(powered){
    findings.push(finding('DEEP-POWERED-BY','Security','Informational','Framework/runtime version is publicly exposed',
      `${host.hostname} exposes X-Powered-By: ${powered}.`,
      'X-Powered-By: '+powered,
      'Suppress unnecessary runtime/version headers after confirming they are not needed operationally.',
      {location:host.url,engine:'deep-headers',evidenceQuality:'observed'}));
  }

  return findings;
}

async function scanHost(host,options={}) {
  const maxPages=Number(options.maxPages||12);
  const html=/text\/html|application\/xhtml/i.test(host.contentType||'');
  let pages=[];
  let discovery={robots:null,sitemapUrls:[],sitemapPages:[]};
  let javascript={bundles:[],apiHints:[],sourceMaps:[]};
  let technologies=[];
  let endpoints=[];

  if(html){
    const crawl=await crawlPages(host.url,host.body,host.headers,maxPages);
    pages=crawl.pages;
    discovery=crawl.discovery;
    technologies=fingerprintTechnologies(new Headers(host.headers),host.body);
    const [javascriptResult,openApi]=await Promise.all([
      inspectJavaScriptBundles(pages,3),
      discoverOpenApi(host)
    ]);
    javascript=javascriptResult;

    const markupHints=[...new Set(pages.flatMap((page)=>page.html?extractApiHints(page.url,page.html):[]))];
    const map=new Map();
    for(const path of [...markupHints,...javascript.apiHints]){
      const item=classifyEndpoint({
        method:'OBSERVE',
        path,
        host:host.hostname,
        source:javascript.apiHints.includes(path)?'javascript':'markup'
      },host.hostname);
      map.set(item.method+' '+item.path,item);
    }
    for(const endpoint of openApi.endpoints || []){
      map.set(endpoint.method+' '+endpoint.path,endpoint);
    }
    endpoints=[...map.values()]
      .filter((item)=>!['Analytics / Telemetry','Static / Generated asset'].includes(item.classification))
      .slice(0,300);
    discovery.openApiSpecs=openApi.specs || [];
  } else if(/json/i.test(host.contentType||'')){
    endpoints=[classifyEndpoint({method:'GET',path:new URL(host.url).pathname||'/',host:host.hostname,source:'host-root'},host.hostname)];
  }

  return {
    hostname:host.hostname,
    url:host.url,
    status:host.status,
    contentType:host.contentType,
    pages:pages.map((p)=>({url:p.url,status:p.status,source:p.source,title:p.title,bytes:p.bytes,error:p.error||null})),
    pageCount:pages.filter((p)=>p.html).length,
    discovery:{
      robots:discovery.robots,
      sitemapUrls:discovery.sitemapUrls||[],
      sitemapPages:(discovery.sitemapPages||[]).slice(0,100),
      openApiSpecs:discovery.openApiSpecs||[]
    },
    technologies,
    endpoints,
    javascript,
    findings:subdomainHeaderFindings(host,pages)
  };
}

function lifecycleAll(findings,previousScan) {
  const old=new Map((previousScan?.findings||[]).map((item)=>[item.fingerprint,item]));
  const current=new Set();

  for(const item of findings){
    current.add(item.fingerprint);
    const prior=old.get(item.fingerprint);
    item.lifecycle=prior?'open':'new';
    item.workflowStatus=prior?.workflowStatus||'open';
  }

  const resolved=(previousScan?.findings||[])
    .filter((item)=>!current.has(item.fingerprint))
    .map((item)=>({...item,lifecycle:'resolved',resolvedAt:new Date().toISOString()}));

  return resolved;
}

function cveFinding(vulnerability,affectedHosts) {
  const score=vulnerability.cvss?.score;
  const severity=score>=9?'Critical':score>=7?'High':score>=4?'Medium':'Low';
  const hostList=affectedHosts.slice(0,12);
  const cwe=(vulnerability.cwes||[]).join(', ')||'not specified';

  return finding(
    vulnerability.id,
    'Vulnerability',
    severity,
    `${vulnerability.id} may affect detected ${vulnerability.technology} ${vulnerability.version}`,
    `NVD lists this CVE for the exact detected CPE/version. CVSS base score: ${score ?? 'unscored'} (${vulnerability.cvss?.severity||'unknown'}).`,
    [
      'Technology: '+vulnerability.technology+' '+vulnerability.version,
      'CPE: '+vulnerability.cpe,
      'CVSS: '+(score ?? 'unscored')+' '+(vulnerability.cvss?.vector||''),
      'CWE: '+cwe,
      'NVD description: '+vulnerability.description,
      'Observed on: '+hostList.join(', ')
    ].join('\n'),
    `Confirm the deployed ${vulnerability.technology} version, review the vendor/NVD advisory for ${vulnerability.id}, then upgrade to a release outside the affected range. Validate compatibility in staging and rerun Deep Scan after deployment.`,
    {
      location:hostList[0]||'',
      affectedLocations:hostList,
      engine:'cve-nvd',
      confidence:'High',
      evidenceQuality:'matched-version'
    }
  );
}

export async function runDeepScan({url,previousScan=null}) {
  const primary=await runFullScan({url,previousScan});
  const root=rootDomain(new URL(primary.finalUrl).hostname);

  const [common,certificateNames]=await Promise.all([
    discoverCommonSubdomains(root),
    discoverCertificateSubdomains(root,120)
  ]);

  const commonNames=common.map((item)=>item.host);
  const candidates=[root,...commonNames,...certificateNames]
    .filter(Boolean)
    .filter((value,index,array)=>array.indexOf(value)===index)
    .slice(0,80);

  const liveResults=(await mapLimit(candidates.slice(0,50),6,resolveLiveHost)).filter(Boolean);
  const liveHosts=liveResults.filter((item)=>item&&item.hostname);

  const hostLimit=50;
  const selectedHosts=liveHosts
    .sort((a,b)=>{
      const aPriority=a.hostname===root?0:commonNames.includes(a.hostname)?1:2;
      const bPriority=b.hostname===root?0:commonNames.includes(b.hostname)?1:2;
      return aPriority-bPriority;
    })
    .slice(0,hostLimit);

  const scanned=(await mapLimit(selectedHosts,4,(host)=>scanHost(host,{maxPages:20}))).filter((item)=>item&&!item.error);

  const primaryHost=new URL(primary.finalUrl).hostname;
  const primaryRecord=scanned.find((item)=>item.hostname===primaryHost)||scanned.find((item)=>item.hostname===root);
  const additionalFindings=scanned
    .filter((item)=>item.hostname!==primaryHost && item.hostname!==root)
    .flatMap((item)=>item.findings||[]);

  const technologyOccurrences=new Map();
  const registerTechnology=(technology,host)=>{
    const key=technology.name+'|'+(technology.version||'');
    if(!technologyOccurrences.has(key)) technologyOccurrences.set(key,{technology,hosts:new Set()});
    technologyOccurrences.get(key).hosts.add(host);
  };

  for(const technology of primary.evidence?.inventory?.technologies||[]) registerTechnology(technology,primaryHost);
  for(const host of scanned){
    for(const technology of host.technologies||[]) registerTechnology(technology,host.hostname);
  }

  const technologies=[...technologyOccurrences.values()].map((entry)=>entry.technology);
  const cveData=await enrichTechnologiesWithCves(technologies,{maxTechnologies:3});
  const cveFindings=[];

  for(const vulnerability of cveData.vulnerabilities||[]){
    const key=vulnerability.technology+'|'+(vulnerability.version||'');
    const hosts=[...(technologyOccurrences.get(key)?.hosts||[])];
    cveFindings.push(cveFinding(vulnerability,hosts));
  }

  const merged=[...primary.findings,...additionalFindings,...cveFindings];
  const unique=new Map();
  for(const item of merged){
    const key=item.fingerprint;
    if(!unique.has(key)||severityRank[item.severity]>severityRank[unique.get(key).severity]) unique.set(key,item);
  }
  primary.findings=[...unique.values()];
  primary.resolvedFindings=lifecycleAll(primary.findings,previousScan);
  primary.summary=summarize(primary.findings);
  primary.score=scoreFindings(primary.findings);
  primary.mode='deep';
  primary.scanType='Deep Scan';

  const allEndpoints=[];
  for(const item of primary.evidence?.inventory?.apiEndpoints||[]) allEndpoints.push({...item,hostname:primaryHost});
  for(const host of scanned){
    for(const endpoint of host.endpoints||[]) allEndpoints.push({...endpoint,hostname:host.hostname});
  }

  const endpointKey=(item)=>item.hostname+'|'+item.method+'|'+item.path;
  const endpointMap=new Map();
  for(const endpoint of allEndpoints) endpointMap.set(endpointKey(endpoint),endpoint);
  const endpoints=[...endpointMap.values()].slice(0,500);

  const [exposureFindings,apiSecurity]=await Promise.all([
    validatePublicExposures({rootDomain:root,liveHosts}),
    assessApiSecurity({rootDomain:root,endpoints})
  ]);

  const validatedMerged=[...primary.findings,...exposureFindings,...apiSecurity.findings];
  const validatedUnique=new Map();
  for(const item of validatedMerged){
    const key=item.fingerprint;
    if(!validatedUnique.has(key)||severityRank[item.severity]>severityRank[validatedUnique.get(key).severity]) validatedUnique.set(key,item);
  }
  primary.findings=[...validatedUnique.values()];
  primary.resolvedFindings=lifecycleAll(primary.findings,previousScan);
  primary.summary=summarize(primary.findings);
  primary.score=scoreFindings(primary.findings);

  const totalPages=(primary.metrics?.pagesCrawled||0)+scanned
    .filter((item)=>item.hostname!==primaryHost)
    .reduce((sum,item)=>sum+(item.pageCount||0),0);

  primary.engineStatus={
    ...(primary.engineStatus||{}),
    apiDiscovery:{
      status:endpoints.length?'complete':'degraded',
      endpoints:endpoints.length,
      dynamicRequests:primary.metrics?.dynamicApiRequests||0,
      scope:'domain'
    },
    deepDiscovery:{
      status:'complete',
      subdomainsDiscovered:candidates.length-1,
      liveHosts:liveHosts.length,
      hostsScanned:scanned.length
    },
    exposureValidation:{
      status:'complete',
      findings:exposureFindings.length,
      hostsTested:Math.min(liveHosts.length,20)
    },
    apiSecurity:{
      status:apiSecurity.coverage.length?'complete':'degraded',
      endpointsTested:apiSecurity.coverage.length,
      findings:apiSecurity.findings.length
    }
  };
  const deepCoreFailures=['browser','security','crawler'].filter((key)=>primary.engineStatus[key]?.status==='failed');
  primary.coverageGaps=Object.entries(primary.engineStatus)
    .filter(([,value])=>value?.status==='degraded'||value?.status==='failed')
    .map(([key])=>key);
  primary.status=deepCoreFailures.length?'partial':primary.coverageGaps.length?'completed_with_gaps':'completed';
  primary.scoreConfidence=primary.coverageGaps.length?(deepCoreFailures.length?'low':'medium'):'high';

  primary.metrics={
    ...primary.metrics,
    deep:true,
    rootDomain:root,
    subdomainsDiscovered:candidates.length-1,
    liveHosts:liveHosts.length,
    hostsScanned:scanned.length,
    domainPagesCrawled:totalPages,
    domainApiEndpoints:endpoints.length,
    cveProductsQueried:cveData.queried,
    cvesMatched:cveData.vulnerabilities?.length||0,
    exposuresValidated:exposureFindings.length,
    apiSecurityEndpointsTested:apiSecurity.coverage.length
  };

  primary.deepCoverage={
    rootDomain:root,
    discoverySources:['DNS common labels','Certificate Transparency','robots.txt','sitemaps','same-host links','JavaScript bundles','browser network'],
    subdomainsDiscovered:candidates.length-1,
    liveHostsConfirmed:liveHosts.length,
    hostsScanned:scanned.length,
    hostLimit,
    pagesPerHostLimit:20,
    endpointLimit:500,
    truncated:liveHosts.length>hostLimit||candidates.length>=80,
    note:'Deep Scan covers public, discoverable HTTP(S) assets. It cannot guarantee discovery of unadvertised, access-controlled or non-HTTP services.'
  };

  primary.evidence={
    ...primary.evidence,
    deep:{
      rootDomain:root,
      candidates,
      liveHosts:liveHosts.map((item)=>({
        hostname:item.hostname,url:item.url,status:item.status,contentType:item.contentType
      })),
      hosts:scanned.map((item)=>({
        hostname:item.hostname,
        url:item.url,
        status:item.status,
        contentType:item.contentType,
        pageCount:item.pageCount,
        pages:item.pages,
        technologies:item.technologies,
        endpoints:item.endpoints,
        sourceMaps:item.javascript?.sourceMaps||[],
        sitemapPages:item.discovery?.sitemapPages||[]
      })),
      endpoints,
      exposureValidation:{
        findings:exposureFindings,
        hostsTested:Math.min(liveHosts.length,20)
      },
      apiSecurity:{
        coverage:apiSecurity.coverage,
        findings:apiSecurity.findings
      },
      cves:cveData
    }
  };

  const attackPaths=buildAttackPaths(primary);
  primary.attackPaths=attackPaths;
  primary.metrics.attackPaths=attackPaths.length;
  primary.evidence.attackPaths=attackPaths;

  primary.priorities=[...primary.findings]
    .filter((item)=>['Critical','High','Medium'].includes(item.severity))
    .sort((a,b)=>severityRank[b.severity]-severityRank[a.severity])
    .slice(0,12)
    .map((item)=>({
      fingerprint:item.fingerprint,
      title:item.title,
      severity:item.severity,
      checkId:item.checkId,
      category:item.category,
      affected:item.affectedLocations?.length||1
    }));

  return primary;
}
