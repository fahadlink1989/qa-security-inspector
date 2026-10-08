import crypto from 'node:crypto';
import * as cheerio from 'cheerio';
import { safeFetch, assertPublicTarget } from './net';
import { finding, scoreFindings } from './scanner';
import { runBrowserChecks } from './browser';
import { classifyEndpoint } from './discovery';

const severityRank={Critical:5,High:4,Medium:3,Low:2,Informational:1};

function rootDomain(hostname){
  const host=String(hostname||'').toLowerCase().replace(/\.$/,'');
  const parts=host.split('.');
  if(parts.length<=2) return host;
  const commonSecondLevel=new Set(['co.uk','org.uk','ac.uk','gov.uk','com.au','net.au','org.au','co.nz','co.jp','com.sg','com.hk','com.br','com.mx','co.in']);
  const last2=parts.slice(-2).join('.');
  if(commonSecondLevel.has(last2)&&parts.length>=3) return parts.slice(-3).join('.');
  return parts.slice(-2).join('.');
}

function firstParty(hostname,root){
  const h=String(hostname||'').toLowerCase();
  const r=String(root||'').toLowerCase();
  return h===r||h.endsWith('.'+r);
}

function normalizeAuth(input={}){
  const type=input.type==='cookie'?'cookie':'bearer';
  const value=String(input.value||'').trim();
  if(!value) throw new Error(type==='cookie'?'Cookie header is required.':'Bearer token is required.');
  if(value.length>12000) throw new Error('Authentication value is too large.');
  if(/[\r\n]/.test(value)) throw new Error('Authentication value contains unsupported line breaks.');
  return {type,value};
}

function authHeaders(url,root,auth){
  const parsed=new URL(url);
  if(!firstParty(parsed.hostname,root)) return {};
  if(auth.type==='cookie') return {cookie:auth.value};
  return {authorization:'Bearer '+auth.value};
}

function redact(text,auth){
  let value=String(text||'');
  if(auth?.value) value=value.split(auth.value).join('[REDACTED]');
  return value.slice(0,1800);
}

function bodySignature(text){
  return crypto.createHash('sha256').update(String(text||'').slice(0,500000)).digest('hex');
}

function collectKeys(value,keys=new Set(),depth=0){
  if(depth>4||value==null) return keys;
  if(Array.isArray(value)){
    for(const item of value.slice(0,4)) collectKeys(item,keys,depth+1);
    return keys;
  }
  if(typeof value==='object'){
    for(const [key,item] of Object.entries(value).slice(0,100)){
      keys.add(key);
      collectKeys(item,keys,depth+1);
    }
  }
  return keys;
}

const sensitiveKey=/^(?:email|phone|mobile|address|name|first_?name|last_?name|user_?id|account_?id|customer_?id|subscription|invoice|role|permissions?|token|access_?token|refresh_?token|api_?key|secret|card|payment|billing)$/i;
const accountPath=/(?:^|\/)(?:me|profile|account|accounts|user|users|customer|customers|subscription|subscriptions|billing|invoice|invoices|session|sessions|admin)(?:\/|$|\?)/i;
const loginPath=/(?:login|sign-?in|auth|session|sso)/i;

async function summarizeResponse(response,method='GET',maxBytes=500000){
  const contentType=response.headers.get('content-type')||'';
  const status=response.status;
  const finalUrl=response.url||'';
  if(method==='HEAD') return {status,contentType,finalUrl,bodyKind:'none',keys:[],sensitiveKeys:[],signature:null,bytes:0};

  const length=Number(response.headers.get('content-length')||0);
  if(length>2_000_000) return {status,contentType,finalUrl,bodyKind:'large',keys:[],sensitiveKeys:[],signature:null,bytes:length};

  const text=(await response.text()).slice(0,maxBytes);
  const summary={status,contentType,finalUrl,bodyKind:'text',keys:[],sensitiveKeys:[],signature:bodySignature(text),bytes:text.length};
  if(/json/i.test(contentType)||/^\s*[\[{]/.test(text)){
    try{
      const parsed=JSON.parse(text);
      const keys=[...collectKeys(parsed)].slice(0,140);
      summary.bodyKind='json';
      summary.keys=keys;
      summary.sensitiveKeys=keys.filter((key)=>sensitiveKey.test(key)).slice(0,40);
    }catch{}
  } else if(/html/i.test(contentType)){
    summary.bodyKind='html';
    const $=cheerio.load(text);
    summary.title=$('title').text().trim();
    summary.links=$('a[href]').length;
    summary.forms=$('form').length;
    summary.signature=bodySignature($('body').text().replace(/\s+/g,' ').slice(0,300000));
  }
  return summary;
}

async function requestSummary(url,root,auth=null,method='GET'){
  const headers={
    accept:'application/json,text/html,text/plain,*/*',
    ...(auth?authHeaders(url,root,auth):{})
  };
  const response=await safeFetch(url,{method,headers},6500);
  return summarizeResponse(response,method);
}

function protectedByUnauth(unauth,auth){
  if(!auth || !(auth.status>=200&&auth.status<400)) return false;
  if([401,403].includes(unauth?.status)) return true;
  if(unauth?.finalUrl && loginPath.test(new URL(unauth.finalUrl).pathname) && !loginPath.test(new URL(auth.finalUrl||'http://invalid').pathname)) return true;
  return false;
}

function safeCandidate(endpoint,root){
  if(!endpoint?.hostname||!endpoint?.path) return false;
  if(!firstParty(endpoint.hostname,root)) return false;
  const method=String(endpoint.method||'OBSERVE').toUpperCase();
  if(!['GET','HEAD','OBSERVE'].includes(method)) return false;
  if(endpoint.path.includes('{')||endpoint.path.includes('}')) return false;
  if(/logout|signout|delete|remove|unsubscribe|download|export|destroy/i.test(endpoint.path)) return false;
  if(['Analytics / Telemetry','Static / Generated asset'].includes(endpoint.classification)) return false;
  return true;
}

function sameResponse(a,b){
  return Boolean(a?.signature&&b?.signature&&a.signature===b.signature&&a.status===b.status);
}

async function crawlAuthenticated(entryUrl,root,auth,maxPages=12){
  const pages=[];
  const queue=[entryUrl];
  const seen=new Set();

  while(queue.length&&pages.length<maxPages){
    const url=queue.shift();
    if(seen.has(url)) continue;
    seen.add(url);

    try{
      const response=await safeFetch(url,{
        method:'GET',
        headers:{accept:'text/html,application/xhtml+xml',...authHeaders(url,root,auth)}
      },7000);
      const contentType=response.headers.get('content-type')||'';
      const finalUrl=response.url||url;
      const status=response.status;
      if(!/text\/html|application\/xhtml/i.test(contentType)){
        pages.push({url,finalUrl,status,contentType,title:'',source:'authenticated-crawl'});
        continue;
      }
      const html=(await response.text()).slice(0,1400000);
      const $=cheerio.load(html);
      const title=$('title').text().trim();
      let unauth=null;
      try{unauth=await requestSummary(url,root,null,'GET');}catch{}
      const authSummary={status,contentType,finalUrl,bodyKind:'html',signature:bodySignature($('body').text().replace(/\s+/g,' ').slice(0,300000))};
      const protectedPage=unauth?protectedByUnauth(unauth,authSummary):false;
      pages.push({
        url,
        finalUrl,
        status,
        title,
        contentType,
        protected:protectedPage,
        unauthStatus:unauth?.status??null,
        unauthFinalUrl:unauth?.finalUrl||null,
        source:'authenticated-crawl'
      });

      $('a[href]').each((_,el)=>{
        if(queue.length+pages.length>=maxPages*3) return false;
        const href=$(el).attr('href');
        if(!href||href.startsWith('#')||href.startsWith('mailto:')||href.startsWith('tel:')||href.startsWith('javascript:')) return;
        try{
          const next=new URL(href,finalUrl);
          next.hash='';
          if(['http:','https:'].includes(next.protocol)&&firstParty(next.hostname,root)&&!seen.has(next.href)) queue.push(next.href);
        }catch{}
      });
    }catch(error){
      pages.push({url,finalUrl:url,status:0,title:'',contentType:'',protected:false,error:redact(error?.message||error,auth),source:'authenticated-crawl'});
    }
  }
  return pages;
}

function sourceEndpoints(sourceScan,targetHost){
  if(sourceScan?.mode==='deep'){
    return (sourceScan.evidence?.deep?.endpoints||[]).filter((item)=>item?.hostname);
  }
  return (sourceScan?.evidence?.inventory?.apiEndpoints||[]).map((item)=>({
    ...item,
    hostname:item.hostname||targetHost
  }));
}

function lifecycle(findings,previous){
  const old=new Map((previous?.findings||[]).map((item)=>[item.fingerprint,item]));
  for(const item of findings){
    const prior=old.get(item.fingerprint);
    item.lifecycle=prior?'open':'new';
    item.workflowStatus=prior?.workflowStatus||'open';
  }
}

export async function runAuthenticatedScan({url,sourceScan=null,previousScan=null,auth:authInput}){
  const startedAt=new Date().toISOString();
  const target=new URL(url);
  await assertPublicTarget(target);
  const root=rootDomain(target.hostname);
  const auth=normalizeAuth(authInput);

  let entryAuth;
  try{
    entryAuth=await requestSummary(target.href,root,auth,'GET');
  }catch(error){
    throw new Error('Authenticated request could not reach the target: '+redact(error?.message||error,auth));
  }

  if([401,403].includes(entryAuth.status)){
    throw new Error('The supplied session was rejected by the selected asset (HTTP '+entryAuth.status+').');
  }

  const pages=await crawlAuthenticated(target.href,root,auth,12);
  const browserTargets=pages.filter((page)=>page.status>=200&&page.status<400).map((page)=>page.finalUrl||page.url).slice(0,3);
  const browser=await runBrowserChecks(target.href,browserTargets,{auth,rootDomain:root});

  const endpoints=sourceEndpoints(sourceScan,target.hostname)
    .filter((item)=>safeCandidate(item,root))
    .slice(0,30);

  const endpointCoverage=[];
  const findings=[];
  let cursor=0;

  async function worker(){
    while(true){
      const index=cursor++;
      if(index>=endpoints.length) return;
      const endpoint=endpoints[index];
      const method=String(endpoint.method||'GET').toUpperCase()==='HEAD'?'HEAD':'GET';
      const path=String(endpoint.path||'/');
      const url='https://'+endpoint.hostname+path;
      try{
        const [unauthenticated,authenticated]=await Promise.all([
          requestSummary(url,root,null,method).catch(()=>null),
          requestSummary(url,root,auth,method).catch(()=>null)
        ]);
        if(!authenticated) continue;

        const isProtected=unauthenticated?protectedByUnauth(unauthenticated,authenticated):false;
        const identical=unauthenticated?sameResponse(unauthenticated,authenticated):false;
        const record={
          method,
          url,
          classification:endpoint.classification||classifyEndpoint({method,path,host:endpoint.hostname,source:'authenticated'},target.hostname).classification,
          authExpected:Boolean(endpoint.authExpected),
          unauthStatus:unauthenticated?.status??null,
          authStatus:authenticated.status,
          protected:isProtected,
          sameAsUnauthenticated:identical,
          bodyKind:authenticated.bodyKind,
          authenticatedKeys:authenticated.keys?.slice(0,40)||[],
          sensitiveKeys:authenticated.sensitiveKeys?.slice(0,30)||[]
        };
        endpointCoverage.push(record);

        if(endpoint.authExpected && unauthenticated && unauthenticated.status>=200&&unauthenticated.status<300){
          const highEvidence=identical||authenticated.sensitiveKeys?.length>0;
          findings.push(finding(
            'AUTH-EXPECTED-ENDPOINT-PUBLIC',
            'Authenticated Security',
            authenticated.sensitiveKeys?.length?'High':'Medium',
            'Endpoint documented as protected also responds without authentication',
            'An endpoint carrying an OpenAPI security requirement returned a successful unauthenticated response during safe comparison.',
            [
              'Endpoint: '+url,
              'Unauthenticated HTTP: '+unauthenticated.status,
              'Authenticated HTTP: '+authenticated.status,
              'Same response signature: '+(identical?'yes':'no'),
              'Authenticated response field names: '+(authenticated.keys?.slice(0,30).join(', ')||'none observed'),
              'Potentially sensitive field names: '+(authenticated.sensitiveKeys?.join(', ')||'none observed'),
              'Credential values and response values were not stored.'
            ].join('\n'),
            'Confirm whether this operation is intended to require authentication. If yes, enforce authentication/authorization before business logic, add a negative authorization test, and rerun Authenticated Scan.',
            {location:url,engine:'authenticated-api',confidence:highEvidence?'High':'Medium',evidenceQuality:'validated'}
          ));
        } else if(
          unauthenticated &&
          unauthenticated.status>=200&&unauthenticated.status<300 &&
          authenticated.status>=200&&authenticated.status<300 &&
          accountPath.test(path) &&
          authenticated.sensitiveKeys?.length>0 &&
          identical
        ){
          findings.push(finding(
            'AUTH-SENSITIVE-SAME-AS-PUBLIC',
            'Authenticated Security',
            'High',
            'Account-style API returns the same structured response without authentication',
            'A first-party account/profile/billing-style endpoint returned the same response signature with and without the supplied session and exposed sensitive-looking field names.',
            [
              'Endpoint: '+url,
              'Unauthenticated HTTP: '+unauthenticated.status,
              'Authenticated HTTP: '+authenticated.status,
              'Same response signature: yes',
              'Potentially sensitive field names: '+authenticated.sensitiveKeys.join(', '),
              'Response values were intentionally not persisted.'
            ].join('\n'),
            'Validate whether this data is intentionally public. If not, require authentication and object-level authorization before returning records, minimize response fields, and add negative authorization tests.',
            {location:url,engine:'authenticated-api',confidence:'Medium',evidenceQuality:'validated'}
          ));
        }
      }catch(error){
        endpointCoverage.push({method,url,status:'error',error:redact(error?.message||error,auth)});
      }
    }
  }

  await Promise.all(Array.from({length:4},()=>worker()));

  const protectedPages=pages.filter((page)=>page.protected);
  const protectedEndpoints=endpointCoverage.filter((item)=>item.protected);
  const suspiciousPublic=endpointCoverage.filter((item)=>item.sameAsUnauthenticated&&(item.authExpected||item.sensitiveKeys?.length));
  const sessionEffectConfirmed=protectedPages.length>0 || protectedEndpoints.length>0;

  if(browser.status==='failed'){
    findings.push(finding(
      'AUTH-BROWSER-FAILED',
      'Scan Health',
      'Informational',
      'Authenticated browser validation did not complete',
      'The HTTP authenticated comparison completed, but the rendered browser layer could not validate the supplied session.',
      redact(browser.error||'Browser engine unavailable.',auth),
      'Retry with a fresh test session. Treat rendered post-login coverage as unavailable until the browser engine succeeds.',
      {location:target.href,engine:'authenticated-browser',confidence:'High',evidenceQuality:'observed'}
    ));
  }

  lifecycle(findings,previousScan);
  const summary={critical:0,high:0,medium:0,low:0,informational:0};
  for(const item of findings){
    const key=String(item.severity||'').toLowerCase();
    if(key in summary) summary[key]+=1;
  }

  const score=scoreFindings(findings);
  const coverageGaps=[];
  if(browser.status!=='complete') coverageGaps.push('authenticatedBrowser');
  if(!endpoints.length) coverageGaps.push('endpointInventory');
  if(!sessionEffectConfirmed) coverageGaps.push('sessionEffectUnconfirmed');

  return {
    id:'auth_'+crypto.randomUUID(),
    type:'authenticated-security',
    mode:'authenticated',
    scanType:'Authenticated Scan',
    url:target.href,
    finalUrl:entryAuth.finalUrl||target.href,
    host:target.hostname,
    startedAt,
    completedAt:new Date().toISOString(),
    status:coverageGaps.length?'completed_with_gaps':'completed',
    score,
    scoreConfidence:coverageGaps.length?'medium':'high',
    summary,
    findings,
    resolvedFindings:[],
    coverageGaps,
    auth:{
      method:auth.type,
      credentialStored:false,
      credentialValue:'not persisted',
      sessionEffectConfirmed
    },
    metrics:{
      authenticatedPages:pages.filter((page)=>page.status>=200&&page.status<400).length,
      protectedPages:protectedPages.length,
      endpointsTested:endpointCoverage.length,
      protectedEndpoints:protectedEndpoints.length,
      suspiciousPublicEndpoints:suspiciousPublic.length,
      browserPages:browser.metrics?.pagesTested||0,
      browserDesktopPages:browser.metrics?.desktopPages||0,
      browserMobilePages:browser.metrics?.mobilePages||0,
      sessionEffectConfirmed
    },
    protectedSurface:{
      pages:protectedPages.map((page)=>({
        url:page.finalUrl||page.url,
        title:page.title,
        unauthStatus:page.unauthStatus,
        authStatus:page.status
      })),
      endpoints:protectedEndpoints.slice(0,80)
    },
    endpointCoverage:endpointCoverage.slice(0,120),
    browser:{
      status:browser.status,
      available:browser.available,
      pages:(browser.pages||[]).map((page)=>({
        url:page.url,
        finalUrl:page.finalUrl,
        mode:page.mode,
        status:page.status,
        error:redact(page.error||'',auth),
        dom:page.dom,
        metrics:page.metrics,
        axeSummary:page.axe?.summary||null
      })),
      error:redact(browser.error||'',auth)
    },
    sourceScanId:sourceScan?.id||null,
    executiveSummary:`Authenticated Scan tested ${pages.length} page candidates and ${endpointCoverage.length} safe first-party API endpoints using an ephemeral ${auth.type} session. ${protectedPages.length} page(s) and ${protectedEndpoints.length} endpoint(s) were confirmed as session-protected. ${suspiciousPublic.length} endpoint(s) require owner validation because authenticated and public behavior overlapped. ${sessionEffectConfirmed?'The supplied session changed observable access on at least one route.':'Inspector could not confirm that the supplied session changed access, so post-login coverage should be treated as unverified.'}`
  };
}
