import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import tls from 'node:tls';
import * as cheerio from 'cheerio';
import { safeFetch, assertPublicTarget } from './net';
import { runBrowserChecks } from './browser';
import {
  crawlPages,
  discoverCommonSubdomains,
  extractApiHints,
  fingerprintTechnologies,
  inspectJavaScriptBundles,
  classifyEndpoint
} from './discovery';

function fingerprint(parts) {
  return crypto.createHash('sha256').update(parts.join('|')).digest('hex').slice(0,20);
}

export function finding(checkId, category, severity, title, summary, evidence, remediation, options={}) {
  const location=options.location||'';
  return {
    id:crypto.randomUUID(),
    fingerprint:fingerprint([checkId,location,title]),
    checkId,
    category,
    severity,
    title,
    summary,
    impact:options.impact||summary,
    evidence,
    remediation,
    confidence:options.confidence||'High',
    evidenceQuality:options.evidenceQuality||'observed',
    location,
    affectedLocations:options.affectedLocations||[location].filter(Boolean),
    engine:options.engine||'http',
    lifecycle:'new',
    workflowStatus:'open'
  };
}

const severityRank={Critical:5,High:4,Medium:3,Low:2,Informational:1};

export function scoreFindings(findings) {
  const weights={Critical:16,High:10,Medium:5,Low:1.5,Informational:0};
  const confidence={High:1,Medium:0.65,Low:0.35};
  const quality={validated:1,observed:0.8,heuristic:0.4};
  const groups=new Map();

  for(const item of findings){
    const prior=groups.get(item.checkId);
    if(!prior || severityRank[item.severity]>severityRank[prior.severity]) {
      groups.set(item.checkId,{...item,count:1});
    } else {
      prior.count += 1;
    }
  }

  let penalty=0;
  for(const item of groups.values()){
    const base=(weights[item.severity]||0)*(confidence[item.confidence]||0.5)*(quality[item.evidenceQuality]||0.6);
    const spread=Math.min(2,Math.max(0,(item.count-1)*0.35));
    penalty += base+spread;
  }

  return Math.max(0,Math.round(100-penalty));
}

function summarize(findings) {
  const out={critical:0,high:0,medium:0,low:0,informational:0};
  for(const item of findings){
    const key=item.severity.toLowerCase();
    if(key in out) out[key]+=1;
  }
  return out;
}

async function tlsInfo(url) {
  if(url.protocol!=='https:') return {enabled:false,status:'not_applicable'};
  await assertPublicTarget(url);
  return new Promise((resolve)=>{
    const socket=tls.connect({
      host:url.hostname,
      port:Number(url.port||443),
      servername:url.hostname,
      rejectUnauthorized:false,
      timeout:6000
    },()=>{
      const cert=socket.getPeerCertificate();
      const result={
        enabled:true,
        status:'complete',
        authorized:socket.authorized,
        authorizationError:socket.authorizationError||null,
        protocol:socket.getProtocol(),
        cipher:socket.getCipher()?.name||'',
        validFrom:cert?.valid_from||'',
        validTo:cert?.valid_to||'',
        issuer:cert?.issuer?.O||cert?.issuer?.CN||'',
        subject:cert?.subject?.CN||''
      };
      socket.end();
      resolve(result);
    });
    socket.on('timeout',()=>{socket.destroy();resolve({enabled:true,status:'degraded',error:'TLS timeout'});});
    socket.on('error',(error)=>resolve({enabled:true,status:'degraded',error:error.message}));
  });
}

async function dnsInfo(hostname) {
  const settled=await Promise.allSettled([
    dns.resolve4(hostname),
    dns.resolve6(hostname),
    dns.resolveMx(hostname),
    dns.resolveNs(hostname),
    dns.resolveTxt(hostname)
  ]);
  const value=(idx)=>settled[idx].status==='fulfilled'?settled[idx].value:[];
  return {
    status:'complete',
    a:value(0),
    aaaa:value(1),
    mx:value(2),
    ns:value(3),
    txt:value(4).flat?.()||value(4)
  };
}

function pageHeader(page,name) {
  return page.headers?.[name.toLowerCase()]||page.headers?.[name]||'';
}

function htmlPages(pages) {
  return pages.filter((p)=>p.html && p.status>=200 && p.status<400);
}

function aggregateSecurityHeaderFindings(pages, finalUrl, mainResponse) {
  const out=[];
  const sampled=htmlPages(pages);
  const add=(id,severity,title,summary,evidence,remediation,affected,extra={})=>{
    out.push(finding(id,'Security',severity,title,summary,evidence,remediation,{
      location:affected[0]||finalUrl.href,
      affectedLocations:affected,
      engine:'headers',
      evidenceQuality:'validated',
      ...extra
    }));
  };

  const missing=(name)=>sampled.filter((p)=>!pageHeader(p,name));
  const missingDirective=(name,pattern)=>sampled.filter((p)=>!pattern.test(pageHeader(p,name)||''));
  const listEvidence=(affected,label)=>[
    label,
    'Affected sampled pages: '+affected.length+'/'+sampled.length,
    ...affected.slice(0,10)
  ].join('\n');

  if(finalUrl.protocol==='https:'){
    const affected=missing('strict-transport-security').map((p)=>p.url);
    if(affected.length){
      add('SEC-HSTS','Medium','HSTS missing on sampled HTTPS responses',
        `Strict-Transport-Security was absent on ${affected.length} of ${sampled.length} sampled HTML responses.`,
        listEvidence(affected,'Strict-Transport-Security: absent'),
        'Enable HSTS after confirming HTTPS coverage for the intended hostnames.',affected);
    }
  }

  {
    const affected=missing('content-security-policy').map((p)=>p.url);
    if(affected.length){
      const sensitive=sampled.some((p)=>{
        const $=cheerio.load(p.html);
        return $('input[type="password"]').length>0 || $('form').length>0;
      });
      add('SEC-CSP',sensitive?'High':'Medium','Content Security Policy missing across sampled pages',
        `CSP was absent on ${affected.length} of ${sampled.length} sampled HTML responses${sensitive?' including pages containing forms':''}.`,
        listEvidence(affected,'Content-Security-Policy: absent'),
        'Deploy a restrictive CSP and test it in report-only mode before enforcement.',affected);
    }
  }

  {
    const affected=sampled.filter((p)=>{
      const csp=pageHeader(p,'content-security-policy');
      return !pageHeader(p,'x-frame-options') && !/frame-ancestors/i.test(csp);
    }).map((p)=>p.url);
    if(affected.length){
      add('SEC-FRAME','Medium','Framing protection missing on sampled pages',
        `${affected.length} sampled pages do not declare X-Frame-Options or CSP frame-ancestors.`,
        listEvidence(affected,'No framing restriction observed'),
        'Set CSP frame-ancestors to the origins that are allowed to embed the application.',affected);
    }
  }

  {
    const affected=sampled.filter((p)=>(pageHeader(p,'x-content-type-options')||'').toLowerCase()!=='nosniff').map((p)=>p.url);
    if(affected.length){
      add('SEC-NOSNIFF','Low','MIME sniffing protection missing',
        `X-Content-Type-Options: nosniff was missing on ${affected.length} sampled pages.`,
        listEvidence(affected,'X-Content-Type-Options: nosniff not observed'),
        'Return X-Content-Type-Options: nosniff on HTML and static responses.',affected);
    }
  }

  {
    const affected=missing('referrer-policy').map((p)=>p.url);
    if(affected.length){
      add('SEC-REFERRER','Low','Referrer policy is not explicit',
        `No Referrer-Policy header was observed on ${affected.length} sampled pages.`,
        listEvidence(affected,'Referrer-Policy: absent'),
        'Set an explicit policy such as strict-origin-when-cross-origin or stricter.',affected);
    }
  }

  {
    const affected=missing('permissions-policy').map((p)=>p.url);
    if(affected.length){
      add('SEC-PERMISSIONS','Informational','Permissions Policy is not explicit',
        `No Permissions-Policy header was observed on ${affected.length} sampled pages.`,
        listEvidence(affected,'Permissions-Policy: absent'),
        'Define only the browser capabilities the application actually requires.',affected,{confidence:'Medium',evidenceQuality:'observed'});
    }
  }

  const server=mainResponse.headers.get('server');
  const powered=mainResponse.headers.get('x-powered-by');
  if(server||powered){
    out.push(finding('SEC-BANNER','Security','Informational','Server or framework banner is exposed',
      'The entry response reveals platform information that can aid technology fingerprinting.',
      `server: ${server||'(not set)'}\nx-powered-by: ${powered||'(not set)'}`,
      'Suppress unnecessary server and framework banners where practical.',
      {location:finalUrl.href,engine:'headers',confidence:'High',evidenceQuality:'observed'}));
  }

  const setCookies=typeof mainResponse.headers.getSetCookie==='function'?mainResponse.headers.getSetCookie():[];
  for(const cookie of setCookies.slice(0,12)){
    const name=(cookie.split('=')[0]||'cookie').trim();
    const looksSession=/session|auth|token|jwt|sid/i.test(name);
    if(finalUrl.protocol==='https:' && !/;\s*secure\b/i.test(cookie)){
      out.push(finding('SEC-COOKIE-SECURE','Security',looksSession?'High':'Medium',`Cookie "${name}" is missing Secure`,
        'A cookie issued over HTTPS is not marked Secure.',
        `Cookie name: ${name}\nSecure attribute: absent`,
        'Mark cookies that should never travel over plaintext HTTP as Secure.',
        {location:finalUrl.href+'#cookie:'+name,engine:'headers',evidenceQuality:'validated'}));
    }
    if(looksSession && !/;\s*httponly\b/i.test(cookie)){
      out.push(finding('SEC-COOKIE-HTTPONLY','Security','Medium',`Session-like cookie "${name}" is missing HttpOnly`,
        'A session-like cookie appears readable by client-side JavaScript.',
        `Cookie name: ${name}\nHttpOnly attribute: absent`,
        'Use HttpOnly for session/authentication cookies that do not require JavaScript access.',
        {location:finalUrl.href+'#cookie:'+name,engine:'headers',evidenceQuality:'validated'}));
    }
    if(looksSession && !/;\s*samesite=/i.test(cookie)){
      out.push(finding('SEC-COOKIE-SAMESITE','Security','Low',`Session-like cookie "${name}" has no SameSite attribute`,
        'No SameSite attribute was observed on a session-like cookie.',
        `Cookie name: ${name}\nSameSite attribute: absent`,
        'Set an appropriate SameSite policy based on cross-site requirements.',
        {location:finalUrl.href+'#cookie:'+name,engine:'headers',confidence:'Medium',evidenceQuality:'observed'}));
    }
  }

  const mixed=[];
  const insecureForms=[];
  for(const page of sampled){
    const $=cheerio.load(page.html);
    $('[src],[href]').each((_,el)=>{
      const value=$(el).attr('src')||$(el).attr('href');
      if(finalUrl.protocol==='https:' && value?.startsWith('http://') && mixed.length<30) mixed.push({page:page.url,resource:value});
    });
    $('form').each((idx,el)=>{
      const action=$(el).attr('action');
      if(!action) return;
      try{
        const resolved=new URL(action,page.url);
        if(finalUrl.protocol==='https:'&&resolved.protocol==='http:') insecureForms.push({page:page.url,action:resolved.href,index:idx});
      }catch{}
    });
  }

  if(mixed.length){
    out.push(finding('SEC-MIXED','Security','Medium','HTTPS pages reference insecure HTTP resources',
      `${mixed.length} insecure resource references were observed across the sampled application.`,
      mixed.slice(0,15).map((x)=>x.page+' -> '+x.resource).join('\n'),
      'Serve all page resources over HTTPS and update hard-coded HTTP references.',
      {location:mixed[0].page,affectedLocations:[...new Set(mixed.map((x)=>x.page))],engine:'crawler',evidenceQuality:'validated'}));
  }

  if(insecureForms.length){
    out.push(finding('SEC-INSECURE-FORM','Security','High','Forms submit from HTTPS to HTTP',
      `${insecureForms.length} forms submit to plaintext HTTP destinations.`,
      insecureForms.slice(0,12).map((x)=>x.page+' -> '+x.action).join('\n'),
      'Submit forms only to HTTPS endpoints.',
      {location:insecureForms[0].page,affectedLocations:[...new Set(insecureForms.map((x)=>x.page))],engine:'crawler',evidenceQuality:'validated'}));
  }

  return out;
}

async function corsFindings(url) {
  try{
    const response=await safeFetch(url.href,{
      method:'GET',
      headers:{origin:'https://inspector.invalid',accept:'text/html,*/*'}
    },6500);
    const allowOrigin=response.headers.get('access-control-allow-origin');
    const allowCreds=(response.headers.get('access-control-allow-credentials')||'').toLowerCase()==='true';

    if(allowOrigin==='https://inspector.invalid' && allowCreds){
      return [finding('SEC-CORS-REFLECT','Security','High','Credentialed CORS reflects an arbitrary origin',
        'The application reflected the scanner-controlled Origin value and also allowed credentials.',
        `Sent Origin: https://inspector.invalid\nAccess-Control-Allow-Origin: ${allowOrigin}\nAccess-Control-Allow-Credentials: true`,
        'Validate Origin against a strict allowlist before reflecting it and only enable credentials where required.',
        {location:url.href,engine:'cors',evidenceQuality:'validated'})];
    }

    if(allowOrigin==='*' && allowCreds){
      return [finding('SEC-CORS-INCONSISTENT','Security','Low','CORS combines wildcard origin with credentials',
        'The response advertises a wildcard origin and credential support. Browsers will not expose credentialed responses with this combination, but it indicates inconsistent CORS configuration.',
        'Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true',
        'Use an explicit origin allowlist when credentials are required.',
        {location:url.href,engine:'cors',evidenceQuality:'validated'})];
    }
  }catch{}
  return [];
}

function softSignature(text) {
  return crypto.createHash('sha1').update(String(text||'').replace(/[a-f0-9]{16,}/gi,'X').replace(/\s+/g,' ').slice(0,12000)).digest('hex');
}

async function publicEndpointFindings(url) {
  const out=[];
  const controlUrl=new URL('/__inspector_not_found_'+crypto.randomUUID()+'.txt',url);
  let control={status:0,signature:null};

  try{
    const res=await safeFetch(controlUrl.href,{method:'GET',headers:{accept:'text/plain,text/html,application/json,*/*'}},3500);
    const body=(await res.text()).slice(0,180000);
    control={status:res.status,signature:softSignature(body)};
  }catch{}

  const probes=[
    {
      path:'/.env',id:'SEC-EXPOSED-ENV',title:'Environment configuration appears publicly exposed',severity:'High',
      validate:(body)=> {
        const keys=[...body.matchAll(/^\s*([A-Z][A-Z0-9_]{2,})\s*=.*$/gm)].map((m)=>m[1]);
        const sensitive=keys.filter((k)=>/KEY|SECRET|TOKEN|PASSWORD|DATABASE|DB_|AWS_|STRIPE|AUTH/i.test(k));
        return keys.length>=2?{valid:true,evidence:'Environment-style keys observed: '+keys.slice(0,12).join(', ')+(sensitive.length?'\nSensitive key names observed: '+sensitive.slice(0,8).join(', '):'')}:null;
      }
    },
    {
      path:'/.git/HEAD',id:'SEC-EXPOSED-GIT',title:'Git metadata is publicly exposed',severity:'High',
      validate:(body)=>/^ref:\s+refs\/heads\//m.test(body)?{valid:true,evidence:'Response matched a Git HEAD ref (ref: refs/heads/...)'}:null
    },
    {
      path:'/server-status',id:'SEC-SERVER-STATUS',title:'Apache server-status is public',severity:'Medium',
      validate:(body)=>/Apache Server Status|Server Version: Apache/i.test(body)?{valid:true,evidence:'Response matched Apache server-status markers.'}:null
    },
    {
      path:'/phpinfo.php',id:'SEC-PHPINFO',title:'phpinfo output is public',severity:'High',
      validate:(body)=>/phpinfo\(\)|PHP Version\s*<\/td>/i.test(body)?{valid:true,evidence:'Response matched phpinfo output markers.'}:null
    },
    {
      path:'/openapi.json',id:'INFO-OPENAPI',title:'OpenAPI specification is publicly available',severity:'Informational',
      validate:(body)=>{
        try{const j=JSON.parse(body);return (j.openapi||j.swagger)?{valid:true,evidence:'Valid API specification marker: '+(j.openapi?'openapi '+j.openapi:'swagger '+j.swagger)}:null;}catch{return null;}
      }
    },
    {
      path:'/swagger.json',id:'INFO-SWAGGER',title:'Swagger specification is publicly available',severity:'Informational',
      validate:(body)=>{
        try{const j=JSON.parse(body);return (j.openapi||j.swagger)?{valid:true,evidence:'Valid API specification marker: '+(j.openapi?'openapi '+j.openapi:'swagger '+j.swagger)}:null;}catch{return null;}
      }
    }
  ];

  for(const probe of probes){
    try{
      const target=new URL(probe.path,url);
      const response=await safeFetch(target.href,{method:'GET',headers:{accept:'text/plain,text/html,application/json,*/*'}},4000);
      if(!(response.status>=200&&response.status<300)) continue;
      const body=(await response.text()).slice(0,220000);
      if(control.status>=200&&control.status<300 && softSignature(body)===control.signature) continue;
      const validation=probe.validate(body,response);
      if(!validation?.valid) continue;

      out.push(finding(probe.id,probe.id.startsWith('INFO-')?'Discovery':'Security',probe.severity,probe.title,
        `${probe.path} returned a response whose content matched the expected signature for this endpoint.`,
        `HTTP ${response.status}\nContent-Type: ${response.headers.get('content-type')||'unknown'}\n${validation.evidence}`,
        probe.id.startsWith('INFO-')?'Confirm that publishing the API specification is intentional.':'Remove public access or restrict the endpoint to trusted administrators.',
        {location:target.href,engine:'validated-probe',evidenceQuality:'validated'}));
    }catch{}
  }

  return out;
}

async function linkChecks(pageUrls) {
  const results=[];
  for(const href of pageUrls.slice(0,20)){
    try{
      const response=await safeFetch(href,{method:'GET',headers:{accept:'text/html,*/*'}},4200);
      results.push({href,status:response.status,finalUrl:response.url||href});
    }catch(error){
      results.push({href,status:0,error:String(error?.message||error).slice(0,160)});
    }
  }
  return results;
}

function aggregateAxeFindings(browser) {
  const groups=new Map();
  for(const violation of browser.accessibility?.violations||[]){
    const key=violation.id;
    if(!groups.has(key)) groups.set(key,{...violation,pages:new Set(),nodes:[]});
    const group=groups.get(key);
    group.pages.add(violation.pageUrl);
    for(const node of violation.nodes||[]) if(group.nodes.length<16) group.nodes.push({...node,pageUrl:violation.pageUrl});
  }

  const out=[];
  const severityFor=(impact)=>impact==='critical'?'High':impact==='serious'?'Medium':impact==='moderate'?'Low':'Informational';

  for(const group of groups.values()){
    const pages=[...group.pages];
    out.push(finding('A11Y-'+group.id.toUpperCase(),'Accessibility',severityFor(group.impact),
      group.help||('Accessibility rule '+group.id+' failed'),
      `${group.nodes.length} sampled elements across ${pages.length} browser-rendered page(s) failed axe rule "${group.id}".`,
      [
        'axe rule: '+group.id,
        'impact: '+group.impact,
        'affected pages: '+pages.length,
        ...pages.slice(0,8),
        ...group.nodes.slice(0,8).map((n)=>'selector: '+(Array.isArray(n.target)?n.target.join(' '):String(n.target||''))+' | '+n.failureSummary)
      ].join('\n').slice(0,6000),
      'Follow the axe rule guidance and retest the affected rendered elements.',
      {location:pages[0]||'',affectedLocations:pages,engine:'axe',evidenceQuality:'validated',confidence:'High'}));
  }

  return out;
}

function browserFindings(browser, finalUrl) {
  const out=[];
  if(!browser.available){
    out.push(finding('SCAN-BROWSER-DEGRADED','Scan Health','Informational','Browser QA engine did not complete',
      'HTTP, TLS, DNS and crawler checks may have completed, but Chromium could not produce reliable rendered-page evidence.',
      browser.error||'No browser-rendered page completed.',
      'Retry the scan. Treat browser, accessibility and dynamic API coverage as unavailable until this engine succeeds.',
      {location:finalUrl.href,engine:'browser',evidenceQuality:'observed'}));
    return out;
  }

  out.push(...aggregateAxeFindings(browser));

  const axeIds=new Set((browser.accessibility?.violations||[]).map((v)=>v.id));
  const rendered=(browser.pages||[]).filter((p)=>!p.error);
  const desktopRendered=rendered.filter((p)=>p.mode==='desktop');

  const aggregateDom=(key)=>desktopRendered.reduce((sum,p)=>sum+Number(p.dom?.[key]||0),0);
  const affectedFor=(key)=>desktopRendered.filter((p)=>Number(p.dom?.[key]||0)>0).map((p)=>p.finalUrl||p.url);

  const unlabeled=aggregateDom('unlabeledInputs');
  if(unlabeled>0 && !axeIds.has('label') && !axeIds.has('aria-input-field-name')){
    const pages=affectedFor('unlabeledInputs');
    out.push(finding('QA-INPUT-LABELS','Accessibility','Medium','Visible form controls lack accessible labels',
      `${unlabeled} visible input/select/textarea control(s) lacked a programmatic label across ${pages.length} rendered desktop page(s).`,
      desktopRendered.filter((p)=>Number(p.dom?.unlabeledInputs||0)>0).map((p)=>`${p.finalUrl||p.url}: ${p.dom.unlabeledInputs} unlabeled control(s)`).join('\n'),
      'Associate each visible form control with a label, aria-label or aria-labelledby.',
      {location:pages[0]||finalUrl.href,affectedLocations:pages,engine:'browser-dom',confidence:'High',evidenceQuality:'validated'}));
  }

  const missingAlt=aggregateDom('missingAlt');
  if(missingAlt>0 && !axeIds.has('image-alt')){
    const pages=affectedFor('missingAlt');
    out.push(finding('QA-IMG-ALT','Accessibility','Medium','Rendered images are missing alt attributes',
      `${missingAlt} image(s) had no alt attribute across ${pages.length} rendered desktop page(s).`,
      desktopRendered.filter((p)=>Number(p.dom?.missingAlt||0)>0).map((p)=>`${p.finalUrl||p.url}: ${p.dom.missingAlt} image(s) missing alt`).join('\n'),
      'Add meaningful alt text for informative images and empty alt attributes for decorative images.',
      {location:pages[0]||finalUrl.href,affectedLocations:pages,engine:'browser-dom',confidence:'High',evidenceQuality:'validated'}));
  }

  const duplicateIds=aggregateDom('duplicateIds');
  if(duplicateIds>0 && !axeIds.has('duplicate-id') && !axeIds.has('duplicate-id-active') && !axeIds.has('duplicate-id-aria')){
    const pages=affectedFor('duplicateIds');
    out.push(finding('QA-DUPLICATE-ID','Accessibility','Low','Duplicate element IDs occur in rendered DOM',
      `${duplicateIds} duplicate id occurrence(s) were observed across ${pages.length} rendered desktop page(s).`,
      desktopRendered.filter((p)=>Number(p.dom?.duplicateIds||0)>0).map((p)=>`${p.finalUrl||p.url}: ${p.dom.duplicateIds} duplicate id occurrence(s)`).join('\n'),
      'Ensure element IDs are unique within each rendered document.',
      {location:pages[0]||finalUrl.href,affectedLocations:pages,engine:'browser-dom',confidence:'High',evidenceQuality:'validated'}));
  }

  const pageErrors=browser.pageErrors||[];
  if(pageErrors.length){
    const pages=[...new Set(pageErrors.map((x)=>x.url))];
    out.push(finding('QA-PAGE-ERROR','Quality','High','Unhandled JavaScript errors occur during page load',
      `${pageErrors.length} unhandled page errors were observed across ${pages.length} rendered page(s).`,
      pageErrors.slice(0,12).map((x)=>x.url+'\n'+x.message).join('\n---\n'),
      'Fix the underlying runtime exceptions and add appropriate error boundaries/monitoring.',
      {location:pages[0],affectedLocations:pages,engine:'browser',evidenceQuality:'validated'}));
  }

  const consoleErrors=browser.consoleErrors||[];
  if(consoleErrors.length){
    const pages=[...new Set(consoleErrors.map((x)=>x.url))];
    out.push(finding('QA-CONSOLE','Quality','Low','Console errors occur in rendered pages',
      `${consoleErrors.length} console error messages were observed across ${pages.length} rendered page(s).`,
      consoleErrors.slice(0,15).map((x)=>x.url+'\n'+x.message).join('\n---\n'),
      'Remove production console errors and resolve the underlying client-side failures.',
      {location:pages[0],affectedLocations:pages,engine:'browser',confidence:'Medium',evidenceQuality:'observed'}));
  }

  const noiseHosts = ['google.com','google-analytics.com','googletagmanager.com','doubleclick.net','googleadservices.com','facebook.com','hotjar.com','clarity.ms','visualwebsiteoptimizer.com','segment.io','segment.com','amplitude.com','mixpanel.com'];
  const noisePathPatterns = ['/nm7sjdp/','/collect','/measurement/','/g/collect','/ccm/','/rmkt/','tid=g-','gtm=','googleadservices','doubleclick'];
  const importantFailures=(browser.failedRequests||[]).filter((x)=>{
    if (!(x.resourceType==='xhr'||x.resourceType==='fetch'||/script|document|stylesheet/.test(x.resourceType||''))) return false;
    try {
      const parsed=new URL(x.url);
      const host=parsed.hostname.toLowerCase();
      const signature=(parsed.pathname+parsed.search).toLowerCase();
      if (noiseHosts.some((noise)=>host===noise||host.endsWith('.'+noise))) return false;
      if (noisePathPatterns.some((pattern)=>signature.includes(pattern))) return false;
    } catch {}
    return true;
  });
  if(importantFailures.length){
    const pages=[...new Set((browser.pages||[]).filter((p)=>p.failedRequests?.length).map((p)=>p.finalUrl||p.url))];
    out.push(finding('QA-REQUEST-FAIL','Quality','Medium','Important browser requests fail',
      `${importantFailures.length} XHR/fetch/document/script/stylesheet requests failed during rendered-page testing.`,
      importantFailures.slice(0,18).map((x)=>x.method+' '+x.url+' — '+x.error).join('\n'),
      'Review deployment paths, API availability, CORS and third-party dependencies for the failed requests.',
      {location:pages[0]||finalUrl.href,affectedLocations:pages,engine:'browser',evidenceQuality:'validated'}));
  }

  const mobileOverflow=(browser.pages||[]).filter((p)=>p.mode==='mobile'&&!p.error&&p.dom?.horizontalOverflow);
  if(mobileOverflow.length){
    const pages=mobileOverflow.map((p)=>p.finalUrl||p.url);
    out.push(finding('QA-MOBILE-OVERFLOW','Quality','Medium','Horizontal overflow occurs on mobile viewport',
      `${pages.length} mobile-rendered page(s) are wider than the 390px viewport.`,
      mobileOverflow.map((p)=>`${p.finalUrl||p.url}: document ${p.dom.documentWidth}px vs viewport ${p.dom.viewportWidth}px`).join('\n'),
      'Identify fixed-width/overflowing elements and correct responsive breakpoints.',
      {location:pages[0],affectedLocations:pages,engine:'browser-mobile',evidenceQuality:'validated'}));
  }

  const lcp=browser.metrics?.lcpMs;
  if(lcp&&lcp>4000){
    out.push(finding('PERF-LCP','Performance','Medium','Largest Contentful Paint is slow',
      `The entry page reported an LCP of about ${lcp} ms in the scanner environment.`,
      `LCP: ${lcp} ms\nFCP: ${browser.metrics?.fcpMs||'n/a'} ms\nLoad: ${browser.metrics?.loadMs||'n/a'} ms`,
      'Optimize the largest above-the-fold content, image delivery, render-blocking resources and server response time.',
      {location:finalUrl.href,engine:'browser-performance',confidence:'Medium',evidenceQuality:'observed'}));
  }

  const cls=Number(browser.metrics?.cls||0);
  if(cls>0.25){
    out.push(finding('PERF-CLS','Performance','Medium','Layout shift is high during page load',
      `The entry page reported a cumulative layout shift of approximately ${cls.toFixed(3)}.`,
      'CLS: '+cls.toFixed(3),
      'Reserve layout space for dynamic content and images, and avoid inserting content above existing content.',
      {location:finalUrl.href,engine:'browser-performance',confidence:'Medium',evidenceQuality:'observed'}));
  }

  return out;
}

function crawlQualityFindings(pages) {
  const out=[];
  const sampled=htmlPages(pages);

  const aggregate=(id,severity,title,predicate,summaryText,evidenceLabel,remediation)=>{
    const affected=sampled.filter(predicate).map((p)=>p.url);
    if(!affected.length) return;
    out.push(finding(id,'Quality',severity,title,
      `${affected.length} of ${sampled.length} crawled HTML pages ${summaryText}.`,
      [evidenceLabel,...affected.slice(0,12)].join('\n'),
      remediation,
      {location:affected[0],affectedLocations:affected,engine:'crawler',evidenceQuality:'validated'}));
  };

  aggregate('QA-TITLE','Low','Pages are missing document titles',
    (p)=>!cheerio.load(p.html)('title').text().trim(),
    'have no non-empty document title','Affected pages:',
    'Add a concise, page-specific title to every indexable page.');

  aggregate('QA-LANG','Low','Pages do not declare a document language',
    (p)=>!cheerio.load(p.html)('html').attr('lang'),
    'have no html lang attribute','Affected pages:',
    'Declare the primary document language on the html element.');

  aggregate('QA-VIEWPORT','Low','Responsive viewport metadata is missing',
    (p)=>!cheerio.load(p.html)('meta[name="viewport"]').length,
    'do not declare viewport metadata','Affected pages:',
    'Add width=device-width, initial-scale=1 on responsive pages.');

  const titleMap=new Map();
  for(const p of sampled){
    const title=cheerio.load(p.html)('title').text().trim();
    if(!title) continue;
    if(!titleMap.has(title)) titleMap.set(title,[]);
    titleMap.get(title).push(p.url);
  }
  const duplicate=[...titleMap.entries()].filter(([,urls])=>urls.length>1);
  if(duplicate.length){
    const affected=[...new Set(duplicate.flatMap(([,urls])=>urls))];
    out.push(finding('QA-DUPLICATE-TITLE','Quality','Low','Multiple crawled pages share the same title',
      `${affected.length} pages share document titles with another crawled page.`,
      duplicate.slice(0,8).map(([title,urls])=>`"${title}"\n${urls.slice(0,5).join('\n')}`).join('\n---\n'),
      'Use page-specific titles that accurately describe each route.',
      {location:affected[0],affectedLocations:affected,engine:'crawler',evidenceQuality:'validated'}));
  }

  return out;
}

function applyLifecycle(findings,previous) {
  const old=new Map((previous?.findings||[]).map((item)=>[item.fingerprint,item]));
  for(const item of findings){
    const prior=old.get(item.fingerprint);
    item.lifecycle=prior?'open':'new';
    item.workflowStatus=prior?.workflowStatus||'open';
  }
  const current=new Set(findings.map((item)=>item.fingerprint));
  const resolved=(previous?.findings||[])
    .filter((item)=>!current.has(item.fingerprint))
    .map((item)=>({...item,lifecycle:'resolved',resolvedAt:new Date().toISOString()}));
  return {findings,resolved};
}

function engineState(status,details={}) {
  return {status,...details};
}

export async function runFullScan({url,previousScan=null}) {
  const startedAt=new Date().toISOString();
  const target=new URL(url);
  await assertPublicTarget(target);

  const main=await safeFetch(target.href,{method:'GET',headers:{accept:'text/html,application/xhtml+xml'}},12000);
  const contentType=main.headers.get('content-type')||'';
  if(!contentType.includes('text/html')) throw new Error(`Target did not return HTML (${contentType||'unknown'}).`);
  const html=(await main.text()).slice(0,2500000);
  const finalUrl=new URL(main.url||target.href);
  const firstHeaders=Object.fromEntries(main.headers.entries());

  const [tls,dnsData,cors,probes,crawlResult,commonSubdomains]=await Promise.all([
    tlsInfo(finalUrl),
    dnsInfo(finalUrl.hostname).catch((error)=>({status:'degraded',a:[],aaaa:[],mx:[],ns:[],txt:[],error:String(error?.message||error)})),
    corsFindings(finalUrl),
    publicEndpointFindings(finalUrl),
    crawlPages(finalUrl.href,html,firstHeaders,18),
    discoverCommonSubdomains(finalUrl.hostname)
  ]);

  const pages=crawlResult.pages;
  const browserTargets=pages.filter((p)=>p.html&&p.status>=200&&p.status<400).map((p)=>p.url).slice(0,4);

  const [browser,jsInspection,links]=await Promise.all([
    runBrowserChecks(finalUrl.href,browserTargets),
    inspectJavaScriptBundles(pages,6),
    linkChecks(pages.filter((p)=>p.source!=='entry').map((p)=>p.url))
  ]);

  const technologies=fingerprintTechnologies(main.headers,html);
  const markupApi=[...new Set(pages.flatMap((page)=>page.html?extractApiHints(page.url,page.html):[]))];
  const browserRequests=(browser.apiRequests||[]).map((item)=>{
    try{
      const u=new URL(item.url);
      return classifyEndpoint({
        method:item.method,
        path:u.pathname+u.search,
        host:u.hostname,
        source:'browser'
      }, finalUrl.hostname);
    }catch{return null;}
  }).filter(Boolean);

  const dynamicApi=browserRequests.filter((item)=>item.host===finalUrl.hostname);
  const apiMap=new Map();
  for(const path of [...markupApi,...jsInspection.apiHints]){
    const item=classifyEndpoint({method:'OBSERVE',path,host:finalUrl.hostname,source:jsInspection.apiHints.includes(path)?'javascript':'markup'},finalUrl.hostname);
    apiMap.set(item.method+' '+item.path,item);
  }
  for(const item of dynamicApi) apiMap.set(item.method+' '+item.path,item);
  const apiEndpoints=[...apiMap.values()].slice(0,200);
  const thirdPartyApiHosts=[...new Set(browserRequests.filter((item)=>item.host!==finalUrl.hostname).map((item)=>item.host))].slice(0,50);

  let findings=[
    ...aggregateSecurityHeaderFindings(pages,finalUrl,main),
    ...cors,
    ...probes,
    ...browserFindings(browser,finalUrl),
    ...crawlQualityFindings(pages)
  ];

  if(tls.enabled){
    if(tls.error||!tls.authorized){
      findings.push(finding('TLS-TRUST','Security','High','TLS certificate validation failed',
        'The HTTPS certificate could not be validated by the scanner.',
        `${tls.error||tls.authorizationError||'Certificate not trusted'}\nProtocol: ${tls.protocol||'unknown'}`,
        'Install a valid publicly trusted certificate and complete the certificate chain.',
        {location:finalUrl.origin,engine:'tls',evidenceQuality:'validated'}));
    }

    if(tls.validTo){
      const days=Math.ceil((new Date(tls.validTo).getTime()-Date.now())/86400000);
      if(days<21){
        findings.push(finding('TLS-EXPIRY','Security',days<7?'High':'Medium','TLS certificate expires soon',
          `The certificate expires in about ${days} days.`,
          `Valid to: ${tls.validTo}\nIssuer: ${tls.issuer||'unknown'}\nProtocol: ${tls.protocol||'unknown'}`,
          'Renew and deploy the certificate before expiry.',
          {location:finalUrl.origin,engine:'tls',evidenceQuality:'validated'}));
      }
    }

    if(tls.protocol && /TLSv1(?:\.0|\.1)?$/.test(tls.protocol)){
      findings.push(finding('TLS-LEGACY','Security','High','Legacy TLS protocol negotiated',
        `The scanner negotiated ${tls.protocol}, which should no longer be accepted for modern public applications.`,
        'Negotiated protocol: '+tls.protocol,
        'Disable legacy TLS versions and require TLS 1.2 or newer.',
        {location:finalUrl.origin,engine:'tls',evidenceQuality:'validated'}));
    }
  }

  const broken=links.filter((item)=>item.status===0||item.status>=400);
  if(broken.length){
    findings.push(finding('QA-BROKEN-LINKS','Quality','Medium','Crawled internal pages fail to load',
      `${broken.length} of ${links.length} sampled internal page URLs returned an error.`,
      broken.slice(0,15).map((x)=>`${x.status||'ERR'} ${x.href}${x.error?' — '+x.error:''}`).join('\n'),
      'Fix, redirect or remove the failing internal URLs and retest the affected navigation.',
      {location:broken[0].href,affectedLocations:broken.map((x)=>x.href),engine:'crawler',evidenceQuality:'validated'}));
  }

  if(jsInspection.sourceMaps.length){
    findings.push(finding('DISCOVERY-SOURCEMAP','Discovery','Informational','Production JavaScript source maps are publicly available',
      `${jsInspection.sourceMaps.length} source map file(s) were confirmed as valid and publicly retrievable.`,
      jsInspection.sourceMaps.slice(0,10).map((x)=>x.url).join('\n'),
      'Confirm this is intentional. If source maps expose proprietary source or internal paths, restrict their public deployment.',
      {location:jsInspection.sourceMaps[0].url,affectedLocations:jsInspection.sourceMaps.map((x)=>x.url),engine:'javascript',evidenceQuality:'validated'}));
  }

  const lifecycle=applyLifecycle(findings,previousScan);
  findings=lifecycle.findings;
  const summary=summarize(findings);
  const score=scoreFindings(findings);

  const priorities=[...findings]
    .filter((item)=>['Critical','High','Medium'].includes(item.severity))
    .sort((a,b)=>severityRank[b.severity]-severityRank[a.severity])
    .slice(0,7)
    .map((item)=>({title:item.title,severity:item.severity,checkId:item.checkId,affected:item.affectedLocations?.length||1}));

  const crawlErrors=pages.filter((p)=>p.status===0).length;
  const axeFailed=browser.pages?.filter((p)=>p.mode==='desktop'&&p.axe?.error).length||0;
  const engineStatus={
    crawler:engineState(pages.length>1?'complete':'degraded',{pagesDiscovered:pages.length,errors:crawlErrors,robots:Boolean(crawlResult.discovery?.robots),sitemapPages:crawlResult.discovery?.sitemapPages?.length||0}),
    browser:engineState(browser.status||'failed',{pagesTested:browser.metrics?.pagesTested||0,desktopPages:browser.metrics?.desktopPages||0,mobilePages:browser.metrics?.mobilePages||0}),
    accessibility:engineState(browser.available?(axeFailed>0?'degraded':'complete'):'failed',{violations:browser.accessibility?.violations?.length||0,axeFailures:axeFailed}),
    security:engineState('complete',{validatedProbes:probes.length,headerPages:htmlPages(pages).length,corsChecks:1}),
    tls:engineState(tls.enabled?(tls.status||'complete'):'not_applicable',{protocol:tls.protocol||null}),
    dns:engineState(dnsData.status||'complete',{records:(dnsData.a?.length||0)+(dnsData.aaaa?.length||0)+(dnsData.mx?.length||0)+(dnsData.ns?.length||0)}),
    javascript:engineState(jsInspection.bundles.length?'complete':'degraded',{bundlesInspected:jsInspection.bundles.length,sourceMaps:jsInspection.sourceMaps.length}),
    apiDiscovery:engineState(apiEndpoints.length?'complete':'degraded',{endpoints:apiEndpoints.length,dynamicRequests:dynamicApi.length})
  };

  const coreFailures=['browser','security','crawler'].filter((key)=>engineStatus[key].status==='failed');
  const coverageGaps=Object.entries(engineStatus).filter(([,value])=>value.status==='degraded'||value.status==='failed').map(([key])=>key);
  const status=coreFailures.length?'partial':coverageGaps.length?'completed_with_gaps':'completed';

  return {
    id:crypto.randomUUID(),
    url:target.href,
    finalUrl:finalUrl.href,
    host:finalUrl.hostname,
    startedAt,
    completedAt:new Date().toISOString(),
    status,
    httpStatus:main.status,
    score,
    summary,
    findings,
    resolvedFindings:lifecycle.resolved,
    priorities,
    engineStatus,
    coverageGaps,
    scoreConfidence: coverageGaps.length ? (coreFailures.length ? 'low' : 'medium') : 'high',
    metrics:{
      pagesCrawled:pages.filter((p)=>p.html).length,
      pagesDiscovered:pages.length,
      sitemapPages:crawlResult.discovery?.sitemapPages?.length||0,
      linksChecked:links.length,
      browserAvailable:browser.available,
      browserPages:browser.metrics?.pagesTested||0,
      browserDesktopPages:browser.metrics?.desktopPages||0,
      browserMobilePages:browser.metrics?.mobilePages||0,
      browserLoadMs:browser.metrics?.loadMs||null,
      browserLcpMs:browser.metrics?.lcpMs||null,
      browserCls:browser.metrics?.cls||0,
      resourceCount:browser.metrics?.resourceCount||0,
      transferBytes:browser.metrics?.transferBytes||0,
      consoleErrors:browser.consoleErrors?.length||0,
      failedRequests:browser.failedRequests?.length||0,
      accessibilityViolations:browser.accessibility?.violations?.length||0,
      accessibilityNodes:browser.accessibility?.summary?.nodes||0,
      dnsRecords:(dnsData.a?.length||0)+(dnsData.aaaa?.length||0)+(dnsData.mx?.length||0)+(dnsData.ns?.length||0),
      tlsProtocol:tls.protocol||null,
      apiEndpoints:apiEndpoints.length,
      dynamicApiRequests:dynamicApi.length,
      thirdPartyApiHosts:thirdPartyApiHosts.length,
      technologies:technologies.length,
      subdomains:commonSubdomains.length,
      jsBundles:jsInspection.bundles.length,
      sourceMaps:jsInspection.sourceMaps.length
    },
    evidence:{
      tls,
      dns:dnsData,
      scanHealth:engineStatus,
      inventory:{
        technologies,
        apiEndpoints,
        thirdPartyApiHosts,
        browserRequests: browserRequests.slice(0,200),
        commonSubdomains,
        robots:crawlResult.discovery?.robots||null,
        sitemapUrls:crawlResult.discovery?.sitemapUrls||[],
        sitemapPages:crawlResult.discovery?.sitemapPages?.slice(0,100)||[],
        pages:pages.map((page)=>({
          url:page.url,
          status:page.status,
          source:page.source,
          title:page.title,
          bytes:page.bytes,
          error:page.error||null
        })),
        javascript:jsInspection
      },
      browser:{
        available:browser.available,
        status:browser.status,
        finalUrl:browser.finalUrl,
        pages:(browser.pages||[]).map((p)=>({
          url:p.url,
          finalUrl:p.finalUrl,
          mode:p.mode,
          status:p.status,
          error:p.error,
          dom:p.dom,
          metrics:p.metrics,
          axeSummary:p.axe?.summary||null,
          axeError:p.axe?.error||null
        })),
        apiRequests:browser.apiRequests,
        badResponses:browser.badResponses
      }
    }
  };
}

export function dueForSchedule(project,lastScan,now=new Date()) {
  if(!project||project.schedule==='manual') return false;
  if(!lastScan) return true;
  const ageHours=(now.getTime()-new Date(lastScan.completedAt||lastScan.startedAt).getTime())/3600000;
  return project.schedule==='daily'?ageHours>=22:ageHours>=24*6.5;
}

export function buildExecutiveSummary(scan) {
  if(!scan) return 'No scan data is available yet.';
  const highRisk=scan.summary.critical+scan.summary.high;
  const materialQuality=scan.findings.filter((f)=>['Quality','Accessibility','Performance'].includes(f.category)&&['High','Medium'].includes(f.severity)).length;
  const newCount=scan.findings.filter((f)=>f.lifecycle==='new').length;
  const resolved=scan.resolvedFindings?.length||0;
  const degraded=Object.entries(scan.engineStatus||{}).filter(([,v])=>v.status==='degraded'||v.status==='failed').map(([k])=>k);

  return `Assurance score is ${scan.score}/100. ${scan.metrics.pagesCrawled||1} HTML pages were crawled, ${scan.metrics.browserPages||0} browser renders were tested, ${scan.metrics.accessibilityViolations||0} accessibility rules produced violations, and ${scan.metrics.apiEndpoints||0} API paths were observed. The scan found ${highRisk} critical/high security findings and ${materialQuality} material quality/accessibility/performance findings. ${newCount} findings are new and ${resolved} previously observed findings are no longer present.${degraded.length?' Coverage was degraded for: '+degraded.join(', ')+'.':''}`;
}
