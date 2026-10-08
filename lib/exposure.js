import dns from 'node:dns/promises';
import { safeFetch, assertPublicTarget } from './net';
import { finding } from './scanner';

const providerSuffixes=[
  'github.io','herokudns.com','azurewebsites.net','cloudfront.net',
  'fastly.net','netlify.app','vercel.app','trafficmanager.net'
];

function withinRoot(host,root){
  const h=String(host||'').toLowerCase();
  const r=String(root||'').toLowerCase();
  return h===r||h.endsWith('.'+r);
}

function looksHtmlLogin(text){
  return /<title[^>]*>[^<]*(?:admin|login|sign[ -]?in|dashboard)|(?:username|email)[^<]{0,120}(?:password)|wp-login/i.test(text);
}

async function getSnippet(url,options={}){
  const response=await safeFetch(url,{
    method:'GET',
    headers:{
      accept:'text/plain,text/html,application/json,application/zip,application/octet-stream,*/*',
      range:'bytes=0-65535'
    }
  },options.timeout||4500);
  const length=Number(response.headers.get('content-length')||0);
  if(length>15_000_000) return {response,text:'',skippedLarge:true};
  const buffer=Buffer.from(await response.arrayBuffer());
  return {
    response,
    buffer,
    text:buffer.toString('utf8').slice(0,120000),
    contentType:response.headers.get('content-type')||'',
    length:length||buffer.length
  };
}

async function validateHostExposure(host){
  const out=[];
  const base=new URL(host.url);
  const probes=[
    {path:'/.git/HEAD',id:'EXP-GIT',severity:'High',title:'Git repository metadata is publicly exposed',
      validate:(r)=>/^ref:\s+refs\/heads\//m.test(r.text),
      evidence:(r)=>'Response matched a Git HEAD ref. HTTP '+r.response.status},
    {path:'/.env',id:'EXP-ENV',severity:'High',title:'Environment configuration appears publicly exposed',
      validate:(r)=>{
        const keys=[...r.text.matchAll(/^\s*([A-Z][A-Z0-9_]{2,})\s*=.*$/gm)].map(m=>m[1]);
        return keys.length>=2;
      },
      evidence:(r)=>{
        const keys=[...r.text.matchAll(/^\s*([A-Z][A-Z0-9_]{2,})\s*=.*$/gm)].map(m=>m[1]).slice(0,12);
        return 'Environment-style keys observed: '+keys.join(', ');
      }},
    {path:'/actuator/env',id:'EXP-ACTUATOR-ENV',severity:'High',title:'Spring actuator environment endpoint is public',
      validate:(r)=>/"propertySources"|"activeProfiles"|"systemProperties"/i.test(r.text),
      evidence:(r)=>'Response contained Spring actuator environment markers. HTTP '+r.response.status},
    {path:'/actuator',id:'EXP-ACTUATOR',severity:'Medium',title:'Spring actuator endpoint is publicly reachable',
      validate:(r)=>/_links|health|metrics|env/i.test(r.text)&&/application\/json|json/i.test(r.contentType),
      evidence:(r)=>'Response contained actuator-style JSON links/keys. HTTP '+r.response.status},
    {path:'/server-status',id:'EXP-SERVER-STATUS',severity:'Medium',title:'Apache server-status is publicly exposed',
      validate:(r)=>/Apache Server Status|Server Version: Apache/i.test(r.text),
      evidence:(r)=>'Response matched Apache server-status markers.'},
    {path:'/phpinfo.php',id:'EXP-PHPINFO',severity:'High',title:'phpinfo output is publicly exposed',
      validate:(r)=>/phpinfo\(\)|PHP Version\s*<\/td>/i.test(r.text),
      evidence:(r)=>'Response matched phpinfo output markers.'},
    {path:'/backup.zip',id:'EXP-BACKUP-ZIP',severity:'High',title:'Potential website backup archive is publicly downloadable',
      validate:(r)=>r.buffer?.[0]===0x50&&r.buffer?.[1]===0x4b,
      evidence:(r)=>'Response began with ZIP magic bytes. Size header: '+r.length+' bytes.'},
    {path:'/site.zip',id:'EXP-SITE-ZIP',severity:'High',title:'Potential website archive is publicly downloadable',
      validate:(r)=>r.buffer?.[0]===0x50&&r.buffer?.[1]===0x4b,
      evidence:(r)=>'Response began with ZIP magic bytes. Size header: '+r.length+' bytes.'},
    {path:'/dump.sql',id:'EXP-SQL-DUMP',severity:'High',title:'Potential SQL database dump is publicly exposed',
      validate:(r)=>/--\s*(?:MySQL|PostgreSQL)|CREATE\s+TABLE|INSERT\s+INTO/i.test(r.text),
      evidence:(r)=>'Response contained SQL dump markers.'},
    {path:'/database.sql',id:'EXP-SQL-DATABASE',severity:'High',title:'Potential SQL database export is publicly exposed',
      validate:(r)=>/--\s*(?:MySQL|PostgreSQL)|CREATE\s+TABLE|INSERT\s+INTO/i.test(r.text),
      evidence:(r)=>'Response contained SQL dump markers.'},
    {path:'/.env.bak',id:'EXP-ENV-BAK',severity:'High',title:'Environment backup file appears publicly exposed',
      validate:(r)=>[...r.text.matchAll(/^\s*([A-Z][A-Z0-9_]{2,})\s*=.*$/gm)].length>=2,
      evidence:(r)=>'Backup response contained environment-style key/value lines.'}
  ];

  for(const probe of probes){
    try{
      const target=new URL(probe.path,base);
      if(target.hostname!==base.hostname) continue;
      const r=await getSnippet(target.href);
      if(!(r.response.status>=200&&r.response.status<300)||r.skippedLarge) continue;
      if(!probe.validate(r)) continue;
      out.push(finding(
        probe.id,'Exposure',probe.severity,probe.title,
        probe.title+' on '+host.hostname+'.',
        probe.evidence(r),
        'Remove the artifact from the public web root or restrict it to trusted administrators. Rotate any credentials/secrets that may have been exposed, then retest.',
        {location:target.href,engine:'exposure-validation',confidence:'High',evidenceQuality:'validated'}
      ));
    }catch{}
  }

  const adminPaths=['/admin','/administrator','/wp-admin','/console','/debug'];
  for(const path of adminPaths){
    try{
      const target=new URL(path,base);
      const r=await getSnippet(target.href,{timeout:3500});
      if(!(r.response.status>=200&&r.response.status<400)||!looksHtmlLogin(r.text)) continue;
      out.push(finding(
        'EXP-ADMIN-SURFACE','Exposure','Informational','Administrative or login surface is publicly reachable',
        'Inspector identified a public administrative/login-style page. Public reachability is not itself a vulnerability, but it increases the externally reachable authentication surface.',
        'Host: '+host.hostname+'\nURL: '+target.href+'\nHTTP '+r.response.status+'\nContent matched login/admin page markers.',
        'Confirm the page is intentionally internet-facing. Enforce strong authentication/MFA, rate limiting and monitoring; restrict by network or identity proxy if public access is unnecessary.',
        {location:target.href,engine:'exposure-validation',confidence:'Medium',evidenceQuality:'observed'}
      ));
      break;
    }catch{}
  }

  return out;
}

export async function findDanglingDnsSignals(hostnames,root){
  const signals=[];
  for(const hostname of hostnames.slice(0,50)){
    if(!withinRoot(hostname,root)) continue;
    try{
      const cnames=await dns.resolveCname(hostname);
      for(const cnameRaw of cnames){
        const cname=String(cnameRaw).toLowerCase().replace(/\.$/,'');
        if(!providerSuffixes.some(s=>cname===s||cname.endsWith('.'+s))) continue;
        let targetResolves=true;
        try{
          const records=await dns.lookup(cname,{all:true});
          targetResolves=records.length>0;
        }catch{targetResolves=false;}
        if(!targetResolves){
          signals.push(finding(
            'EXP-DANGLING-DNS','Exposure','High','Potential dangling DNS / subdomain takeover condition',
            hostname+' points to a third-party service hostname that did not resolve during validation.',
            'Hostname: '+hostname+'\nCNAME: '+cname+'\nProvider target DNS resolution: failed',
            'Confirm the third-party resource still exists. If unused, remove the DNS record. If required, recreate/claim the provider resource and verify ownership before restoring traffic.',
            {location:'https://'+hostname+'/',engine:'dns-exposure',confidence:'Medium',evidenceQuality:'validated'}
          ));
        }
      }
    }catch{}
  }
  return signals;
}

export async function validatePublicExposures({rootDomain,liveHosts}){
  const prioritized=[...liveHosts]
    .sort((a,b)=>{
      const score=(h)=>/staging|dev|test|admin|auth|login|api|billing|portal/i.test(h.hostname)?0:1;
      return score(a)-score(b);
    })
    .slice(0,20);

  const results=[];
  let cursor=0;
  async function worker(){
    while(true){
      const i=cursor++;
      if(i>=prioritized.length) return;
      const host=prioritized[i];
      results.push(...await validateHostExposure(host));
    }
  }
  await Promise.all(Array.from({length:4},()=>worker()));
  results.push(...await findDanglingDnsSignals(liveHosts.map(h=>h.hostname),rootDomain));
  return results;
}
