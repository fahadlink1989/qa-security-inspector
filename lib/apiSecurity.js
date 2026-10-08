import { safeFetch } from './net';
import { finding } from './scanner';

function isFirstParty(host,root){
  const h=String(host||'').toLowerCase();
  const r=String(root||'').toLowerCase();
  return h===r||h.endsWith('.'+r);
}

function candidateEndpoint(item){
  const method=String(item.method||'').toUpperCase();
  if(!['GET','HEAD','OBSERVE'].includes(method)) return false;
  if(!item.hostname||!item.path||item.path.includes('{')||item.path.includes('}')) return false;
  if(['Analytics / Telemetry','Static / Generated asset'].includes(item.classification)) return false;
  if(/logout|signout|delete|remove|unsubscribe|download|export/i.test(item.path)) return false;
  return true;
}

function collectKeys(value,keys=new Set(),depth=0){
  if(depth>4||value==null) return keys;
  if(Array.isArray(value)){
    for(const item of value.slice(0,3)) collectKeys(item,keys,depth+1);
    return keys;
  }
  if(typeof value==='object'){
    for(const [key,item] of Object.entries(value).slice(0,80)){
      keys.add(key);
      collectKeys(item,keys,depth+1);
    }
  }
  return keys;
}

const sensitiveKey=/^(?:email|phone|mobile|address|user_?id|account_?id|customer_?id|subscription|invoice|role|permissions?|token|access_?token|refresh_?token|api_?key|secret|card|payment|billing)$/i;
const sensitivePath=/(?:^|\/)(?:me|profile|account|accounts|user|users|customer|customers|subscription|subscriptions|billing|invoice|invoices|session|sessions|admin)(?:\/|$|\?)/i;

async function probeEndpoint(endpoint,root){
  if(!isFirstParty(endpoint.hostname,root)||!candidateEndpoint(endpoint)) return null;
  const method=endpoint.method==='HEAD'?'HEAD':'GET';
  const scheme='https:';
  const target=new URL(scheme+'//'+endpoint.hostname+endpoint.path);
  const response=await safeFetch(target.href,{
    method,
    headers:{accept:'application/json,text/plain,*/*'}
  },5000);

  const record={
    endpoint,
    url:target.href,
    status:response.status,
    contentType:response.headers.get('content-type')||'',
    allow:response.headers.get('allow')||'',
    keys:[],
    sensitiveKeys:[],
    bodyKind:'none'
  };

  if(method==='GET'&&response.status>=200&&response.status<300){
    const length=Number(response.headers.get('content-length')||0);
    if(length>2_000_000) return record;
    const text=(await response.text()).slice(0,500000);
    if(/json/i.test(record.contentType)||/^\s*[\[{]/.test(text)){
      try{
        const parsed=JSON.parse(text);
        const keys=[...collectKeys(parsed)].slice(0,120);
        record.keys=keys;
        record.sensitiveKeys=keys.filter(k=>sensitiveKey.test(k)).slice(0,30);
        record.bodyKind='json';
      }catch{record.bodyKind='text';}
    }else{
      record.bodyKind='text';
    }
  }

  return record;
}

export async function assessApiSecurity({rootDomain,endpoints}){
  const findings=[];
  const coverage=[];
  const candidates=endpoints
    .filter(candidateEndpoint)
    .filter(e=>isFirstParty(e.hostname,rootDomain))
    .sort((a,b)=>{
      const score=(e)=>e.authExpected?0:/Authentication|Billing|Business API/.test(e.classification||'')?1:2;
      return score(a)-score(b);
    })
    .slice(0,24);

  let cursor=0;
  async function worker(){
    while(true){
      const i=cursor++;
      if(i>=candidates.length) return;
      const endpoint=candidates[i];
      try{
        const result=await probeEndpoint(endpoint,rootDomain);
        if(!result) continue;
        coverage.push(result);

        if(endpoint.authExpected && result.status>=200&&result.status<300){
          findings.push(finding(
            'API-AUTH-EXPECTED-200','API Security','High','Endpoint documented as protected responded without authentication',
            'An OpenAPI-described endpoint with a security requirement returned a successful unauthenticated response. This requires application-owner validation because some APIs intentionally make selected responses public.',
            'Endpoint: '+result.url+'\nHTTP '+result.status+'\nOpenAPI security requirement: present\nResponse type: '+result.bodyKind+'\nObserved keys: '+result.keys.slice(0,25).join(', '),
            'Confirm the endpoint is intended to require authentication. If so, enforce authorization before controller/business logic, add automated negative authorization tests, and retest with Inspector.',
            {location:result.url,engine:'api-security',confidence:'High',evidenceQuality:'validated'}
          ));
        } else if(result.status>=200&&result.status<300 && sensitivePath.test(endpoint.path) && result.sensitiveKeys.length){
          findings.push(finding(
            'API-PUBLIC-SENSITIVE-DATA','API Security','High','Unauthenticated endpoint returns potentially sensitive structured data',
            'A first-party account/user/billing-style endpoint returned structured data without authentication and exposed fields commonly associated with sensitive records.',
            'Endpoint: '+result.url+'\nHTTP '+result.status+'\nClassification: '+endpoint.classification+'\nPotentially sensitive field names: '+result.sensitiveKeys.join(', ')+'\nValues were intentionally not stored.',
            'Confirm whether the response is intentionally public. If not, require authentication and object-level authorization before returning records, minimize returned fields, add negative authorization tests, and rotate any credentials if secrets were exposed.',
            {location:result.url,engine:'api-security',confidence:'Medium',evidenceQuality:'validated'}
          ));
        }
      }catch{}
    }
  }
  await Promise.all(Array.from({length:4},()=>worker()));

  return {findings,coverage};
}
