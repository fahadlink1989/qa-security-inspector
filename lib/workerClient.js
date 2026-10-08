import crypto from 'node:crypto';

const ALLOWED_ENGINES=new Set(['zap','nuclei','naabu','openvas','trivy','gitleaks']);
const ALLOWED_PROFILES=new Set(['safe','deep','code','network']);

export function scannerWorkerStatus(){
  return {
    configured:Boolean(process.env.SCANNER_WORKER_URL&&process.env.SCANNER_WORKER_SECRET),
    urlConfigured:Boolean(process.env.SCANNER_WORKER_URL),
    secretConfigured:Boolean(process.env.SCANNER_WORKER_SECRET)
  };
}

export async function runWorkerEngine({engine,target,profile='safe',jobId,metadata={}}){
  if(!ALLOWED_ENGINES.has(engine)) throw new Error('Unsupported scanner engine.');
  if(!ALLOWED_PROFILES.has(profile)) throw new Error('Unsupported scanner profile.');
  const base=process.env.SCANNER_WORKER_URL;
  const secret=process.env.SCANNER_WORKER_SECRET;
  if(!base||!secret) throw new Error('Scanner worker is not configured.');

  const body=JSON.stringify({
    version:1,
    jobId:jobId||crypto.randomUUID(),
    engine,
    profile,
    target,
    metadata
  });
  const timestamp=String(Date.now());
  const signature=crypto.createHmac('sha256',secret).update(timestamp+'.'+body).digest('hex');

  const response=await fetch(new URL('/v1/scan',base),{
    method:'POST',
    headers:{
      'content-type':'application/json',
      'x-inspector-timestamp':timestamp,
      'x-inspector-signature':signature
    },
    body,
    signal:AbortSignal.timeout(300000)
  });
  const result=await response.json().catch(()=>({}));
  if(!response.ok) throw new Error(result.error||('Scanner worker returned '+response.status));
  return result;
}
