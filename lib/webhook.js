import dns from 'node:dns/promises';
import https from 'node:https';
import {isPublicAddress,validateWebhookUrl} from './publicAddress.mjs';
export async function deliverWebhook(value,payload) {
  const url=validateWebhookUrl(value);
  const records=await dns.lookup(url.hostname.replace(/^\[|\]$/g,''),{all:true,verbatim:true});
  if(!records.length||records.some(r=>!isPublicAddress(r.address))) throw new Error('Webhook resolves to a non-public address.');
  const record=records[0],body=JSON.stringify(payload);
  // Pin the validated address for the connection; preserve hostname for TLS verification.
  // Never forward the payload through a redirect.
  return new Promise((resolve,reject)=>{
    const req=https.request(url,{method:'POST',agent:false,headers:{'content-type':'application/json','content-length':Buffer.byteLength(body)},
      lookup:(_host,options,callback)=>options?.all?callback(null,[record]):callback(null,record.address,record.family)},res=>{
      res.resume();
      if(res.statusCode>=200&&res.statusCode<300) resolve({status:'delivered',httpStatus:res.statusCode});
      else reject(new Error('Webhook returned HTTP '+res.statusCode+'; redirects are not followed.'));
      req.destroy();
    });
    const timer=setTimeout(()=>req.destroy(new Error('Webhook delivery timed out.')),5000);
    req.on('close',()=>clearTimeout(timer));req.on('error',reject);req.end(body);
  });
}
