import crypto from 'node:crypto';
import {database,transaction} from './db';
import {encryptPayload,decryptPayload} from './crypto';
export function publicAppUrl(){
  const raw=process.env.APP_PUBLIC_URL||(process.env.APP_ORIGINS||'').split(',')[0]?.trim();
  try{const url=new URL(raw);if(url.protocol!=='https:'&&!(process.env.NODE_ENV!=='production'&&url.hostname==='localhost'))return null;return url.origin;}catch{return null;}
}
export const emailConfigured=()=>Boolean(process.env.RESEND_API_KEY&&process.env.EMAIL_FROM&&publicAppUrl());
export async function enqueueEmail(client,{workspaceId=null,to,purpose,text,subject}){
  if(!emailConfigured())return {status:'not_configured'};
  const id=crypto.randomUUID();
  const payload=encryptPayload({from:process.env.EMAIL_FROM,to:[to],subject,text},'email:'+id);
  await client.query('INSERT INTO inspector_email_outbox(id,workspace_id,purpose,payload) VALUES($1,$2,$3,$4)',[id,workspaceId,purpose,payload]);
  return {id,status:'queued'};
}
export async function consumeEmail(fetcher=fetch){
  if(!emailConfigured())return {status:'not_configured'};
  const job=await transaction(async client=>{
    // Never retry beyond the provider's 24h idempotency window. A lost acknowledgment
    // after that point requires operator investigation, not another possible send.
    await client.query("UPDATE inspector_email_outbox SET status='failed',payload=NULL,lease_until=NULL,last_error='Delivery retry window expired; check provider logs.' WHERE status IN ('queued','sending') AND created_at<now()-interval '23 hours'");
    const {rows}=await client.query("SELECT * FROM inspector_email_outbox WHERE (status='queued' AND available_at<=now()) OR (status='sending' AND lease_until<now()) ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1");
    if(!rows.length)return null;
    const job=rows[0],token=crypto.randomUUID();
    await client.query("UPDATE inspector_email_outbox SET status='sending',attempts=attempts+1,lease_token=$2,lease_until=now()+interval '60 seconds' WHERE id=$1",[job.id,token]);return {...job,token};
  });
  if(!job)return {idle:true};
  let providerId=null,error='Email provider temporarily unavailable.',terminal=false;
  try{
    const response=await fetcher('https://api.resend.com/emails',{method:'POST',headers:{authorization:'Bearer '+process.env.RESEND_API_KEY,'content-type':'application/json','Idempotency-Key':'inspector/'+job.id},body:JSON.stringify(decryptPayload(job.payload,'email:'+job.id)),signal:AbortSignal.timeout(15000),redirect:'error'});
    if(response.ok){providerId=(await response.json()).id;if(typeof providerId!=='string')throw new Error('Invalid acknowledgment');}
    else {terminal=response.status<500&&![408,409,429].includes(response.status);error='Email provider returned HTTP '+response.status+'.';}
  }catch{/* Never retain provider errors containing tokens or recipient details. */}
  await transaction(async client=>{
    if(providerId){
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[providerId]);
      const events=await client.query("SELECT kind,occurred_at FROM inspector_email_events WHERE provider_id=$1 ORDER BY CASE WHEN kind IN ('email.bounced','email.complained','email.failed') THEN 0 ELSE 1 END,occurred_at DESC LIMIT 1",[providerId]);
      const event=events.rows[0],status=event?.kind==='email.delivered'?'delivered':event?'bounced':'accepted';
      await client.query("UPDATE inspector_email_outbox SET status=$3,provider_id=$4,accepted_at=now(),delivered_at=$5,payload=NULL,lease_token=NULL,lease_until=NULL,last_error=NULL WHERE id=$1 AND lease_token=$2 AND status='sending'",[job.id,job.token,status,providerId,status==='delivered'?event.occurred_at:null]);
    }else{
      terminal=terminal||job.attempts>=7;
      await client.query("UPDATE inspector_email_outbox SET status=$3,last_error=$4,payload=CASE WHEN $5 THEN NULL ELSE payload END,available_at=now()+$6*interval '1 second',lease_token=NULL,lease_until=NULL WHERE id=$1 AND lease_token=$2 AND status='sending'",[job.id,job.token,terminal?'failed':'queued',error,terminal,Math.min(3600,30*2**job.attempts)]);
    }
  });
  return {processed:true};
}
export async function recordEmailEvent(id,event){
  const kinds=['email.delivered','email.bounced','email.complained','email.failed'];
  if(!kinds.includes(event.type)||typeof event.data?.email_id!=='string')return;
  const occurred=new Date(event.created_at);if(!Number.isFinite(occurred.valueOf()))throw new Error('Invalid event timestamp');
  await transaction(async client=>{
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[event.data.email_id]);
    await client.query('INSERT INTO inspector_email_events(id,provider_id,kind,occurred_at) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING',[id,event.data.email_id,event.type,occurred]);
    // A subsequent delivery event must never hide a bounce or complaint.
    if(event.type==='email.delivered')await client.query("UPDATE inspector_email_outbox SET status='delivered',delivered_at=$2 WHERE provider_id=$1 AND status='accepted'",[event.data.email_id,occurred]);
    else await client.query("UPDATE inspector_email_outbox SET status='bounced',last_error=$2 WHERE provider_id=$1",[event.data.email_id,event.type]);
  });
}
