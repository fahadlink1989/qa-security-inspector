import {Webhook} from 'svix';
import {recordEmailEvent} from '../../../../lib/backend/email';
export const runtime='nodejs';
export async function POST(request){
  if(!process.env.RESEND_WEBHOOK_SECRET)return new Response('Webhook not configured',{status:503});
  const body=await request.text();if(body.length>262144)return new Response('Too large',{status:413});
  let event;try{event=new Webhook(process.env.RESEND_WEBHOOK_SECRET).verify(body,{'svix-id':request.headers.get('svix-id'),'svix-timestamp':request.headers.get('svix-timestamp'),'svix-signature':request.headers.get('svix-signature')});}catch{return new Response('Invalid signature',{status:400});}
  try{await recordEmailEvent(request.headers.get('svix-id'),event);return Response.json({received:true});}catch{return new Response('Event could not be saved',{status:503});}
}
