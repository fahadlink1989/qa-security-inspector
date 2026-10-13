import {stripeClient,handleBillingEvent} from '../../../../lib/backend/billing';
export const runtime='nodejs';
export async function POST(request){
  if(!process.env.STRIPE_WEBHOOK_SECRET||!process.env.STRIPE_SECRET_KEY)return new Response('Webhook not configured',{status:503});
  const body=await request.text();if(body.length>1048576)return new Response('Too large',{status:413});
  let event;try{event=stripeClient().webhooks.constructEvent(body,request.headers.get('stripe-signature'),process.env.STRIPE_WEBHOOK_SECRET);}catch{return new Response('Invalid signature',{status:400});}
  const live=process.env.STRIPE_SECRET_KEY.startsWith('sk_live_');if(event.livemode!==live)return new Response('Billing mode mismatch',{status:400});
  try{await handleBillingEvent(event);return Response.json({received:true});}catch{return new Response('Event processing failed; retry later',{status:503});}
}
