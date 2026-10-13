import Stripe from 'stripe';
import {database,transaction} from './db';
import {publicAppUrl} from './email';
export const billingConfigured=()=>Boolean(process.env.STRIPE_SECRET_KEY&&process.env.STRIPE_WEBHOOK_SECRET&&process.env.STRIPE_PRICE_ID&&publicAppUrl());
export const billingEnforced=()=>process.env.BILLING_ENFORCED==='1';
export function stripeClient(){if(!process.env.STRIPE_SECRET_KEY)throw Object.assign(new Error('Billing is not configured.'),{status:503});return new Stripe(process.env.STRIPE_SECRET_KEY,{timeout:10000,maxNetworkRetries:1});}
export function monthlyLimit(){const n=Number(process.env.STRIPE_MONTHLY_SCAN_LIMIT);return Number.isSafeInteger(n)&&n>0?n:null;}
export async function syncSubscription(client,workspaceId,provider=stripeClient()){
  const row=(await client.query('SELECT * FROM inspector_billing WHERE workspace_id=$1 FOR UPDATE',[workspaceId])).rows[0];
  if(!row?.customer_id)return row||null;
  const list=await provider.subscriptions.list({customer:row.customer_id,status:'all',limit:100});
  if(list.has_more)throw new Error('Subscription reconciliation requires operator review.');
  const matches=list.data.filter(s=>s.items.data.some(item=>item.price.id===process.env.STRIPE_PRICE_ID));
  // There should be one subscription. Favor a valid one, then the latest record.
  matches.sort((a,b)=>Number(['active','trialing'].includes(b.status))-Number(['active','trialing'].includes(a.status))||b.created-a.created);
  const sub=matches[0],item=sub?.items.data.find(i=>i.price.id===process.env.STRIPE_PRICE_ID);
  const result=await client.query(`UPDATE inspector_billing SET subscription_id=$2,status=$3,price_id=$4,period_end=$5,cancel_at_period_end=$6,verified_at=now(),updated_at=now() WHERE workspace_id=$1 RETURNING *`,
    [workspaceId,sub?.id||null,sub?.status||'unsubscribed',item?.price.id||null,(item?.current_period_end||sub?.current_period_end)?new Date((item?.current_period_end||sub.current_period_end)*1000):null,Boolean(sub?.cancel_at_period_end)]);
  return result.rows[0];
}
export async function billingView(workspaceId){
  const {rows}=await database().query('SELECT status,period_end,cancel_at_period_end,verified_at,customer_id IS NOT NULL AS has_customer FROM inspector_billing WHERE workspace_id=$1',[workspaceId]);
  const usage=await database().query("SELECT count(*)::int AS count FROM inspector_jobs WHERE workspace_id=$1 AND created_at>=date_trunc('month',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'",[workspaceId]);
  let price=null;
  if(billingConfigured())try{const p=await stripeClient().prices.retrieve(process.env.STRIPE_PRICE_ID);if(p.active&&p.type==='recurring')price={currency:p.currency,amount:p.unit_amount,interval:p.recurring.interval,intervalCount:p.recurring.interval_count};}catch{/* The status stays unavailable; do not invent a price. */}
  return {configured:billingConfigured(),checkoutAvailable:Boolean(price&&monthlyLimit()),enforced:billingEnforced(),mode:process.env.STRIPE_SECRET_KEY?.startsWith('sk_live_')?'live':'test',subscription:rows[0]||{status:'unsubscribed'},price,monthlyScanLimit:monthlyLimit(),scansThisMonth:usage.rows[0].count};
}
export async function openBilling(account,action,provider=stripeClient()){
  if(!billingConfigured()||!monthlyLimit())throw Object.assign(new Error('Billing setup is incomplete. No checkout is available.'),{status:503});
  return transaction(async client=>{
    await client.query('INSERT INTO inspector_billing(workspace_id) VALUES($1) ON CONFLICT DO NOTHING',[account.workspaceId]);
    let row=(await client.query('SELECT * FROM inspector_billing WHERE workspace_id=$1 FOR UPDATE',[account.workspaceId])).rows[0];
    const stripe=provider,origin=publicAppUrl();
    if(action==='refresh'){await syncSubscription(client,account.workspaceId,stripe);return {refreshed:true};}
    if(!row.customer_id){const customer=await stripe.customers.create({email:account.email,name:account.name,metadata:{workspaceId:account.workspaceId}},{idempotencyKey:'inspector-customer-'+account.workspaceId});await client.query('UPDATE inspector_billing SET customer_id=$2 WHERE workspace_id=$1',[account.workspaceId,customer.id]);row.customer_id=customer.id;}
    if(action==='portal')return {url:(await stripe.billingPortal.sessions.create({customer:row.customer_id,return_url:origin+'/?settings=billing'})).url};
    row=await syncSubscription(client,account.workspaceId,stripe);
    if(!['unsubscribed','canceled','incomplete_expired'].includes(row.status))throw Object.assign(new Error('This workspace already has a subscription. Use Manage billing.'),{status:409});
    if(row.checkout_id&&new Date(row.checkout_expires_at)>new Date()){
      const old=await stripe.checkout.sessions.retrieve(row.checkout_id);
      if(old.status==='open')return {url:old.url};
      if(old.status==='complete')throw Object.assign(new Error('Payment is being reconciled. Refresh billing status shortly.'),{status:409});
    }
    const price=await stripe.prices.retrieve(process.env.STRIPE_PRICE_ID);
    if(!price.active||price.type!=='recurring')throw new Error('Configure an active recurring Stripe price.');
    const checkout=await stripe.checkout.sessions.create({customer:row.customer_id,mode:'subscription',line_items:[{price:price.id,quantity:1}],client_reference_id:account.workspaceId,subscription_data:{metadata:{workspaceId:account.workspaceId}},success_url:origin+'/?settings=billing&checkout=success',cancel_url:origin+'/?settings=billing'},{idempotencyKey:'inspector-checkout-'+account.workspaceId+'-'+(row.checkout_id||'initial')});
    await client.query('UPDATE inspector_billing SET checkout_id=$2,checkout_url=$3,checkout_expires_at=$4 WHERE workspace_id=$1',[account.workspaceId,checkout.id,checkout.url,new Date(checkout.expires_at*1000)]);
    return {url:checkout.url};
  });
}
export async function handleBillingEvent(event,provider=stripeClient()){
  if(!['checkout.session.completed','checkout.session.async_payment_succeeded','checkout.session.async_payment_failed','customer.subscription.created','customer.subscription.updated','customer.subscription.deleted','invoice.paid','invoice.payment_failed'].includes(event.type))return;
  const customer=event.data.object.customer;
  if(typeof customer!=='string')return;
  await transaction(async client=>{
    const found=await client.query('SELECT workspace_id FROM inspector_billing WHERE customer_id=$1 FOR UPDATE',[customer]);
    if(!found.rowCount)return;const workspaceId=found.rows[0].workspace_id;
    const seen=await client.query('SELECT id FROM inspector_billing_events WHERE id=$1',[event.id]);if(seen.rowCount)return;
    // Retrieve current state under the row lock; out-of-order deliveries cannot revert it.
    await syncSubscription(client,workspaceId,provider);
    await client.query('INSERT INTO inspector_billing_events(id,workspace_id,kind) VALUES($1,$2,$3)',[event.id,workspaceId,event.type]);
  });
}
export async function assertScanEntitlement(client,workspaceId){
  if(!billingEnforced())return;
  if(!billingConfigured()||!monthlyLimit())throw Object.assign(new Error('Billing configuration is unavailable. Existing results remain accessible.'),{status:503});
  let row=(await client.query('SELECT * FROM inspector_billing WHERE workspace_id=$1 FOR UPDATE',[workspaceId])).rows[0];
  if(row?.customer_id&&(!row.verified_at||Date.now()-new Date(row.verified_at)>900000))row=await syncSubscription(client,workspaceId);
  if(!row||!['active','trialing'].includes(row.status))throw Object.assign(new Error('An active subscription is required to start another scan. Open Settings → Billing.'),{status:402});
  const usage=await client.query("SELECT count(*)::int AS count FROM inspector_jobs WHERE workspace_id=$1 AND created_at>=date_trunc('month',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'",[workspaceId]);
  if(usage.rows[0].count>=monthlyLimit())throw Object.assign(new Error('This workspace has used its monthly scan allowance. Existing results remain accessible.'),{status:402});
}
