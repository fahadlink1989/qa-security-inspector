import {withWorkspace,rateLimit} from '../../../lib/backend/auth';
import {workspaceContext} from '../../../lib/backend/context';
import {billingView,openBilling} from '../../../lib/backend/billing';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export const GET=withWorkspace(async()=>Response.json(await billingView(workspaceContext().workspaceId),{headers:{'cache-control':'no-store'}}));
export const POST=withWorkspace(async request=>{
  const account=workspaceContext();if(account.role!=='owner')return Response.json({error:'Only workspace owners can manage billing.'},{status:403});
  const {action}=await request.json();if(!['checkout','portal','refresh'].includes(action))return Response.json({error:'Unknown billing action.'},{status:400});
  await rateLimit('billing:'+account.workspaceId,20,3600);
  try{return Response.json(await openBilling(account,action));}catch(error){return Response.json({error:error.status?error.message:'Billing provider unavailable. Please try again.'},{status:error.status||503});}
});
