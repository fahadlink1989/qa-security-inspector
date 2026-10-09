import {withWorkspace,rateLimit} from '../../../lib/backend/auth';
import {workspaceContext} from '../../../lib/backend/context';
import {encryptPayload} from '../../../lib/backend/crypto';
import {readState,mutateState} from '../../../lib/store';
import {enqueueJob} from '../../../lib/backend/queue';
import {assertPublicTarget} from '../../../lib/net';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export const POST=withWorkspace(async request=>{
  try{
    const body=await request.json(),context=workspaceContext();
    if(body.action==='configure'){
      if(!['owner','admin'].includes(context.role))return Response.json({error:'Only workspace owners or admins can configure the provider.'},{status:403});
      const key=String(body.key||'').trim();
      if(key&&(!/^[A-Za-z0-9_-]{20,200}$/.test(key)))throw new Error('Enter a valid Google API key.');
      await mutateState(state=>{state.workspace.performanceKey=key?encryptPayload({key},context.workspaceId+':pagespeed'):null;return state;});
      return Response.json({ok:true,configured:Boolean(key||process.env.PAGESPEED_API_KEY)});
    }
    if(body.authorized!==true)throw new Error('Confirm permission to test and send this public URL to Google.');
    const state=await readState(),project=state.projects.find(p=>p.id===body.projectId);
    const asset=project?.assets?.find(a=>a.id===body.assetId&&a.status==='active');
    if(!asset)throw new Error('Active target not found.');
    const url=new URL(asset.url);
    if(!['http:','https:'].includes(url.protocol)||url.username||url.password)throw new Error('Use a public HTTP(S) URL without credentials.');
    await assertPublicTarget(url);
    const active=state.jobs.find(j=>j.type==='performance'&&j.assetId===asset.id&&['queued','running'].includes(j.status));
    if(active)return Response.json(active,{status:202});
    await rateLimit('pagespeed:'+context.workspaceId,20,3600);
    const job=await enqueueJob({type:'performance',projectId:project.id,assetId:asset.id,target:asset.url,scanType:'Website Performance'},{});
    return Response.json(job,{status:202});
  }catch(error){return Response.json({error:error.message},{status:error.status||400});}
});
