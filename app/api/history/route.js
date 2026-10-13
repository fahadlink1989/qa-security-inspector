import {withWorkspace} from '../../../lib/backend/auth';
import {workspaceContext} from '../../../lib/backend/context';
import {database} from '../../../lib/backend/db';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export const GET=withWorkspace(async request=>{
  const params=new URL(request.url).searchParams,values=[workspaceContext().workspaceId],clauses=['workspace_id=$1'];
  for(const [parameter,column] of [['projectId','project_id'],['assetId','asset_id'],['kind','kind'],['id','id']])if(params.get(parameter)){values.push(params.get(parameter));clauses.push(column+'=$'+values.length);}
  if(params.get('cursor')){
    let cursor;try{cursor=JSON.parse(Buffer.from(params.get('cursor'),'base64url').toString());}catch{return Response.json({error:'Invalid history cursor.'},{status:400});}
    if(!Array.isArray(cursor)||cursor.length!==3||!Number.isFinite(Date.parse(cursor[0]))||cursor.some(v=>typeof v!=='string'))return Response.json({error:'Invalid history cursor.'},{status:400});
    values.push(...cursor);const i=values.length;clauses.push(`(recorded_at,kind,id)<($${i-2}::timestamptz,$${i-1},$${i})`);
  }
  const limit=Math.min(100,Math.max(1,Number(params.get('limit'))||25));values.push(limit+1);
  const detail=Boolean(params.get('id'));
  const {rows}=await database().query(`SELECT kind,id,recorded_at,${detail?'data':"jsonb_build_object('id',id,'projectId',project_id,'assetId',asset_id,'status',data->'status','url',data->'url','scanType',data->'scanType','summary',data->'summary','completedAt',data->'completedAt','findingCount',jsonb_array_length(coalesce(data->'findings','[]')) ) AS data"} FROM inspector_scan_history WHERE ${clauses.join(' AND ')} ORDER BY recorded_at DESC,kind DESC,id DESC LIMIT $${values.length}`,values);
  const items=rows.slice(0,limit),last=items.at(-1);
  return Response.json({items:items.map(r=>({...r.data,_kind:r.kind})),nextCursor:rows.length>limit?Buffer.from(JSON.stringify([last.recorded_at.toISOString(),last.kind,last.id])).toString('base64url'):null},{headers:{'cache-control':'no-store'}});
});
