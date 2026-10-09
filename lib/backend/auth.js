import { database } from './db';
import { hashToken } from './crypto';
import { inWorkspace } from './context';
export const COOKIE='inspector_session';
export function sessionToken(request) {
  return (request.headers.get('cookie')||'').split(';').map(s=>s.trim()).find(s=>s.startsWith(COOKIE+'='))?.slice(COOKIE.length+1)||'';
}
export function checkOrigin(request) {
  if(['GET','HEAD','OPTIONS'].includes(request.method)) return;
  const origin=request.headers.get('origin');
  const allowed=(process.env.APP_ORIGINS||'http://localhost:3000').split(',').map(s=>s.trim());
  if(!origin||!allowed.includes(origin)) throw Object.assign(new Error('Request origin is not allowed.'),{status:403});
}
export async function session(request) {
  const token=sessionToken(request);
  if(!token) return null;
  const {rows}=await database().query(`SELECT s.workspace_id AS "workspaceId",u.id AS "userId",u.email,m.role,w.name
    FROM inspector_sessions s JOIN inspector_users u ON u.id=s.user_id
    JOIN inspector_memberships m ON m.user_id=s.user_id AND m.workspace_id=s.workspace_id
    JOIN inspector_workspaces w ON w.id=s.workspace_id
    WHERE s.token_hash=$1 AND s.expires_at>now()`,[hashToken(token)]);
  return rows[0]||null;
}
export function withWorkspace(handler) {
  return async(request,...args)=>{
    try {
      checkOrigin(request);
      const account=await session(request);
      if(!account) return Response.json({error:'Sign in to your workspace.'},{status:401});
      if(account.role==='viewer'&&!['GET','HEAD'].includes(request.method)) return Response.json({error:'This account has read-only access.'},{status:403});
      return await inWorkspace(account,()=>handler(request,...args));
    } catch(error) {
      console.error('workspace request rejected',error.message);
      return Response.json({error:error.status?error.message:'Workspace service is unavailable.'},{status:error.status||503});
    }
  };
}
export async function rateLimit(key,limit=10,seconds=900) {
  const {rows}=await database().query(`INSERT INTO inspector_rate_limits(key,count,expires_at) VALUES($1,1,now()+$2*interval '1 second')
    ON CONFLICT(key) DO UPDATE SET count=CASE WHEN inspector_rate_limits.expires_at<now() THEN 1 ELSE inspector_rate_limits.count+1 END,
    expires_at=CASE WHEN inspector_rate_limits.expires_at<now() THEN excluded.expires_at ELSE inspector_rate_limits.expires_at END RETURNING count`,[hashToken(key),seconds]);
  if(rows[0].count>limit) throw Object.assign(new Error('Too many attempts. Please try again later.'),{status:429});
}
