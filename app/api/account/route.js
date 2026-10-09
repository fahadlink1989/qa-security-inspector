import crypto from 'node:crypto';
import { database, transaction } from '../../../lib/backend/db';
import { COOKIE, checkOrigin, rateLimit, session, sessionToken } from '../../../lib/backend/auth';
import { hashToken, passwordHash, passwordMatches } from '../../../lib/backend/crypto';
import { initialState } from '../../../lib/store';
export const runtime='nodejs';
export const dynamic='force-dynamic';
const cookie=(token,age=604800)=>`${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${age}${process.env.NODE_ENV==='production'?'; Secure':''}`;
export async function GET(request) {
  try { const account=await session(request); return Response.json({account},{status:account?200:401,headers:{'cache-control':'no-store'}}); }
  catch { return Response.json({error:'Account service is unavailable.'},{status:503}); }
}
export async function POST(request) {
  try {
    checkOrigin(request);
    const body=await request.json();
    if(['create_workspace','switch_workspace'].includes(body.action)) {
      const account=await session(request);
      if(!account)return Response.json({error:'Sign in to manage workspaces.'},{status:401});
      let workspaceId;
      if(body.action==='create_workspace') {
        const name=String(body.name||'').trim();
        if(!name||name.length>100)return Response.json({error:'Enter a workspace name of 1–100 characters.'},{status:400});
        await rateLimit('workspace-create:'+account.userId,20,86400);
        workspaceId=await transaction(async client=>{
          const id=crypto.randomUUID();
          await client.query('INSERT INTO inspector_workspaces(id,name,state) VALUES($1,$2,$3)',[id,name,JSON.stringify(initialState(id,name))]);
          await client.query("INSERT INTO inspector_memberships(workspace_id,user_id,role) VALUES($1,$2,'owner')",[id,account.userId]);
          await client.query('UPDATE inspector_sessions SET workspace_id=$1 WHERE token_hash=$2 AND user_id=$3',[id,hashToken(sessionToken(request)),account.userId]);
          return id;
        });
      } else {
        const updated=await database().query(`UPDATE inspector_sessions s SET workspace_id=m.workspace_id FROM inspector_memberships m
          WHERE s.token_hash=$1 AND s.user_id=$2 AND m.user_id=s.user_id AND m.workspace_id=$3 RETURNING s.workspace_id`,[hashToken(sessionToken(request)),account.userId,body.workspaceId]);
        if(!updated.rowCount)return Response.json({error:'Workspace not found or access denied.'},{status:403});
        workspaceId=updated.rows[0].workspace_id;
      }
      return Response.json({workspaceId},{headers:{'cache-control':'no-store'}});
    }
    if(body.action==='logout') {
      await database().query('DELETE FROM inspector_sessions WHERE token_hash=$1',[hashToken(sessionToken(request))]);
      return Response.json({ok:true},{headers:{'set-cookie':cookie('',0)}});
    }
    const email=String(body.email||'').trim().toLowerCase();
    const password=String(body.password||'');
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>254||password.length<12||password.length>128) {
      return Response.json({error:'Enter a valid email and a password of 12–128 characters.'},{status:400});
    }
    await rateLimit('account:'+email,15);
    // Global cap also prevents attackers bypassing per-email limits with random addresses.
    await rateLimit('account:global',300,900);
    const token=crypto.randomBytes(32).toString('base64url');
    let account;
    if(body.action==='register') {
      const encoded=await passwordHash(password);
      account=await transaction(async client=>{
        const userId=crypto.randomUUID(),workspaceId=crypto.randomUUID();
        const name=String(body.workspaceName||'Inspector Workspace').trim().slice(0,100)||'Inspector Workspace';
        await client.query('INSERT INTO inspector_users(id,email,password_hash) VALUES($1,$2,$3)',[userId,email,encoded]);
        await client.query('INSERT INTO inspector_workspaces(id,name,state) VALUES($1,$2,$3)',[workspaceId,name,JSON.stringify(initialState(workspaceId,name))]);
        await client.query("INSERT INTO inspector_memberships(workspace_id,user_id,role) VALUES($1,$2,'owner')",[workspaceId,userId]);
        await client.query("INSERT INTO inspector_sessions(token_hash,user_id,workspace_id,expires_at) VALUES($1,$2,$3,now()+interval '7 days')",[hashToken(token),userId,workspaceId]);
        return {userId,workspaceId,email,name,role:'owner'};
      });
    } else if(body.action==='login') {
      const {rows}=await database().query(`SELECT u.*,m.workspace_id,w.name,m.role FROM inspector_users u
        JOIN inspector_memberships m ON m.user_id=u.id JOIN inspector_workspaces w ON w.id=m.workspace_id WHERE u.email=$1 ORDER BY w.created_at LIMIT 1`,[email]);
      const user=rows[0];
      // Perform the KDF even for unknown accounts to reduce account-enumeration timing.
      const valid=await passwordMatches(password,user?.password_hash||('0'.repeat(32)+':'+ '0'.repeat(128)));
      if(!user||!valid) return Response.json({error:'Email or password is incorrect.'},{status:401});
      await database().query("INSERT INTO inspector_sessions(token_hash,user_id,workspace_id,expires_at) VALUES($1,$2,$3,now()+interval '7 days')",[hashToken(token),user.id,user.workspace_id]);
      account={userId:user.id,workspaceId:user.workspace_id,email,name:user.name,role:user.role};
    } else return Response.json({error:'Unknown account action.'},{status:400});
    return Response.json({account},{headers:{'set-cookie':cookie(token),'cache-control':'no-store'}});
  } catch(error) {
    const status=error.status||(error.code==='23505'?409:503);
    return Response.json({error:error.status?error.message:error.code==='23505'?'An account already exists for this email. Sign in instead.':'Account service is unavailable.'},{status});
  }
}
