import crypto from 'node:crypto';
import {emailConfigured,enqueueEmail,publicAppUrl} from '../../../lib/backend/email';
import {withWorkspace,rateLimit} from '../../../lib/backend/auth';
import {workspaceContext} from '../../../lib/backend/context';
import {database,transaction} from '../../../lib/backend/db';
import {hashToken} from '../../../lib/backend/crypto';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export const GET=withWorkspace(async()=>{
  const account=workspaceContext();
  const members=await database().query('SELECT u.id,u.email,m.role FROM inspector_memberships m JOIN inspector_users u ON u.id=m.user_id WHERE m.workspace_id=$1 ORDER BY u.email',[account.workspaceId]);
  const invites=account.role==='owner'?await database().query('SELECT id,email,role,created_at,expires_at,accepted_at,revoked_at FROM inspector_invitations WHERE workspace_id=$1 ORDER BY created_at DESC LIMIT 100',[account.workspaceId]):{rows:[]};
  const events=account.role==='owner'?await database().query('SELECT e.action,e.detail,e.created_at,u.email AS actor FROM inspector_account_events e LEFT JOIN inspector_users u ON u.id=e.actor_id WHERE e.workspace_id=$1 ORDER BY e.id DESC LIMIT 50',[account.workspaceId]):{rows:[]};
  const recovery=await database().query('SELECT created_at FROM inspector_recovery_codes WHERE user_id=$1',[account.userId]);
  return Response.json({members:members.rows,invitations:invites.rows,events:events.rows,emailConfigured:emailConfigured(),recoveryConfigured:recovery.rowCount>0},{headers:{'cache-control':'no-store'}});
});
export const POST=withWorkspace(async request=>{
  const account=workspaceContext();if(account.role!=='owner')return Response.json({error:'Only workspace owners can manage team access.'},{status:403});
  try {
    const body=await request.json();await rateLimit('team:'+account.workspaceId,40,3600);
    let token,delivery;
    await transaction(async client=>{
      // Serialize owner actions and re-check membership inside the transaction.
      await client.query('SELECT id FROM inspector_workspaces WHERE id=$1 FOR UPDATE',[account.workspaceId]);
      const role=await client.query('SELECT role FROM inspector_memberships WHERE workspace_id=$1 AND user_id=$2',[account.workspaceId,account.userId]);
      if(role.rows[0]?.role!=='owner')throw new Error('Owner access required.');
      if(body.action==='invite'){
        const email=String(body.email||'').trim().toLowerCase();
        if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>254||!['member','viewer'].includes(body.role))throw new Error('Enter a valid email and select Member or Viewer.');
        const existing=await client.query('SELECT u.id FROM inspector_memberships m JOIN inspector_users u ON u.id=m.user_id WHERE m.workspace_id=$1 AND u.email=$2',[account.workspaceId,email]);
        if(existing.rowCount)throw new Error('This person already belongs to the workspace.');
        await client.query('UPDATE inspector_invitations SET revoked_at=now() WHERE workspace_id=$1 AND email=$2 AND accepted_at IS NULL AND revoked_at IS NULL',[account.workspaceId,email]);
        token=crypto.randomBytes(32).toString('base64url');
        await client.query("INSERT INTO inspector_invitations(id,workspace_id,email,role,token_hash,created_by,expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+interval '7 days')",[crypto.randomUUID(),account.workspaceId,email,body.role,hashToken(token),account.userId]);
        if(body.sendEmail===true){if(!emailConfigured())throw new Error('Email delivery is not configured. Create a link to share instead.');delivery=await enqueueEmail(client,{workspaceId:account.workspaceId,to:email,purpose:'invitation',subject:'Your Inspector workspace invitation',text:`You have been invited to join ${account.name} as ${body.role}. Open ${publicAppUrl()}/login#invite=${token} to accept. This link expires in seven days. If you did not expect this invitation, ignore this email.`});}
        await client.query("INSERT INTO inspector_account_events(workspace_id,actor_id,action,detail) VALUES($1,$2,'invitation_created',$3)",[account.workspaceId,account.userId,JSON.stringify({email,role:body.role})]);
      }else if(body.action==='revoke_invitation'){
        const r=await client.query('UPDATE inspector_invitations SET revoked_at=now() WHERE workspace_id=$1 AND id=$2 AND accepted_at IS NULL AND revoked_at IS NULL RETURNING email',[account.workspaceId,body.id]);
        if(!r.rowCount)throw new Error('Pending invitation not found.');
        await client.query("INSERT INTO inspector_account_events(workspace_id,actor_id,action,detail) VALUES($1,$2,'invitation_revoked',$3)",[account.workspaceId,account.userId,JSON.stringify({email:r.rows[0].email})]);
      }else if(['change_role','remove_member'].includes(body.action)){
        if(body.userId===account.userId)throw new Error('You cannot remove or change your own owner access.');
        const member=await client.query('SELECT m.role,u.email FROM inspector_memberships m JOIN inspector_users u ON u.id=m.user_id WHERE m.workspace_id=$1 AND m.user_id=$2 FOR UPDATE OF m',[account.workspaceId,body.userId]);
        if(!member.rowCount||member.rows[0].role==='owner')throw new Error('Select a non-owner member.');
        if(body.action==='change_role'){
          if(!['member','viewer'].includes(body.role))throw new Error('Invalid role.');
          await client.query('UPDATE inspector_memberships SET role=$3 WHERE workspace_id=$1 AND user_id=$2',[account.workspaceId,body.userId,body.role]);
        }else {
          await client.query('DELETE FROM inspector_memberships WHERE workspace_id=$1 AND user_id=$2',[account.workspaceId,body.userId]);
          await client.query('DELETE FROM inspector_sessions WHERE workspace_id=$1 AND user_id=$2',[account.workspaceId,body.userId]);
          await client.query('UPDATE inspector_invitations SET revoked_at=now() WHERE workspace_id=$1 AND email=$2 AND accepted_at IS NULL',[account.workspaceId,member.rows[0].email]);
        }
        await client.query('INSERT INTO inspector_account_events(workspace_id,actor_id,action,detail) VALUES($1,$2,$3,$4)',[account.workspaceId,account.userId,body.action,JSON.stringify({email:member.rows[0].email,role:body.role||null})]);
      }else throw new Error('Unknown team action.');
    });
    return Response.json({ok:true,token,delivery},{headers:{'cache-control':'no-store'}});
  }catch(error){return Response.json({error:error.status?error.message:error.code?'Team access could not be updated.':error.message},{status:error.status||400});}
});

