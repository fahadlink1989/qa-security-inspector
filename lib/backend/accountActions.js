import crypto from 'node:crypto';
import {database,transaction} from './db';
import {session,rateLimit,COOKIE} from './auth';
import {hashToken,passwordHash,passwordMatches} from './crypto';
const fail=(message,status=400)=>{throw Object.assign(new Error(message),{status});};
const validPassword=p=>{if(typeof p!=='string'||p.length<12||p.length>128)fail('Use a password of 12–128 characters.');};
export const newRecoveryCode=()=>crypto.randomBytes(24).toString('base64url');
export async function setRecoveryCode(client,userId,code){
  await client.query('INSERT INTO inspector_recovery_codes(user_id,token_hash) VALUES($1,$2) ON CONFLICT(user_id) DO UPDATE SET token_hash=excluded.token_hash,created_at=now()',[userId,hashToken(code)]);
}
export async function accountAction(request,body) {
  const action=body.action;
  if(!['recover','recovery_code','change_password','accept_invitation'].includes(action))return null;
  await rateLimit('sensitive-account:global',150,900);
  const email=String(body.email||'').trim().toLowerCase();
  if(action==='recover') {
    await rateLimit('recover:'+email,5,900);validPassword(body.password);
    const code=String(body.recoveryCode||'').trim();
    if(code.length>128)fail('Recovery details are invalid.');
    const encoded=await passwordHash(body.password);
    await transaction(async client=>{
      const {rows}=await client.query('SELECT u.id FROM inspector_users u JOIN inspector_recovery_codes r ON r.user_id=u.id WHERE u.email=$1 AND r.token_hash=$2 FOR UPDATE OF r',[email,hashToken(code)]);
      if(!rows.length)fail('Recovery details are invalid or this code has already been used.',401);
      await client.query('UPDATE inspector_users SET password_hash=$2 WHERE id=$1',[rows[0].id,encoded]);
      await client.query('DELETE FROM inspector_recovery_codes WHERE user_id=$1',[rows[0].id]);
      await client.query('DELETE FROM inspector_sessions WHERE user_id=$1',[rows[0].id]);
      await client.query("INSERT INTO inspector_account_events(actor_id,action) VALUES($1,'account_recovered')",[rows[0].id]);
    });
    return Response.json({ok:true,message:'Password reset. Sign in and generate a new recovery code.'},{headers:{'cache-control':'no-store'}});
  }
  if(action==='accept_invitation') {
    const token=String(body.token||'');if(token.length>128||token.length<20)fail('Invalid invitation.');
    await rateLimit('invite-accept:'+hashToken(token),10,900);
    const account=await session(request);
    if(!account)validPassword(body.password);
    const encoded=account?null:await passwordHash(body.password),sessionValue=crypto.randomBytes(32).toString('base64url');
    let recoveryCode;
    await transaction(async client=>{
      const {rows}=await client.query('SELECT * FROM inspector_invitations WHERE token_hash=$1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now() FOR UPDATE',[hashToken(token)]);
      const invite=rows[0];if(!invite)fail('This invitation has expired or is no longer available.');
      let userId=account?.userId;
      if(account){if(account.email!==invite.email)fail('Sign in with the email address invited to this workspace.',403);}
      else {
        if(email!==invite.email)fail('Use the email address that was invited.',403);
        const exists=await client.query('SELECT id,password_hash FROM inspector_users WHERE email=$1 FOR UPDATE',[email]);
        if(exists.rowCount){
          if(!await passwordMatches(body.password,exists.rows[0].password_hash))fail('Use your existing account password to accept this invitation.',401);
          userId=exists.rows[0].id;
        }else{
          userId=crypto.randomUUID();await client.query('INSERT INTO inspector_users(id,email,password_hash) VALUES($1,$2,$3)',[userId,email,encoded]);
          recoveryCode=newRecoveryCode();await setRecoveryCode(client,userId,recoveryCode);
        }
      }
      // Existing membership is never promoted or demoted by a stale invite.
      await client.query('INSERT INTO inspector_memberships(workspace_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',[invite.workspace_id,userId,invite.role]);
      await client.query('UPDATE inspector_invitations SET accepted_at=now() WHERE id=$1',[invite.id]);
      await client.query("INSERT INTO inspector_sessions(token_hash,user_id,workspace_id,expires_at) VALUES($1,$2,$3,now()+interval '7 days')",[hashToken(sessionValue),userId,invite.workspace_id]);
      await client.query("INSERT INTO inspector_account_events(workspace_id,actor_id,action,detail) VALUES($1,$2,'invitation_accepted',$3)",[invite.workspace_id,userId,JSON.stringify({role:invite.role})]);
    });
    return Response.json({ok:true,recoveryCode},{headers:{'cache-control':'no-store','set-cookie':`${COOKIE}=${sessionValue}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800${process.env.NODE_ENV==='production'?'; Secure':''}`}});
  }
  const account=await session(request);if(!account)fail('Sign in first.',401);
  await rateLimit('account-security:'+account.userId,10,900);
  if(typeof body.currentPassword!=='string'||body.currentPassword.length>128)fail('Enter your current password.');
  const code=action==='recovery_code'?newRecoveryCode():null;
  if(action==='change_password')validPassword(body.password);
  const encoded=action==='change_password'?await passwordHash(body.password):null;
  await transaction(async client=>{
    const {rows}=await client.query('SELECT password_hash FROM inspector_users WHERE id=$1 FOR UPDATE',[account.userId]);
    if(!await passwordMatches(body.currentPassword,rows[0].password_hash))fail('Current password is incorrect.',401);
    if(code) await setRecoveryCode(client,account.userId,code);
    else {
      await client.query('UPDATE inspector_users SET password_hash=$2 WHERE id=$1',[account.userId,encoded]);
      await client.query('DELETE FROM inspector_sessions WHERE user_id=$1',[account.userId]);
      await client.query('DELETE FROM inspector_recovery_codes WHERE user_id=$1',[account.userId]);
    }
    await client.query('INSERT INTO inspector_account_events(workspace_id,actor_id,action) VALUES($1,$2,$3)',[account.workspaceId,account.userId,action]);
  });
  return Response.json({ok:true,recoveryCode:code,message:code?'Save this code securely. It replaces any previous recovery code.':'Password changed. Sign in again and create a new recovery code.'},{headers:{'cache-control':'no-store'}});
}
