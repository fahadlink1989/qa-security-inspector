import {withWorkspace} from '../../../lib/backend/auth';
import {workspaceContext} from '../../../lib/backend/context';
import {database} from '../../../lib/backend/db';
import {emailConfigured} from '../../../lib/backend/email';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export const GET=withWorkspace(async()=>{
  const account=workspaceContext();if(account.role!=='owner')return Response.json({error:'Owner access required.'},{status:403});
  const db=database(),id=account.workspaceId;
  const [email,history,performance,workspace,heartbeat]=await Promise.all([
    db.query('SELECT purpose,status,created_at,accepted_at,delivered_at,last_error FROM inspector_email_outbox WHERE workspace_id=$1 ORDER BY created_at DESC LIMIT 20',[id]),
    db.query('SELECT kind,count(*)::int AS count FROM inspector_scan_history WHERE workspace_id=$1 GROUP BY kind',[id]),
    db.query("SELECT id,data->'devices' AS devices,data->>'status' AS status,recorded_at FROM inspector_scan_history WHERE workspace_id=$1 AND kind='performance' ORDER BY recorded_at DESC LIMIT 1",[id]),
    db.query("SELECT coalesce(length(state->'workspace'->>'performanceKey'),0)>0 AS key_configured FROM inspector_workspaces WHERE id=$1",[id]),
    db.query("SELECT last_seen FROM inspector_worker_heartbeats WHERE id='consumer'")
  ]);
  const p=performance.rows[0];
  return Response.json({email:{configured:emailConfigured(),deliveryTrackingConfigured:Boolean(process.env.RESEND_WEBHOOK_SECRET),recent:email.rows},history:{storage:'PostgreSQL per-scan records',counts:history.rows},worker:{lastSeen:heartbeat.rows[0]?.last_seen||null},pageSpeed:{configured:Boolean(process.env.PAGESPEED_API_KEY||workspace.rows[0]?.key_configured),lastVerification:p?{id:p.id,at:p.recorded_at,status:p.status,mobile:p.devices?.mobile?.status,desktop:p.devices?.desktop?.status,errors:Object.values(p.devices||{}).filter(d=>d.status!=='completed').map(d=>d.error)}:null}},{headers:{'cache-control':'no-store'}});
});
