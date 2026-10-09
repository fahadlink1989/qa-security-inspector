import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
export async function verifyBackend(base) {
  const db=new pg.Client({connectionString:process.env.DATABASE_URL});await db.connect();
  const run=crypto.randomUUID(),accounts=[];
  const origin=(process.env.APP_ORIGINS||'http://localhost:3000').split(',')[0];
  const password=crypto.randomBytes(24).toString('base64url');
  let checks=0;
  const check=(value,message)=>{assert.ok(value,message);checks++;};
  async function request(path,body,cookie='',method=body?'POST':'GET'){
    const response=await fetch(base+path,{method,headers:{origin,'content-type':'application/json',cookie},body:body?JSON.stringify(body):undefined});
    const text=await response.text();let data;try{data=JSON.parse(text);}catch{data=text;}
    return {status:response.status,data,cookie:response.headers.get('set-cookie')?.split(';')[0]};
  }
  async function tick(schedule=false){const r=await fetch(base+'/api/internal/tick'+(schedule?'?schedule=1':''),{method:'POST',headers:{authorization:'Bearer '+process.env.INTERNAL_WORKER_SECRET}});check(r.ok,'consumer request succeeds');return r.json();}
  try {
    check((await request('/api/workspace')).status===401,'anonymous workspace denied');
    check((await request('/api/internal/tick',{})).status===401,'anonymous consumer denied');
    for(const suffix of ['a','b']){
      const r=await request('/api/account',{action:'register',email:`qa-${run}-${suffix}@example.test`,password,workspaceName:'Automated verification'});
      check(r.status===200,'registration succeeds');accounts.push({...r.data.account,cookie:r.cookie});
    }
    const [a,b]=accounts;
    const projectResponse=await request('/api/workspace',{action:'create_project',name:'Authorized QA target',url:'https://qa-security-inspector.vercel.app'},a.cookie);
    check(projectResponse.status===200,'target creation succeeds');
    const project=projectResponse.data.result;
    const additions=await Promise.all(Array.from({length:12},(_,i)=>request('/api/workspace',{action:'add_asset',projectId:project.id,url:'https://qa-security-inspector.vercel.app/?qa='+i,label:'Concurrent '+i},a.cookie)));
    check(additions.every(r=>r.status===200),'parallel writes succeed');
    const state=(await request('/api/workspace',null,a.cookie)).data;
    check(state.projects[0].assets.length===13,'transactional writes preserve all concurrent changes');
    check((await request('/api/workspace',null,b.cookie)).data.projects.length===0,'workspace B cannot read A data');
    check((await request('/api/workspace',{action:'add_asset',projectId:project.id,url:'https://qa-security-inspector.vercel.app'},b.cookie)).status===400,'cross-workspace target mutation rejected');
    const csrf=await fetch(base+'/api/workspace',{method:'POST',headers:{cookie:a.cookie,origin:'https://untrusted.example','content-type':'application/json'},body:JSON.stringify({action:'create_project',url:'https://qa-security-inspector.vercel.app'})});
    check(csrf.status===403,'cross-origin mutation rejected');
    const queued=await request('/api/scan',{projectId:project.id,assetId:project.assets[0].id,authorized:true},a.cookie);
    check(queued.status===202&&queued.data.status==='queued','scan submission persists queued job');
    check((await request('/api/scan?jobId='+queued.data.id,null,b.cookie)).status===404,'job isolation enforced');
    const raw=(await db.query('SELECT payload FROM inspector_jobs WHERE id=$1',[queued.data.id])).rows[0];
    check(typeof raw.payload==='string'&&!raw.payload.startsWith('{'),'job payload encrypted');
    // Force an expired lease on a synthetic unsupported job; exercise recovery without scanning a target.
    await db.query("UPDATE inspector_jobs SET data=jsonb_set(data,'{type}','\"self-test-invalid\"'),status='running',lease_token=$2,lease_until=now()-interval '1 second',attempts=1 WHERE id=$1",[queued.data.id,crypto.randomUUID()]);
    await Promise.all([tick(),tick()]);
    let retried=(await db.query('SELECT * FROM inspector_jobs WHERE id=$1',[queued.data.id])).rows[0];
    check(retried.attempts===2&&retried.status==='queued','expired job claimed exactly once and retry persisted');
    await db.query("UPDATE inspector_jobs SET available_at=now()-interval '1 second' WHERE id=$1",[queued.data.id]);await tick();
    retried=(await db.query('SELECT * FROM inspector_jobs WHERE id=$1',[queued.data.id])).rows[0];
    check(retried.status==='failed'&&retried.payload===null,'retry exhaustion fails job and erases credentials');
    await db.query("UPDATE inspector_memberships SET role='viewer' WHERE user_id=$1",[b.userId]);
    check((await request('/api/workspace',{action:'create_project',url:'https://qa-security-inspector.vercel.app'},b.cookie)).status===403,'viewer mutation denied');
    check((await request('/api/workspace',{action:'update_project',projectId:project.id,patch:{schedule:'daily'}},a.cookie)).status===400,'schedule requires authorization');
    // Avoid thirteen scans: only the original asset remains active for scheduling checks.
    await db.query("UPDATE inspector_workspaces SET state=jsonb_set(state,'{projects,0,assets}',$2::jsonb) WHERE id=$1",[a.workspaceId,JSON.stringify([project.assets[0]])]);
    check((await request('/api/workspace',{action:'update_project',projectId:project.id,patch:{schedule:'daily',scheduleAuthorized:true}},a.cookie)).status===200,'authorized scheduling saved');
    await tick(true);await tick(true);
    const scheduled=await db.query("SELECT id FROM inspector_jobs WHERE workspace_id=$1 AND data->>'trigger'='schedule'",[a.workspaceId]);
    check(scheduled.rowCount===1,'schedule enqueue is idempotent');
    await db.query('DELETE FROM inspector_jobs WHERE id=$1',[scheduled.rows[0].id]);
    if(process.env.RUN_REAL_SCAN==='1'){
      const scan=await request('/api/scan',{projectId:project.id,assetId:project.assets[0].id,authorized:true},a.cookie);
      await tick();
      const completed=(await request('/api/scan?jobId='+scan.data.id,null,a.cookie)).data;
      check(['completed','completed_with_gaps'].includes(completed.status),'real web scan completes');
      const report=await request('/api/report?projectId='+project.id+'&format=csv',null,a.cookie);
      check(report.status===200,'report export reads persisted scan');
      const saved=(await request('/api/workspace',null,a.cookie)).data.scans.find(s=>s.id===scan.data.id);
      check(saved?.engineRuns?.some(e=>e.engine==='zap'&&e.status==='completed'),'ZAP produces real results');
      console.log('BACKEND_REAL_SCAN',JSON.stringify({status:completed.status,findings:completed.findings,engines:saved.engineRuns.map(e=>({engine:e.engine,status:e.status}))}));
    }
    await request('/api/account',{action:'logout'},a.cookie);
    check((await request('/api/workspace',null,a.cookie)).status===401,'logout revokes session');
    console.log('BACKEND_VERIFICATION_PASS',checks,'checks');
  }finally{
    for(const account of accounts){
      await db.query('BEGIN');
      try{
        await db.query('DELETE FROM inspector_jobs WHERE workspace_id=$1',[account.workspaceId]);
        await db.query('DELETE FROM inspector_sessions WHERE user_id=$1',[account.userId]);
        await db.query('DELETE FROM inspector_memberships WHERE user_id=$1',[account.userId]);
        await db.query('DELETE FROM inspector_users WHERE id=$1',[account.userId]);
        await db.query('DELETE FROM inspector_workspaces WHERE id=$1',[account.workspaceId]);
        await db.query('COMMIT');
      }catch(e){await db.query('ROLLBACK');throw e;}
    }
    await db.end();
  }
}
