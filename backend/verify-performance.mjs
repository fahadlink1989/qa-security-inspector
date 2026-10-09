import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import chromium from '@sparticuz/chromium';
import {chromium as playwright} from 'playwright-core';
export async function verifyPerformance(base){
  const email='qa-speed-'+crypto.randomUUID()+'@example.test',password=crypto.randomBytes(24).toString('base64url');
  const db=new pg.Client({connectionString:process.env.DATABASE_URL});await db.connect();let browser;
  try{
    browser=await playwright.launch({args:chromium.args.filter(a=>a!=='--disable-web-security'),executablePath:await chromium.executablePath(),headless:true});
    const page=await browser.newPage();
    await page.goto(base+'/login',{waitUntil:'networkidle'});
    await page.getByRole('button',{name:'Create a new workspace',exact:true}).click();
    await page.getByLabel('Workspace name').fill('Performance verification');await page.getByLabel('Email',{exact:true}).fill(email);await page.getByLabel('Password',{exact:true}).fill(password);
    await page.getByRole('button',{name:'Create workspace',exact:true}).click();await page.waitForURL(base+'/');
    await page.getByRole('button',{name:'Add your first target',exact:true}).click();await page.getByLabel('Target name',{exact:true}).fill('Inspector performance QA');await page.getByLabel('Target URL',{exact:true}).fill('https://qa-security-inspector.vercel.app');await page.getByRole('button',{name:'Add Target',exact:true}).click();
    await page.getByRole('heading',{name:'Targets',exact:true}).waitFor();
    const read=async()=>await (await page.request.get(base+'/api/workspace')).json();let state=await read();const projectId=state.projects[0].id,assetId=state.projects[0].assets[0].id;
    const post=data=>page.request.post(base+'/api/performance',{headers:{origin:base},data});
    assert.equal((await post({projectId,assetId})).status(),400,'authorization is required');
    const testKey=crypto.randomBytes(30).toString('base64url');assert.equal((await post({action:'configure',key:testKey})).status(),200);
    state=await read();assert.equal(state.workspace.performanceKeyConfigured,true);assert.equal(state.workspace.performanceKey,undefined);assert.ok(!JSON.stringify(state).includes(testKey),'API key must not be exposed');
    assert.equal((await post({action:'configure',key:''})).status(),200);
    await page.reload({waitUntil:'networkidle'});await page.locator('nav').getByRole('button',{name:/Targets/}).click();
    await page.getByRole('button',{name:'Speed',exact:true}).click();const panel=page.getByRole('dialog',{name:'Website performance'});await panel.waitFor();assert.equal(await panel.getByRole('button',{name:'Measure mobile & desktop'}).isDisabled(),true);
    await panel.getByRole('checkbox').check();await panel.getByRole('button',{name:'Measure mobile & desktop'}).click();
    let run;
    for(let i=0;i<100;i++){state=await read();run=state.projects[0].performanceScans?.[0];if(run)break;await new Promise(r=>setTimeout(r,4000));}
    assert.ok(run,'real provider result must persist');assert.deepEqual(Object.keys(run.devices).sort(),['desktop','mobile']);
    for(const d of Object.values(run.devices)){if(d.status==='completed'){assert.equal(d.provider,'Google PageSpeed Insights');assert.ok(Number.isFinite(d.score));}else{assert.equal(d.score,undefined);assert.ok(d.error);}}
    await page.reload({waitUntil:'networkidle'});await page.locator('nav').getByRole('button',{name:/Targets/}).click();await page.getByRole('button',{name:'Speed',exact:true}).click();await page.getByRole('button',{name:'Desktop',exact:true}).click();await page.getByLabel('Measurement history',{exact:true}).waitFor();
    console.log('PERFORMANCE_QA_PASS',JSON.stringify({status:run.status,devices:Object.fromEntries(Object.entries(run.devices).map(([k,d])=>[k,{status:d.status,score:d.score??null,httpStatus:d.httpStatus??null}])),authorization:true,keyEncryptedAndRedacted:true,persistence:true,browser:true}));
  }finally{
    await browser?.close();const {rows}=await db.query('SELECT id FROM inspector_users WHERE email=$1',[email]);
    for(const u of rows){const memberships=await db.query('SELECT workspace_id FROM inspector_memberships WHERE user_id=$1',[u.id]);await db.query('BEGIN');try{await db.query('DELETE FROM inspector_sessions WHERE user_id=$1',[u.id]);await db.query('DELETE FROM inspector_memberships WHERE user_id=$1',[u.id]);await db.query('DELETE FROM inspector_users WHERE id=$1',[u.id]);for(const m of memberships.rows){await db.query('DELETE FROM inspector_jobs WHERE workspace_id=$1',[m.workspace_id]);await db.query('DELETE FROM inspector_workspaces WHERE id=$1',[m.workspace_id]);}await db.query('COMMIT');}catch(e){await db.query('ROLLBACK');throw e;}}
    await db.end();
  }
}
