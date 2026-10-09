import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import chromium from '@sparticuz/chromium';
import { chromium as playwright } from 'playwright-core';
export async function verifyUI(base){
  const email='qa-ui-'+crypto.randomUUID()+'@example.test';
  const password=crypto.randomBytes(24).toString('base64url');
  const db=new pg.Client({connectionString:process.env.DATABASE_URL});await db.connect();
  let browser;
  try {
    browser=await playwright.launch({args:chromium.args.filter(arg=>arg!=='--disable-web-security'),executablePath:await chromium.executablePath(),headless:true});
    const page=await browser.newPage();
    page.on('request',request=>{if(request.url().endsWith('/api/account'))console.log('BROWSER_ACCOUNT_REQUEST',JSON.stringify({origin:request.headers().origin||null,url:request.url()}));});
    page.on('response',async response=>{if(response.url().endsWith('/api/account')&&!response.ok())console.log('BROWSER_ACCOUNT_ERROR',response.status(),await response.text());});
    await page.goto(base+'/login',{waitUntil:'networkidle',timeout:60000});
    await page.getByRole('button',{name:'Create a new workspace',exact:true}).click();
    await page.getByLabel('Workspace name').fill('UI verification');
    await page.getByLabel('Email',{exact:true}).fill(email);
    await page.getByLabel('Password',{exact:true}).fill(password);
    await page.getByRole('button',{name:'Create workspace',exact:true}).click();
    await page.waitForURL(base+'/',{timeout:30000});
    await page.getByRole('heading',{name:'Dashboard',exact:true}).waitFor();
    const workspace=await page.request.get(base+'/api/workspace');
    assert.equal(workspace.status(),200);assert.equal((await workspace.json()).projects.length,0);
    assert.equal(await page.getByLabel('Workspace',{exact:true}).locator('option:checked').textContent(),'UI verification');
    await page.getByRole('button',{name:'Add your first target',exact:true}).click();
    await page.getByLabel('Target name',{exact:true}).fill('Inspector QA target');
    await page.getByLabel('Target URL',{exact:true}).fill('https://qa-security-inspector.vercel.app');
    await page.getByRole('button',{name:'Add Target',exact:true}).click();
    await page.getByRole('heading',{name:'Targets',exact:true}).waitFor();
    await page.getByText('Inspector QA target',{exact:true}).waitFor();
    await page.reload({waitUntil:'networkidle'});
    assert.equal(await page.getByLabel('Workspace',{exact:true}).locator('option:checked').textContent(),'UI verification');
    let snapshot=await (await page.request.get(base+'/api/workspace')).json();
    assert.equal(snapshot.projects[0].assets[0].label,'Inspector QA target');
    const firstWorkspace=snapshot.workspace.id;
    const denied=await page.request.post(base+'/api/account',{headers:{origin:base},data:{action:'switch_workspace',workspaceId:crypto.randomUUID()}});
    assert.equal(denied.status(),403);
    await page.getByRole('button',{name:'＋ Create workspace',exact:true}).click();
    await page.getByLabel('Workspace name',{exact:true}).fill('Second QA workspace');
    await page.getByRole('button',{name:'Create workspace',exact:true}).click();
    await page.getByRole('heading',{name:'Second QA workspace is ready',exact:true}).waitFor();
    snapshot=await (await page.request.get(base+'/api/workspace')).json();
    assert.equal(snapshot.projects.length,0);
    await page.getByLabel('Workspace',{exact:true}).selectOption(firstWorkspace);
    await page.getByRole('heading',{name:'Dashboard',exact:true}).waitFor();
    await page.getByText('Security posture for UI verification.',{exact:true}).waitFor();
    snapshot=await (await page.request.get(base+'/api/workspace')).json();
    assert.equal(snapshot.workspace.id,firstWorkspace);assert.equal(snapshot.projects[0].assets[0].label,'Inspector QA target');
    await page.getByRole('button',{name:'＋ New Scan',exact:true}).click();
    await page.getByRole('heading',{name:'Choose what you want to test',exact:true}).waitFor();
    console.log('SCAN_SELECTOR_DIAGNOSTIC',JSON.stringify(await page.locator('.scanModal select').evaluateAll(items=>items.map(item=>({label:item.getAttribute('aria-label'),value:item.value,options:[...item.options].map(o=>({text:o.textContent,value:o.value,selected:o.selected}))})))));
    assert.equal(await page.locator('.scanModal select').first().inputValue(),snapshot.projects[0].assets[0].id,'scan wizard preselects saved target');
    await page.getByRole('button',{name:/Web App Scan/}).click();
    await page.getByRole('checkbox').check();
    await page.getByRole('button',{name:'Start Scan',exact:true}).click();
    await page.getByRole('heading',{name:'Scans',exact:true}).waitFor();
    let result;
    for(let attempt=0;attempt<150;attempt++){
      snapshot=await (await page.request.get(base+'/api/workspace')).json();
      result=snapshot.scans.find(s=>s.assetId===snapshot.projects[0].assets[0].id);
      if(result)break;
      const failed=snapshot.jobs.find(j=>j.status==='failed');
      if(failed)throw new Error('Real scan failed: '+failed.error);
      await new Promise(resolve=>setTimeout(resolve,4000));
    }
    assert.ok(result,'real authorized scan must produce a persisted result');
    await page.reload({waitUntil:'networkidle'});
    await page.locator('nav').getByRole('button',{name:/Targets/}).click();
    await page.getByRole('button',{name:/Inspector QA target/}).click();
    await page.getByRole('dialog',{name:'Target details'}).waitFor();
    await page.getByRole('button',{name:/Web App Scan/}).click();
    await page.getByRole('dialog',{name:'Scan details'}).waitFor();
    await page.getByRole('heading',{name:'Coverage and limitations'}).waitFor();
    const pdfLink=await page.getByRole('link',{name:'Download scan report'}).getAttribute('href');
    const pdf=await page.request.get(base+pdfLink);assert.equal(pdf.status(),200);assert.equal((await pdf.body()).subarray(0,4).toString(),'%PDF');
    await page.getByRole('button',{name:'Close scan details'}).click();
    assert.ok(result.findings.length,'the live QA target must expose a finding for remediation QA');
    if(result.findings.length){
      await page.locator('nav').getByRole('button',{name:/Risks/}).click();
      await page.getByRole('button',{name:'Review',exact:true}).first().click();
      await page.getByLabel('Owner or team',{exact:true}).fill('Platform QA');
      await page.getByLabel('Remediation notes',{exact:true}).fill('Review evidence and verify the deployed fix.');
      await page.getByRole('button',{name:'Save remediation details'}).click();
      await page.getByText('Risk updated. Changes are saved across this target’s scan history.',{exact:true}).waitFor();
      await page.getByRole('button',{name:'In progress',exact:true}).click();
      await page.waitForTimeout(1000);
      snapshot=await (await page.request.get(base+'/api/workspace')).json();
      const assigned=snapshot.scans.flatMap(s=>s.findings).find(f=>f.owner==='Platform QA');
      assert.equal(assigned.workflowStatus,'in_progress');
      assert.ok(assigned.notes.includes('Review evidence'));
      await page.getByRole('button',{name:'Retest finding',exact:true}).click();
      let verified=false;
      for(let attempt=0;attempt<150;attempt++){
        snapshot=await (await page.request.get(base+'/api/workspace')).json();
        const original=snapshot.scans.find(s=>s.id===result.id)?.findings.find(f=>f.fingerprint===assigned.fingerprint);
        if(original?.retests?.length){assert.ok(['still_present','resolved','inconclusive'].includes(original.retests.at(-1).status));verified=true;break;}
        await new Promise(resolve=>setTimeout(resolve,4000));
      }
      assert.ok(verified,'retest result must persist');
      await page.reload({waitUntil:'networkidle'});
    }
    for(const format of ['html','csv']){
      const report=await page.request.get(base+'/api/report?'+new URLSearchParams({projectId:snapshot.projects[0].id,format,section:'technical'}));
      assert.equal(report.status(),200);assert.ok((await report.text()).includes('Point-in-time assessment'));
    }
    await page.locator('nav').getByRole('button',{name:/Scans/}).click();
    await page.getByRole('button',{name:'＋ New Scan',exact:true}).click();
    await page.getByRole('button',{name:/Web App Scan/}).click();
    await page.getByLabel('When to run',{exact:true}).selectOption('daily');
    await page.getByRole('checkbox').check();
    await page.getByRole('button',{name:'Save schedule',exact:true}).click();
    await page.getByRole('button',{name:'Stop schedule',exact:true}).waitFor();
    snapshot=await (await page.request.get(base+'/api/workspace')).json();
    assert.equal(snapshot.projects[0].assets[0].schedule,'daily');
    await page.getByRole('button',{name:'Stop schedule',exact:true}).click();
    await page.getByText('Not scheduled',{exact:true}).waitFor();
    snapshot=await (await page.request.get(base+'/api/workspace')).json();
    assert.equal(snapshot.projects[0].assets[0].schedule,'manual');
    console.log('CUSTOMER_JOURNEY_PASS','real scan, target history, scan details, risk ownership/status persistence, real retest outcome, schedule create/stop, PDF/HTML/CSV coverage reports');
    await page.locator('nav').getByRole('button',{name:/Settings/}).click();
    await page.getByRole('button',{name:'Sign out',exact:true}).click();
    await page.waitForURL(base+'/login');
    await page.getByLabel('Email',{exact:true}).fill(email);
    await page.getByLabel('Password',{exact:true}).fill(password);
    await page.getByRole('button',{name:'Sign in',exact:true}).click();
    await page.waitForURL(base+'/',{timeout:30000});
    await page.getByRole('heading',{name:'Dashboard',exact:true}).waitFor();
    console.log('BROWSER_VERIFICATION_PASS',new URL(base).hostname,'signup workspace visible, first target saved, reload persistence, workspace creation/switching, scan target selection, logout/login');
  }finally{
    await browser?.close();
    const users=await db.query('SELECT id FROM inspector_users WHERE email=$1',[email]);
    for(const user of users.rows){
      const memberships=await db.query('SELECT workspace_id FROM inspector_memberships WHERE user_id=$1',[user.id]);
      await db.query('BEGIN');
      try{
        await db.query('DELETE FROM inspector_sessions WHERE user_id=$1',[user.id]);
        await db.query('DELETE FROM inspector_memberships WHERE user_id=$1',[user.id]);
        await db.query('DELETE FROM inspector_users WHERE id=$1',[user.id]);
        for(const membership of memberships.rows){await db.query('DELETE FROM inspector_jobs WHERE workspace_id=$1',[membership.workspace_id]);await db.query('DELETE FROM inspector_workspaces WHERE id=$1',[membership.workspace_id]);}
        await db.query('COMMIT');
      }catch(error){await db.query('ROLLBACK');throw error;}
    }
    await db.end();
  }
}
