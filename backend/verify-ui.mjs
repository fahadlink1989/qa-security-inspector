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
    assert.ok((await page.getByLabel('Target',{exact:true}).locator('option:checked').textContent()).includes('Inspector QA target'));
    await page.getByRole('button',{name:'Cancel',exact:true}).click();
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
