const assert=require('node:assert/strict');
const {chromium}=require('playwright-core');
const binary=require('@sparticuz/chromium').default;
(async()=>{
let server;
if(process.env.START_QA_SERVER==='1'){const app=require('next')({dev:false,dir:process.cwd()});await app.prepare();server=require('node:http').createServer(app.getRequestHandler());await new Promise(r=>server.listen(3002,'127.0.0.1',r));}
const browser=await chromium.launch({executablePath:process.env.BROWSER_EXECUTABLE||await binary.executablePath(),args:process.env.BROWSER_EXECUTABLE?['--no-sandbox','--disable-gpu','--disable-software-rasterizer','--no-zygote']:binary.args,headless:true});
const page=await browser.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
const scan={id:'s',projectId:'p',assetId:'a',mode:'deep',status:'completed',score:0,completedAt:'2026-10-08T00:00:00Z',url:'https://example.com',findings:[{id:'f',fingerprint:'fp',title:'Header missing',severity:'High',summary:'Observed missing header',evidence:'Response header absent',remediation:'Configure header',firstSeen:'2026-10-07',lastSeen:'2026-10-08'}],engineRuns:[{engine:'inspector',status:'completed',findingCount:1}],evidence:{deep:{liveHosts:[{hostname:'app.example.com',url:'https://app.example.com',status:200}]}}};
const data={projects:[{id:'p',name:'QA Workspace',schedule:'manual',assets:[{id:'a',label:'Example',url:'https://example.com',createdAt:'2026-10-07'}]}],scans:[scan],jobs:[],workspace:{}};const posts=[];
await page.route('**/api/workspace',async route=>{
if(route.request().method()==='POST'){const body=route.request().postDataJSON();posts.push(body);if(body.action==='update_asset')data.projects[0].assets[0].label=body.patch.label;if(body.action==='risk_update')Object.assign(scan.findings[0],{workflowStatus:body.patch.status||scan.findings[0].workflowStatus,owner:body.patch.owner||scan.findings[0].owner});return route.fulfill({json:{result:{}}});}return route.fulfill({json:data});});
await page.route('**/api/engine-status',route=>route.fulfill({json:{builtIn:[],worker:{configured:false,engines:[{id:'zap',name:'OWASP ZAP',status:'not configured'}]}}}));
await page.goto(process.env.BASE_URL||'http://127.0.0.1:3000');await page.getByRole('button',{name:'Skip',exact:true}).click();
await page.locator('.primaryNav button').filter({hasText:'Targets'}).click();await page.getByRole('button',{name:'Example https://example.com'}).click();
await page.getByRole('textbox',{name:'Label',exact:true}).fill('Updated target');await page.getByRole('button',{name:'Save label',exact:true}).click();await page.waitForTimeout(200);assert.equal(posts.at(-1).action,'update_asset');assert.ok(await page.getByText('app.example.com ·').count());
await page.locator('.riskDrawer .drawerTop button').click();await page.locator('.primaryNav button').filter({hasText:'Scans'}).click();await page.getByRole('button',{name:/Details/}).click();await page.getByText('Preview scan report').waitFor();await page.locator('.riskDrawer .drawerTop button').click();
await page.locator('.primaryNav button').filter({hasText:'Risks'}).click();await page.getByRole('button',{name:/Header missing/}).first().click();await page.getByRole('textbox',{name:'Owner',exact:true}).fill('AppSec');await page.getByRole('button',{name:'Save owner',exact:true}).click();await page.waitForTimeout(150);assert.equal(posts.at(-1).patch.owner,'AppSec');await page.locator('.riskDrawer .drawerTop button').click();
await page.locator('.primaryNav button').filter({hasText:'Reports'}).click();await page.getByRole('combobox',{name:'Severity',exact:true}).selectOption('High');assert.ok((await page.getByRole('link',{name:'Download PDF ⇩'}).getAttribute('href')).includes('severity=High'));
await page.getByRole('button',{name:'＋ New Scan',exact:true}).count().then(async n=>{if(!n)await page.locator('.primaryNav button').filter({hasText:'Scans'}).click()});await page.getByRole('button',{name:'＋ New Scan',exact:true}).first().click();assert.ok(await page.getByRole('checkbox',{name:'OWASP ZAP · not configured'}).isDisabled());assert.equal(errors.length,0,errors.join('\n'));
console.log('Browser journey passed: target edit/history/relationships, scan detail, risk owner, report filter, disabled unavailable engine; no page errors.');await browser.close();if(server)server.close();
})().catch(e=>{console.error(e);process.exit(1)});
