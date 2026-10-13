import {test} from 'node:test';
import assert from 'node:assert/strict';
import {currentRiskRows,carryRiskLifecycle,priorRiskSnapshot,updateRiskDetails} from '../lib/riskModel.mjs';
import {isPublicAddress,validateWebhookUrl} from '../lib/publicAddress.mjs';
const finding={fingerprint:'header-rule',severity:'High',workflowStatus:'open'};
const scan=(id,date,findings=[{...finding}],mode='standard')=>({id,projectId:'p',assetId:'a',completedAt:date,status:'completed',mode,findings});
test('scan profiles share one risk; clean scan retains accepted decisions and evidence',()=>{
 const old=scan('old','2026-01-01',[{...finding,workflowStatus:'accepted',owner:'Security'}]);
 const newer=scan('new','2026-02-01',[{...finding,workflowStatus:'accepted'}],'deep');
 const clean=scan('clean','2026-03-01',[]);
 const rows=currentRiskRows([clean,newer,old],{});
 assert.equal(rows.length,1);assert.equal(rows[0].workflowStatus,'accepted');assert.equal(rows[0].firstSeen,'2026-01-01');assert.equal(rows[0].lastSeen,'2026-02-01');assert.equal(rows[0].coverageUnverified,true);
});
test('reopening and remediation survive a scan that did not observe the finding',()=>{
 const old=scan('old','2026-01-01',[{...finding,workflowStatus:'resolved',owner:'Engineering',notes:'SEC-123',firstSeen:'2026-01-01',workflowHistory:[{from:'open',to:'resolved',at:'2026-01-02'}]}]);
 const clean=scan('clean','2026-02-01',[]),again=scan('again','2026-03-01');
 carryRiskLifecycle(again,priorRiskSnapshot([clean,old],again));
 assert.equal(again.findings[0].workflowStatus,'open');assert.equal(again.findings[0].notes,'SEC-123');assert.equal(again.findings[0].owner,'Engineering');assert.equal(again.findings[0].workflowHistory.at(-1).from,'resolved');
});
test('workflow update affects both profiles, never another target',()=>{
 const a=scan('a','2026-01-01'),b=scan('b','2026-01-02',undefined,'deep'),other={...scan('c','2026-01-03'),assetId:'other'};
 const state={projects:[{id:'p'}],scans:[a,b,other]};
 updateRiskDetails(state,{kind:'web',projectId:'p',scanId:'a',fingerprint:finding.fingerprint,status:'resolved'},'test');
 assert.equal(b.findings[0].workflowStatus,'resolved');assert.equal(other.findings[0].workflowStatus,'open');
});
test('failed scans do not replace last observed evidence',()=>{
 const old=scan('old','2026-01-01'),failed={...scan('fail','2026-02-01',[]),status:'failed'};
 assert.equal(currentRiskRows([failed,old],{})[0]._scan.id,'old');
});
test('webhook address policy rejects special-use and alternate IP forms',()=>{
 for(const ip of ['127.0.0.1','10.1.1.1','100.64.0.1','169.254.169.254','192.168.0.1','172.31.1.1','198.19.0.1','203.0.113.1','239.1.1.1','255.255.255.255','::1','::ffff:127.0.0.1','fc00::1','fe80::1','2001:db8::1','2002:7f00:1::'])assert.equal(isPublicAddress(ip),false,ip);
 for(const url of ['http://example.com','https://user:pass@example.com','https://example.com:8443','https://127.1','https://2130706433','https://[::ffff:127.0.0.1]'])assert.throws(()=>validateWebhookUrl(url),url);
 assert.equal(isPublicAddress('8.8.8.8'),true);assert.equal(isPublicAddress('2606:4700:4700::1111'),true);assert.equal(validateWebhookUrl('https://example.com/hook').hostname,'example.com');
});
