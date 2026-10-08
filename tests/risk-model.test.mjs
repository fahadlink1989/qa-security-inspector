import {test} from 'node:test';
import assert from 'node:assert/strict';
import {currentRiskRows,filterReportRows,updateRiskInState} from '../lib/riskModel.js';
const finding=(id)=>({fingerprint:id,severity:'High',workflowStatus:'open'});
const project={id:'p',assets:[{id:'a'},{id:'b'}],codeScans:[{id:'code',projectId:'p',repository:{url:'https://github.com/o/r'},findings:[finding('secret')]}]};
const state=()=>({projects:[structuredClone(project)],scans:[
{id:'deep',projectId:'p',assetId:'a',mode:'deep',completedAt:'2026-10-07',findings:[finding('deep-only'),finding('same')]},
{id:'baseline',projectId:'p',assetId:'a',mode:'standard',completedAt:'2026-10-08',findings:[finding('same')]},
{id:'other',projectId:'p',assetId:'b',mode:'standard',completedAt:'2026-10-08',findings:[finding('same')]}
]});
test('baseline preserves deep risks and identical fingerprints on other targets',()=>{
const s=state();assert.equal(currentRiskRows(s,s.projects[0]).length,4);
});
test('report filters scope target, severity and status',()=>{
const s=state();const rows=currentRiskRows(s,s.projects[0]);assert.equal(filterReportRows(rows,{assetId:'b',severity:'High',status:'open'}).length,1);assert.equal(filterReportRows(rows,{severity:'Low'}).length,0);
});
test('workflow persists across profiles without modifying another target',()=>{
const s=state();updateRiskInState(s,'baseline','same',{status:'accepted',owner:'Engineering'});assert.equal(s.scans[0].findings[1].workflowStatus,'accepted');assert.equal(s.scans[2].findings[0].workflowStatus,'open');assert.equal(s.scans[1].findings[0].owner,'Engineering');
});
test('code risks support status and owner with history',()=>{
const s=state();const f=updateRiskInState(s,'code','secret',{status:'in_progress',owner:'AppSec'});assert.equal(f.owner,'AppSec');assert.equal(f.actionHistory.length,1);assert.throws(()=>updateRiskInState(s,'code','secret',{status:'invalid'}));
});
