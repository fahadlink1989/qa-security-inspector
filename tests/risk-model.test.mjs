import assert from 'node:assert/strict';
import {currentRiskRows,retestOutcome,applyWorkflow,carryRiskLifecycle,coverageState,updateRiskDetails} from '../lib/riskModel.mjs';
const f={fingerprint:'shared-rule',severity:'High'};
const scan=(id,assetId,extra={})=>({id,assetId,projectId:'p',status:'completed',completedAt:'2026-10-09',findings:[{...f}],...extra});
assert.equal(currentRiskRows([scan('a','one'),scan('b','two')],{}).length,2,'same rule on two targets stays distinct');
assert.equal(currentRiskRows([scan('a','one'),scan('b','one',{mode:'deep'})],{}).length,2,'web scan does not erase deep coverage');
assert.equal(currentRiskRows([],{authScans:[scan('a','one'),scan('b','two')],codeScans:[scan('c',null,{repositoryUrl:'https://github.com/a/a'}),scan('d',null,{repositoryUrl:'https://github.com/a/b'})]}).length,4);
assert.equal(retestOutcome({status:'completed_with_gaps',findings:[]},'shared-rule'),'inconclusive');
assert.equal(retestOutcome({status:'completed',findings:[],engineRuns:[{status:'skipped'}]},'shared-rule'),'inconclusive');
assert.equal(retestOutcome({status:'completed',findings:[]},'shared-rule'),'resolved');
assert.equal(retestOutcome({status:'completed_with_gaps',findings:[f]},'shared-rule'),'still_present');
const finding={...f};applyWorkflow(finding,'accepted');assert.equal(finding.workflowHistory.length,1);applyWorkflow(finding,'accepted');assert.equal(finding.workflowHistory.length,1);assert.throws(()=>applyWorkflow(finding,'invalid'));
console.log('8 risk lifecycle regression checks passed');

const rerun=carryRiskLifecycle(scan('new','one'),{completedAt:'2026-01-01',findings:[{...f,workflowStatus:'accepted',firstSeen:'2026-01-01'}]});
assert.equal(rerun.findings[0].workflowStatus,'accepted');
assert.equal(rerun.findings[0].firstSeen,'2026-01-01');
assert.equal(carryRiskLifecycle(scan('new','one'),{findings:[{...f,workflowStatus:'resolved'}]}).findings[0].workflowStatus,'open');
console.log('Rescan lifecycle regression checks passed');

const retained=currentRiskRows([scan('new','one',{completedAt:'2026-10-10',status:'completed_with_gaps',findings:[]}),scan('old','one')],{});
assert.equal(retained.length,1,'incomplete scan must not erase prior risks');
assert.equal(retained[0].coverageUnverified,true);
assert.equal(currentRiskRows([scan('new','one',{completedAt:'2026-10-10',findings:[]}),scan('old','one')],{}).length,0);
console.log('Incomplete scan risk retention passed');

const state={projects:[{id:'p'}],scans:[scan('new','one'),scan('old','one'),scan('other','two')]};
updateRiskDetails(state,{projectId:'p',kind:'web',scanId:'new',fingerprint:'shared-rule',owner:'Platform',notes:'Ticket SEC-12',status:'in_progress'},'u');
assert.equal(state.scans[1].findings[0].owner,'Platform');
assert.equal(state.scans[2].findings[0].owner,undefined,'workflow must not cross targets');
assert.throws(()=>updateRiskDetails(state,{projectId:'different',kind:'web',scanId:'new'},'u'));
assert.equal(carryRiskLifecycle(scan('next','one'),state.scans[0]).findings[0].notes,'Ticket SEC-12');
assert.equal(coverageState(scan('a','one',{engineRuns:[{engine:'zap',status:'failed'}]})).complete,false);
const closed=scan('old','one',{findings:[{...f,workflowStatus:'resolved',retests:[{status:'resolved'}]}]});
assert.equal(currentRiskRows([scan('new','one',{completedAt:'2026-10-10',findings:[]}),closed],{})[0].workflowStatus,'resolved');
console.log('Owner scope, persistence, coverage and verified closure checks passed');
