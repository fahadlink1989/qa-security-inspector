import assert from 'node:assert/strict';
import {currentRiskRows,retestOutcome,applyWorkflow,carryRiskLifecycle} from '../lib/riskModel.mjs';
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
