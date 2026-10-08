import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
const text=await fs.readFile(new URL('../lib/intelligence.js',import.meta.url),'utf8');
const source=text.slice(text.indexOf('function validatePlan'),text.indexOf('async function directOpenAI'));
const validate=new Function(source+'\nreturn validatePlan;')();
test('AI actions and guidance require scanner evidence references',()=>{
const plan=validate({actions:[{title:'Invented',relatedFindings:['unknown']},{title:'Known',relatedFindings:['fp','unknown']}],findingGuidance:[{fingerprint:'unknown'},{fingerprint:'fp',steps:['Fix observed header']}]},{findings:[{fingerprint:'fp'}]});
assert.equal(plan.actions.length,1);assert.deepEqual(plan.actions[0].relatedFindings,['fp']);assert.deepEqual(Object.keys(plan.findingGuidance),['fp']);
});
