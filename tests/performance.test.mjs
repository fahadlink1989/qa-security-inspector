import assert from 'node:assert/strict';
import {normalizePageSpeed,providerError} from '../lib/performanceModel.mjs';
// Synthetic provider fixture used exclusively to verify parsing; never a production fallback.
const fixture={lighthouseResult:{fetchTime:'2026-10-09T00:00:00Z',lighthouseVersion:'13',categories:{performance:{score:0,auditRefs:[{id:'unused-javascript'},{id:'first-contentful-paint'}]}},audits:{'first-contentful-paint':{title:'First Contentful Paint',numericValue:1234,displayValue:'1.2 s',score:0.5},'unused-javascript':{title:'Reduce unused JavaScript',score:0,description:'Remove unused code',details:{overallSavingsMs:150,items:[{url:'https://example.test/app.js',wastedBytes:1000}]}}}}};
const result=normalizePageSpeed(fixture,'mobile');assert.equal(result.score,0,'zero score is valid, not missing');assert.equal(result.metrics[0].value,1234);assert.equal(result.issues[0].savingsMs,150);assert.equal(result.fieldData.page,null,'lab metrics must not become field data');
assert.throws(()=>normalizePageSpeed({lighthouseResult:{runtimeError:{code:'NAVIGATION_FAILED'}}},'desktop'));
assert.throws(()=>normalizePageSpeed({lighthouseResult:{categories:{performance:{score:null}}}},'desktop'));
assert.ok(providerError(429).includes('quota'));
console.log('PageSpeed normalization, missing data, navigation failure and quota tests passed');
