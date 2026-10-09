'use client';
import {useState} from 'react';
function Metric({label,value}){return <div className="performanceMetric"><span>{label}</span><strong>{value??'Not available'}</strong></div>;}
function FieldData({data}){
  const entries=Object.entries(data?.metrics||{});
  if(!entries.length)return <p>No real-user dataset was supplied by Google for this scope. This is not a passing result.</p>;
  return <><p>{data.id} · Google experience category: {data.category||'Not supplied'}</p><div className="performanceMetrics">{entries.map(([key,m])=><Metric key={key} label={key.replaceAll('_',' ')} value={m.percentile==null?'Not available':key.includes('CUMULATIVE_LAYOUT_SHIFT')?(m.percentile/100).toFixed(2):m.percentile+' ms'}/>)}</div><p className="muted">Values are Google’s 75th-percentile field measurements. Page and origin coverage are shown separately.</p></>;
}
export default function PerformancePanel({asset,runs,jobs,onRun,onClose,onSettings}){
  const [device,setDevice]=useState('mobile'),[runId,setRunId]=useState(''),[authorized,setAuthorized]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState('');
  const history=runs.filter(s=>s.assetId===asset.id).sort((a,b)=>String(b.completedAt).localeCompare(String(a.completedAt)));
  const run=history.find(r=>r.id===runId)||history[0];
  const result=run?.devices?.[device];
  const job=jobs.find(j=>j.type==='performance'&&j.assetId===asset.id&&['queued','running'].includes(j.status));
  const submit=async()=>{setBusy(true);setError('');try{await onRun(asset.id);setRunId('');setAuthorized(false);}catch(e){setError(e.message);}finally{setBusy(false);}};
  const download=()=>{const link=document.createElement('a');const url=URL.createObjectURL(new Blob([JSON.stringify(run,null,2)],{type:'application/json'}));link.href=url;link.download='inspector-pagespeed-'+run.id+'.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
  return <div className="modalBackdrop"><section className="modal performancePanel" role="dialog" aria-modal="true" aria-label="Website performance"><div className="modalHead"><div><span className="eyebrow">GOOGLE PAGESPEED INSIGHTS</span><h2>Website performance</h2><p>{asset.label} · {asset.url}</p></div><button aria-label="Close performance" onClick={onClose}>×</button></div>
    <p>Measure this public page on mobile and desktop. Lab scores vary with test conditions; they are separate from security scores.</p>
    <div className="performanceControls"><label><input type="checkbox" checked={authorized} onChange={e=>setAuthorized(e.target.checked)}/> I have permission to test this public page and send its URL to Google.</label><button className="primaryBtn" disabled={!authorized||busy||Boolean(job)} onClick={submit}>{busy?'Queueing…':job?'Measurement in progress':'Measure mobile & desktop'}</button><button className="secondaryBtn" onClick={onSettings}>API key settings</button></div>
    {error?<p role="alert" className="formError">{error}</p>:null}
    {job?<div className="scanExpectations" role="status">{job.stage} · {job.progress||0}% · Results are saved when both measurements finish. You can close this panel.</div>:null}
    {history.length?<label className="field">Measurement history<select value={run?.id||''} onChange={e=>setRunId(e.target.value)}>{history.map(r=><option key={r.id} value={r.id}>{new Date(r.completedAt).toLocaleString()} · {r.status.replaceAll('_',' ')}</option>)}</select></label>:<div className="emptyRow">No performance measurements yet. Scores appear only after Google returns a valid result.</div>}
    <div className="tabs">{['mobile','desktop'].map(d=><button key={d} className={device===d?'active':''} onClick={()=>setDevice(d)}>{d==='mobile'?'Mobile':'Desktop'}</button>)}</div>
    {result?.status==='failed'?<div className="formError" role="alert"><strong>Measurement unavailable</strong><p>{result.error}</p>{result.httpStatus?<p>Google response: HTTP {result.httpStatus}</p>:null}<button className="secondaryBtn" onClick={onSettings}>Configure Google API key</button></div>:null}
    {result?.status==='completed'?<>
      <div className="performanceScore"><strong className={result.score>=90?'good':result.score>=50?'average':'poor'}>{result.score}<small>/100</small></strong><div><h3>{device==='mobile'?'Mobile':'Desktop'} lab performance</h3><p>Google Lighthouse {result.lighthouseVersion} · {new Date(result.fetchedAt).toLocaleString()}</p><p>{result.finalUrl}</p></div></div>
      <div className="performanceMetrics">{result.metrics.map(m=><Metric key={m.id} label={m.title} value={m.displayValue}/>)}</div>
      <p className="muted">LCP: main content loading · CLS: layout stability · TBT: main-thread blocking in this lab test. TBT is not the real-user INP metric.</p>
      {result.warnings?.length?<section><h3>Measurement warnings</h3>{result.warnings.map((w,i)=><p key={i}>{w}</p>)}</section>:null}
      <section><h3>Performance issues and opportunities ({result.issues.length})</h3><p className="muted">These are Google’s audit findings and estimated savings, not confirmed security vulnerabilities. Savings overlap and should not be added together.</p>{result.issues.map(issue=><details key={issue.id} className="performanceIssue"><summary><strong>{issue.title}</strong><span>{issue.displayValue}{issue.savingsMs!=null?' · estimated '+Math.round(issue.savingsMs)+' ms savings':''}</span></summary><p>{issue.description}</p>{issue.items.map((item,i)=><pre key={i}>{JSON.stringify(item,null,2)}</pre>)}</details>)}{!result.issues.length?<p>No failing performance audits were returned for this measurement.</p>:null}</section>
      <section><h3>Real-user experience · this page</h3><FieldData data={result.fieldData.page}/><h3>Real-user experience · entire origin</h3><FieldData data={result.fieldData.origin}/><p className="muted">Field data is shown only if the provider supplies it. Google is moving this data to its separate CrUX APIs; unavailable field data is never replaced with lab values.</p></section>
    </>:null}
    <div className="modalFoot">{run?<button className="secondaryBtn" onClick={download}>Download measurement JSON</button>:null}<a className="secondaryBtn" target="_blank" rel="noreferrer" href={'https://pagespeed.web.dev/analysis?'+new URLSearchParams({url:asset.url,form_factor:device})}>Open Google PageSpeed ↗</a><button className="primaryBtn" onClick={onClose}>Done</button></div>
  </section></div>;
}
