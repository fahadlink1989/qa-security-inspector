const metricIds=['first-contentful-paint','largest-contentful-paint','speed-index','total-blocking-time','cumulative-layout-shift','interactive'];
export function normalizePageSpeed(data,strategy){
  const lh=data?.lighthouseResult;
  if(!lh||lh.runtimeError)throw new Error(lh?.runtimeError?.code||'INVALID_PROVIDER_RESULT');
  const audits=lh.audits||{};
  const score=lh.categories?.performance?.score;
  if(typeof score!=='number')throw new Error('NO_PERFORMANCE_SCORE');
  const metrics=metricIds.filter(id=>audits[id]).map(id=>({id,title:audits[id].title,value:audits[id].numericValue??null,unit:audits[id].numericUnit||null,displayValue:audits[id].displayValue||'Not available',score:audits[id].score}));
  const ids=new Set((lh.categories?.performance?.auditRefs||[]).map(a=>a.id));
  const issues=Object.entries(audits).filter(([id,a])=>ids.has(id)&&a.score!==null&&a.score<1&&!metricIds.includes(id)&&!['manual','notApplicable','informative'].includes(a.scoreDisplayMode)).map(([id,a])=>({
    id,title:a.title,description:a.description||'',displayValue:a.displayValue||'',score:a.score,
    savingsMs:a.details?.overallSavingsMs??a.metricSavings?.LCP??null,savingsBytes:a.details?.overallSavingsBytes??null,
    items:(a.details?.items||[]).slice(0,12).map(item=>Object.fromEntries(Object.entries(item).filter(([k,v])=>['url','totalBytes','wastedBytes','wastedMs','duration','transferSize','label'].includes(k)&&['string','number'].includes(typeof v))))
  })).sort((a,b)=>(b.savingsMs||0)-(a.savingsMs||0)||a.score-b.score);
  const field=experience=>experience?.metrics&&Object.keys(experience.metrics).length?{id:experience.id,category:experience.overall_category,metrics:experience.metrics}:null;
  return {strategy,status:'completed',provider:'Google PageSpeed Insights',score:Math.round(score*100),fetchedAt:lh.fetchTime||new Date().toISOString(),lighthouseVersion:lh.lighthouseVersion,requestedUrl:lh.requestedUrl,finalUrl:lh.finalDisplayedUrl||lh.finalUrl,metrics,issues,
    fieldData:{page:field(data.loadingExperience),origin:field(data.originLoadingExperience)},
    environment:{formFactor:lh.configSettings?.formFactor,throttlingMethod:lh.configSettings?.throttlingMethod},warnings:lh.runWarnings||[]};
}
export function providerError(status){
  if(status===429)return 'Google PageSpeed quota exceeded. Add a Google API key in Settings or check its quota, then retry.';
  if(status===400||status===401||status===403)return 'Google rejected the request. Check the target URL and the API key’s PageSpeed API access in Settings.';
  return 'Google PageSpeed could not complete this measurement. Retry later; no score has been estimated.';
}
