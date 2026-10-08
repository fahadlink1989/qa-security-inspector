import chromiumBinary from '@sparticuz/chromium';
import { chromium as playwrightChromium } from 'playwright-core';
import axe from 'axe-core';
import { assertPublicTarget } from './net';

function uniqPush(array, value, max=40, keyFn=(x)=>JSON.stringify(x)) {
  const key=keyFn(value);
  if(array.some((item)=>keyFn(item)===key)) return;
  if(array.length<max) array.push(value);
}

async function secureContext(browser, viewport, userAgent) {
  const hostCache=new Map();
  const context=await browser.newContext({viewport,userAgent});

  await context.route('**/*', async(route)=>{
    try{
      const reqUrl=new URL(route.request().url());
      if(['data:','blob:'].includes(reqUrl.protocol)) return route.continue();
      if(!['http:','https:'].includes(reqUrl.protocol)) return route.abort();
      const key=reqUrl.hostname.toLowerCase();
      if(!hostCache.has(key)){
        await assertPublicTarget(reqUrl);
        hostCache.set(key,true);
      }
      return route.continue();
    }catch{
      return route.abort();
    }
  });

  return context;
}

function summarizeViolations(violations=[]) {
  const counts={critical:0,serious:0,moderate:0,minor:0,unknown:0};
  let nodes=0;
  for(const violation of violations){
    const impact=violation.impact || 'unknown';
    counts[impact]=(counts[impact]||0)+1;
    nodes += violation.nodes?.length || 0;
  }
  return {counts,nodes};
}

async function inspectPage(context, url, mode, shared) {
  const page=await context.newPage();
  const local={
    url,
    finalUrl:url,
    mode,
    status:null,
    consoleErrors:[],
    pageErrors:[],
    failedRequests:[],
    badResponses:[],
    apiRequests:[],
    metrics:{},
    dom:{},
    axe:{violations:[],summary:{counts:{},nodes:0}},
    error:null
  };

  page.on('console',(msg)=>{
    if(msg.type()==='error'){
      const entry={url:page.url()||url,message:msg.text().slice(0,600)};
      uniqPush(local.consoleErrors,entry,15,(x)=>x.message);
      uniqPush(shared.consoleErrors,entry,40,(x)=>x.url+'|'+x.message);
    }
  });
  page.on('pageerror',(error)=>{
    const entry={url:page.url()||url,message:String(error?.message||error).slice(0,600)};
    uniqPush(local.pageErrors,entry,12,(x)=>x.message);
    uniqPush(shared.pageErrors,entry,30,(x)=>x.url+'|'+x.message);
  });
  page.on('request',(request)=>{
    const type=request.resourceType();
    if(type==='xhr'||type==='fetch'){
      try{
        const reqUrl=new URL(request.url());
        const entry={url:reqUrl.href,method:request.method(),resourceType:type};
        uniqPush(local.apiRequests,entry,40,(x)=>x.method+'|'+x.url);
        uniqPush(shared.apiRequests,entry,120,(x)=>x.method+'|'+x.url);
      }catch{}
    }
  });
  page.on('requestfailed',(request)=>{
    const entry={url:request.url(),method:request.method(),resourceType:request.resourceType(),error:request.failure()?.errorText||'failed'};
    uniqPush(local.failedRequests,entry,20,(x)=>x.method+'|'+x.url);
    uniqPush(shared.failedRequests,entry,50,(x)=>x.method+'|'+x.url);
  });
  page.on('response',(response)=>{
    if(response.status()>=400){
      const entry={url:response.url(),status:response.status(),requestType:response.request().resourceType()};
      uniqPush(local.badResponses,entry,25,(x)=>x.status+'|'+x.url);
      uniqPush(shared.badResponses,entry,70,(x)=>x.status+'|'+x.url);
    }
  });

  await page.addInitScript(() => {
    window.__inspectorPerf={cls:0,lcp:null,longTasks:0};
    try{
      new PerformanceObserver((list)=>{
        for(const entry of list.getEntries()){
          if(!entry.hadRecentInput) window.__inspectorPerf.cls += entry.value || 0;
        }
      }).observe({type:'layout-shift',buffered:true});
    }catch{}
    try{
      new PerformanceObserver((list)=>{
        const entries=list.getEntries();
        const last=entries[entries.length-1];
        if(last) window.__inspectorPerf.lcp=Math.round(last.startTime);
      }).observe({type:'largest-contentful-paint',buffered:true});
    }catch{}
    try{
      new PerformanceObserver((list)=>{
        window.__inspectorPerf.longTasks += list.getEntries().length;
      }).observe({type:'longtask',buffered:true});
    }catch{}
  });

  try{
    const response=await page.goto(url,{waitUntil:'domcontentloaded',timeout:14000});
    local.status=response?.status() || null;
    await page.waitForTimeout(800);
    local.finalUrl=page.url();

    local.dom=await page.evaluate(()=>{
      const all=(selector)=>Array.from(document.querySelectorAll(selector));
      const visible=(el)=>{
        const r=el.getBoundingClientRect();
        const s=getComputedStyle(el);
        return r.width>0 && r.height>0 && s.visibility!=='hidden' && s.display!=='none';
      };
      const named=(el)=>Boolean(el.textContent?.trim()||el.getAttribute('aria-label')||el.getAttribute('aria-labelledby')||el.getAttribute('title'));
      const labelFor=(el)=>{
        const id=el.getAttribute('id');
        if(id){
          const label=document.querySelector('label[for="'+CSS.escape(id)+'"]');
          if(label?.textContent?.trim()) return true;
        }
        return Boolean(el.closest('label')||el.getAttribute('aria-label')||el.getAttribute('aria-labelledby')||el.getAttribute('title'));
      };
      const forms=all('form');
      const inputs=all('input,select,textarea');
      const buttons=all('button,[role="button"]');
      const links=all('a[href]');
      const images=all('img');
      const nav=performance.getEntriesByType('navigation')[0];
      const resources=performance.getEntriesByType('resource');
      const paints=performance.getEntriesByType('paint');
      const fcp=paints.find((p)=>p.name==='first-contentful-paint');

      return {
        title:document.title,
        h1Count:all('h1').length,
        forms:forms.length,
        links:links.length,
        images:images.length,
        inputs:inputs.length,
        buttons:buttons.length,
        unlabeledInputs:inputs.filter((el)=>visible(el)&&!labelFor(el)).length,
        unnamedButtons:buttons.filter((el)=>visible(el)&&!named(el)).length,
        missingAlt:images.filter((el)=>!el.hasAttribute('alt')).length,
        emptyLinks:links.filter((el)=>visible(el)&&!named(el)&&!el.querySelector('img[alt]')).length,
        horizontalOverflow:document.documentElement.scrollWidth>window.innerWidth+4,
        viewportWidth:window.innerWidth,
        documentWidth:document.documentElement.scrollWidth,
        insecureForms:forms.filter((form)=>{
          try{
            const action=new URL(form.getAttribute('action')||location.href,location.href);
            return location.protocol==='https:'&&action.protocol==='http:';
          }catch{return false;}
        }).length,
        passwordFields:all('input[type="password"]').length,
        formsWithoutMethod:forms.filter((form)=>!form.getAttribute('method')).length,
        buttonsWithoutType:all('form button').filter((button)=>!button.getAttribute('type')).length,
        duplicateIds:(()=>{
          const ids=all('[id]').map((el)=>el.id).filter(Boolean);
          return ids.length-new Set(ids).size;
        })(),
        metrics:{
          domContentLoadedMs:nav?Math.round(nav.domContentLoadedEventEnd):null,
          loadMs:nav?Math.round(nav.loadEventEnd||nav.duration):null,
          fcpMs:fcp?Math.round(fcp.startTime):null,
          transferBytes:Math.round(resources.reduce((sum,entry)=>sum+(entry.transferSize||0),0)),
          decodedBytes:Math.round(resources.reduce((sum,entry)=>sum+(entry.decodedBodySize||0),0)),
          resourceCount:resources.length,
          perf:window.__inspectorPerf||{}
        }
      };
    });

    local.metrics=local.dom.metrics || {};

    if(mode==='desktop'){
      try{
        await page.addScriptTag({content:axe.source});
        const result=await page.evaluate(async()=>{
          return await window.axe.run(document,{
            runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21a','wcag21aa']},
            resultTypes:['violations']
          });
        });
        local.axe.violations=(result.violations||[]).slice(0,30).map((v)=>({
          id:v.id,
          impact:v.impact||'unknown',
          help:v.help,
          helpUrl:v.helpUrl,
          tags:v.tags,
          nodes:(v.nodes||[]).slice(0,8).map((n)=>({
            target:n.target,
            html:String(n.html||'').slice(0,500),
            failureSummary:String(n.failureSummary||'').slice(0,800)
          }))
        }));
        local.axe.summary=summarizeViolations(local.axe.violations);
      }catch(error){
        local.axe.error=String(error?.message||error).slice(0,400);
      }
    }
  }catch(error){
    local.error=String(error?.message||error).slice(0,800);
  }finally{
    await page.close().catch(()=>{});
  }

  return local;
}

export async function runBrowserChecks(targetUrl, pageUrls=[]) {
  const result={
    engine:'chromium',
    available:false,
    status:'failed',
    pages:[],
    consoleErrors:[],
    pageErrors:[],
    failedRequests:[],
    badResponses:[],
    apiRequests:[],
    accessibility:{violations:[],summary:{counts:{},nodes:0}},
    metrics:{},
    finalUrl:targetUrl,
    error:null
  };

  let browser;

  try{
    browser=await playwrightChromium.launch({
      args:chromiumBinary.args,
      executablePath:await chromiumBinary.executablePath(),
      headless:true
    });

    const candidates=[targetUrl,...pageUrls]
      .filter(Boolean)
      .filter((value,index,array)=>array.indexOf(value)===index)
      .slice(0,4);

    const desktop=await secureContext(browser,{width:1365,height:768},'InspectorBrowser/2.0 (+authorized QA checks)');
    for(const url of candidates){
      const pageResult=await inspectPage(desktop,url,'desktop',result);
      result.pages.push(pageResult);
    }
    await desktop.close();

    const mobile=await secureContext(browser,{width:390,height:844},'InspectorMobile/2.0 (+authorized QA checks)');
    for(const url of candidates.slice(0,2)){
      const pageResult=await inspectPage(mobile,url,'mobile',result);
      result.pages.push(pageResult);
    }
    await mobile.close();

    const successful=result.pages.filter((p)=>!p.error);
    result.available=successful.length>0;
    result.status=result.available?(successful.length===result.pages.length?'complete':'degraded'):'failed';
    result.finalUrl=successful[0]?.finalUrl||targetUrl;

    const violations=[];
    for(const page of result.pages.filter((p)=>p.mode==='desktop')){
      for(const violation of page.axe?.violations||[]){
        violations.push({...violation,pageUrl:page.finalUrl||page.url});
      }
    }
    result.accessibility.violations=violations.slice(0,80);
    result.accessibility.summary=summarizeViolations(result.accessibility.violations);

    const first=successful[0];
    result.metrics={
      loadMs:first?.metrics?.loadMs||null,
      domContentLoadedMs:first?.metrics?.domContentLoadedMs||null,
      fcpMs:first?.metrics?.fcpMs||null,
      lcpMs:first?.metrics?.perf?.lcp||null,
      cls:first?.metrics?.perf?.cls||0,
      longTasks:first?.metrics?.perf?.longTasks||0,
      transferBytes:successful.reduce((sum,p)=>sum+(p.metrics?.transferBytes||0),0),
      resourceCount:successful.reduce((sum,p)=>sum+(p.metrics?.resourceCount||0),0),
      pagesTested:successful.length,
      desktopPages:successful.filter((p)=>p.mode==='desktop').length,
      mobilePages:successful.filter((p)=>p.mode==='mobile').length
    };
  }catch(error){
    result.error=String(error?.message||error).slice(0,1000);
  }finally{
    if(browser) await browser.close().catch(()=>{});
  }

  return result;
}
