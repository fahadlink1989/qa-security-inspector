import dns from 'node:dns/promises';
import * as cheerio from 'cheerio';
import { safeFetch } from './net';

function headersObject(headers) {
  return Object.fromEntries(headers.entries());
}

function normalizeUrl(value, base) {
  try {
    const url = new URL(value, base);
    url.hash = '';
    return url;
  } catch {
    return null;
  }
}

function safePath(url) {
  return url.pathname + (url.search || '');
}

export function fingerprintTechnologies(headers, html) {
  const technologies = [];
  const add = (name, evidence, confidence='Medium', version=null) => {
    if (!technologies.some((item)=>item.name===name && item.version===version)) {
      technologies.push({name,evidence,confidence,version});
    }
  };

  const server = headers.get('server') || '';
  const powered = headers.get('x-powered-by') || '';

  if (server) {
    const nginx = server.match(/nginx\/?([0-9.]+)?/i);
    const apache = server.match(/apache\/?([0-9.]+)?/i);
    if (nginx) add('nginx','server response header','High',nginx[1] || null);
    else if (apache) add('Apache HTTP Server','server response header','High',apache[1] || null);
    else add(server,'server response header','High');
  }

  if (powered) {
    const php = powered.match(/PHP\/?([0-9.]+)/i);
    const express = powered.match(/Express/i);
    if (php) add('PHP','x-powered-by response header','High',php[1] || null);
    else if (express) add('Express','x-powered-by response header','High');
    else add(powered,'x-powered-by response header','High');
  }

  const next = html.match(/"nextExport"|"buildId"|\/_next\/static\//i);
  if (next) add('Next.js','Next.js runtime/assets','High');
  const wpVersion = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s+([0-9.]+)["']/i)
    || html.match(/content=["']WordPress\s+([0-9.]+)["'][^>]+name=["']generator["']/i);
  if (/wp-content|wp-includes|wp-json/i.test(html)) add('WordPress','WordPress public paths','High',wpVersion?.[1]||null);
  if (/cdn\.shopify\.com|Shopify\.theme|myshopify\.com/i.test(html)) add('Shopify','Shopify asset/runtime markers','High');
  if (/data-reactroot|__REACT|react(?:\.production)?\.min\.js/i.test(html)) add('React','React DOM/script markers');
  if (/ng-version|angular(?:\.min)?\.js/i.test(html)) add('Angular','Angular runtime markers');
  if (/vue(?:\.runtime)?(?:\.min)?\.js|data-v-[a-f0-9]+/i.test(html)) add('Vue','Vue runtime markers');
  if (headers.get('cf-ray') || /cloudflare/i.test(server)) add('Cloudflare','Cloudflare response markers','High');
  if (/googletagmanager\.com|gtag\(/i.test(html)) add('Google Tag Manager / Analytics','analytics script markers');
  if (/segment\.com|analytics\.js/i.test(html)) add('Segment','analytics script markers');
  if (/sentry\.io|Sentry\.init/i.test(html)) add('Sentry','error-monitoring markers');
  return technologies;
}

export function extractSameHostLinks(baseUrl, html, max=120) {
  const base = new URL(baseUrl);
  const links = [];
  const seen = new Set();
  const $ = cheerio.load(html);

  $('a[href]').each((_,el)=>{
    if (links.length >= max) return false;
    const href = $(el).attr('href');
    if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('tel:') || href.startsWith('javascript:')) return;
    const url = normalizeUrl(href, base);
    if (!url) return;
    if (!['http:','https:'].includes(url.protocol)) return;
    if (url.hostname !== base.hostname) return;
    if (/\.(?:jpg|jpeg|png|gif|webp|svg|ico|pdf|zip|gz|mp4|mp3|woff2?|ttf)(?:$|\?)/i.test(url.pathname)) return;
    if (!seen.has(url.href)) {
      seen.add(url.href);
      links.push(url.href);
    }
  });

  return links;
}

export function extractApiHints(baseUrl, content) {
  const base = new URL(baseUrl);
  const set = new Set();
  const patterns = [
    /["'`](\/api\/[a-zA-Z0-9_\-\/.?=&%:{}$]+)["'`]/g,
    /["'`](\/graphql(?:\?[^"'`]*)?)["'`]/g,
    /fetch\(\s*["']([^"']+)["']/g,
    /axios\.(?:get|post|put|patch|delete)\(\s*["']([^"']+)["']/g,
    /["'](https?:\/\/[^"']+\/(?:api|graphql)\/[^"']*)["']/g
  ];

  for (const pattern of patterns) {
    for (const match of content.matchAll(pattern)) {
      const url = normalizeUrl(match[1], base);
      if (!url || url.hostname !== base.hostname) continue;
      const path = safePath(url);
      if (path.length <= 500) set.add(path);
    }
  }

  return [...set].slice(0,200);
}

export function extractScriptUrls(baseUrl, html, max=20) {
  const base = new URL(baseUrl);
  const urls = [];
  const $ = cheerio.load(html);

  $('script[src]').each((_, el) => {
    if (urls.length >= max) return false;
    const url = normalizeUrl($(el).attr('src'), base);
    if (!url || !['http:','https:'].includes(url.protocol)) return;
    if (url.hostname === base.hostname && !urls.includes(url.href)) urls.push(url.href);
  });

  return urls;
}

async function fetchText(url, timeout=4500, maxBytes=800000) {
  const response = await safeFetch(url, { method:'GET', headers:{accept:'text/plain,text/html,application/json,application/javascript,*/*'} }, timeout);
  const text = (await response.text()).slice(0,maxBytes);
  return {
    url: response.url || url,
    status: response.status,
    contentType: response.headers.get('content-type') || '',
    headers: headersObject(response.headers),
    text
  };
}

export async function discoverRobotsAndSitemaps(startUrl) {
  const base = new URL(startUrl);
  const result = { robots: null, sitemapUrls: [], sitemapPages: [], disallow: [] };

  try {
    const robotsUrl = new URL('/robots.txt', base).href;
    const robots = await fetchText(robotsUrl, 3500, 200000);
    if (robots.status >= 200 && robots.status < 400 && /text|plain/i.test(robots.contentType || 'text/plain')) {
      result.robots = { url: robots.url, status: robots.status };
      for (const line of robots.text.split(/\r?\n/)) {
        const sitemap = line.match(/^\s*Sitemap:\s*(.+)$/i);
        if (sitemap) {
          const u = normalizeUrl(sitemap[1].trim(), base);
          if (u && ['http:','https:'].includes(u.protocol)) result.sitemapUrls.push(u.href);
        }
        const disallow = line.match(/^\s*Disallow:\s*(\S+)/i);
        if (disallow && disallow[1] !== '/') result.disallow.push(disallow[1]);
      }
    }
  } catch {}

  if (!result.sitemapUrls.length) result.sitemapUrls.push(new URL('/sitemap.xml', base).href);

  for (const sitemapUrl of result.sitemapUrls.slice(0,3)) {
    try {
      const sitemap = await fetchText(sitemapUrl, 4500, 900000);
      if (!(sitemap.status >= 200 && sitemap.status < 400)) continue;
      for (const match of sitemap.text.matchAll(/<loc>\s*([^<]+?)\s*<\/loc>/gi)) {
        const u = normalizeUrl(match[1].trim(), base);
        if (u && u.hostname === base.hostname && !result.sitemapPages.includes(u.href)) {
          result.sitemapPages.push(u.href);
        }
        if (result.sitemapPages.length >= 100) break;
      }
    } catch {}
  }

  return result;
}

function disallowed(url, rules) {
  try {
    const path = new URL(url).pathname;
    return (rules || []).some((rule) => rule && rule !== '/' && path.startsWith(rule));
  } catch {
    return false;
  }
}

export async function crawlPages(startUrl, firstHtml, firstHeaders={}, maxPages=18) {
  const base = new URL(startUrl);
  const discovery = await discoverRobotsAndSitemaps(startUrl);
  const queue = [];
  const queued = new Set();
  const seen = new Set([startUrl]);

  const enqueue = (href, source) => {
    const u = normalizeUrl(href, base);
    if (!u || u.hostname !== base.hostname || !['http:','https:'].includes(u.protocol)) return;
    if (seen.has(u.href) || queued.has(u.href) || disallowed(u.href, discovery.disallow)) return;
    queued.add(u.href);
    queue.push({href:u.href,source});
  };

  for (const href of discovery.sitemapPages.slice(0,40)) enqueue(href,'sitemap');
  for (const href of extractSameHostLinks(startUrl,firstHtml,80)) enqueue(href,'link');

  const pages=[{
    url:startUrl,
    status:200,
    html:firstHtml,
    headers:firstHeaders,
    source:'entry',
    title:cheerio.load(firstHtml)('title').text().trim(),
    bytes:firstHtml.length
  }];

  while(queue.length && pages.length < maxPages){
    const batch=queue.splice(0,Math.min(4,maxPages-pages.length));

    const completed=await Promise.all(batch.map(async(item)=>{
      const href=item.href;
      queued.delete(href);
      if(seen.has(href)) return null;
      seen.add(href);
      try {
        const response=await safeFetch(href,{method:'GET',headers:{accept:'text/html,application/xhtml+xml'}},5000);
        const ct=response.headers.get('content-type')||'';
        if(!ct.includes('text/html')) {
          return {url:response.url||href,status:response.status,html:'',headers:headersObject(response.headers),source:item.source,title:'',bytes:0,contentType:ct};
        }
        const html=(await response.text()).slice(0,1400000);
        const pageUrl=response.url||href;
        const $=cheerio.load(html);
        for(const next of extractSameHostLinks(pageUrl,html,40)) enqueue(next,'link');
        return {
          url:pageUrl,
          status:response.status,
          html,
          headers:headersObject(response.headers),
          source:item.source,
          title:$('title').text().trim(),
          bytes:html.length,
          contentType:ct
        };
      } catch(error) {
        return {url:href,status:0,html:'',headers:{},source:item.source,title:'',bytes:0,error:String(error?.message||error).slice(0,200)};
      }
    }));

    for(const page of completed) if(page) pages.push(page);
  }

  return { pages, discovery };
}

export async function inspectJavaScriptBundles(pages, maxBundles=6) {
  const scripts=[];
  for(const page of pages){
    if(!page.html) continue;
    for(const src of extractScriptUrls(page.url,page.html,20)){
      if(!scripts.includes(src)) scripts.push(src);
      if(scripts.length>=maxBundles) break;
    }
    if(scripts.length>=maxBundles) break;
  }

  const bundles=[];
  const apiHints=new Set();
  const sourceMaps=[];

  for(const url of scripts){
    try{
      const file=await fetchText(url,4500,900000);
      if(!(file.status>=200 && file.status<400)) continue;
      const hints=extractApiHints(file.url,file.text);
      hints.forEach((hint)=>apiHints.add(hint));
      const mapMatch=file.text.match(/[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)/);
      let sourceMap=null;
      if(mapMatch){
        const mapUrl=normalizeUrl(mapMatch[1].trim(),file.url);
        if(mapUrl && mapUrl.hostname===new URL(file.url).hostname){
          try{
            const map=await fetchText(mapUrl.href,3500,700000);
            let valid=false;
            if(map.status>=200 && map.status<300){
              try{
                const parsed=JSON.parse(map.text);
                valid=Array.isArray(parsed.sources) && parsed.sources.length>0;
              }catch{}
            }
            if(valid){
              sourceMap={url:mapUrl.href,status:map.status};
              sourceMaps.push(sourceMap);
            }
          }catch{}
        }
      }
      bundles.push({url:file.url,status:file.status,bytes:file.text.length,apiHints:hints.slice(0,20),sourceMap});
    }catch{}
  }

  return {
    bundles,
    apiHints:[...apiHints].slice(0,150),
    sourceMaps
  };
}

export async function discoverCommonSubdomains(hostname) {
  const parts=hostname.split('.');
  const root=parts.length>2 ? parts.slice(-2).join('.') : hostname;
  const labels=['www','api','app','auth','login','portal','admin','dev','staging','status'];
  const found=[];

  for(const label of labels){
    const host=label+'.'+root;
    try{
      const [v4,v6]=await Promise.allSettled([dns.resolve4(host),dns.resolve6(host)]);
      const ips=[
        ...(v4.status==='fulfilled'?v4.value:[]),
        ...(v6.status==='fulfilled'?v6.value:[])
      ];
      if(ips.length) found.push({host,ips:ips.slice(0,4)});
    }catch{}
  }

  return found;
}


export async function discoverCertificateSubdomains(rootDomain, max=120) {
  const discovered = new Set();
  const root = String(rootDomain || '').toLowerCase().replace(/^\*\./,'').replace(/\.$/,'');
  if (!root || !root.includes('.')) return [];

  try {
    const response = await fetch('https://crt.sh/?q=%25.' + encodeURIComponent(root) + '&output=json', {
      headers: { 'user-agent':'InspectorQA/2.1 (+authorized asset discovery)', accept:'application/json' },
      signal: AbortSignal.timeout(10000),
      cache: 'no-store'
    });
    if (!response.ok) return [];
    const rows = await response.json();

    for (const row of Array.isArray(rows) ? rows : []) {
      const values = String(row.name_value || row.common_name || '').split(/\s+/);
      for (let value of values) {
        value = value.trim().toLowerCase().replace(/^\*\./,'').replace(/\.$/,'');
        if (!value || value === root) continue;
        if (value.endsWith('.' + root)) discovered.add(value);
        if (discovered.size >= max) return [...discovered];
      }
    }
  } catch {}

  return [...discovered];
}

export function classifyEndpoint(item, applicationHost) {
  const method = String(item?.method || 'OBSERVE').toUpperCase();
  const path = String(item?.path || '');
  const source = String(item?.source || 'observed');
  const host = String(item?.host || applicationHost || '').toLowerCase();
  const joined = (host + path).toLowerCase();

  const analyticsPatterns = [
    'google-analytics','googletagmanager','doubleclick','googleadservices','/collect','/measurement/',
    '/g/collect','/ccm/','/rmkt/','visualwebsiteoptimizer','hotjar','segment','amplitude','mixpanel',
    'facebook.com/tr','connect.facebook','clarity.ms','tiktok','taboola','outbrain'
  ];
  const authPatterns = ['/auth','/login','/logout','/oauth','/sso','/token','/session','/signin','/signup'];
  const billingPatterns = ['/billing','/payment','/checkout','/invoice','/subscription','/stripe'];
  const apiPatterns = ['/api/','/graphql','/rest/','/v1/','/v2/','/v3/'];

  let classification='Unknown';
  if (analyticsPatterns.some((pattern)=>joined.includes(pattern))) classification='Analytics / Telemetry';
  else if (authPatterns.some((pattern)=>path.toLowerCase().includes(pattern))) classification='Authentication';
  else if (billingPatterns.some((pattern)=>path.toLowerCase().includes(pattern))) classification='Billing / Commerce';
  else if (apiPatterns.some((pattern)=>path.toLowerCase().includes(pattern))) classification='Business API';
  else if (source === 'browser') classification='Application request';

  return { ...item, method, path, host, classification };
}
