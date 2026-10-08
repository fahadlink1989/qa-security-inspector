import dns from 'node:dns/promises';
import * as cheerio from 'cheerio';
import { safeFetch } from './net';

export function fingerprintTechnologies(headers, html) {
  const technologies = [];
  const add = (name, evidence, confidence='Medium') => {
    if (!technologies.some((item)=>item.name===name)) technologies.push({name,evidence,confidence});
  };
  const server = headers.get('server') || '';
  const powered = headers.get('x-powered-by') || '';
  if (server) add(server, 'server response header', 'High');
  if (powered) add(powered, 'x-powered-by response header', 'High');
  if (/__NEXT_DATA__|\/_next\//i.test(html)) add('Next.js','Next.js asset markers','High');
  if (/wp-content|wp-includes/i.test(html)) add('WordPress','WordPress asset paths','High');
  if (/cdn\.shopify\.com|Shopify\.theme/i.test(html)) add('Shopify','Shopify asset markers','High');
  if (/data-reactroot|__REACT|react(?:\.production)?\.min\.js/i.test(html)) add('React','React DOM/script markers');
  if (/ng-version|angular(?:\.min)?\.js/i.test(html)) add('Angular','Angular markers');
  if (/vue(?:\.runtime)?(?:\.min)?\.js|data-v-[a-f0-9]+/i.test(html)) add('Vue','Vue markers');
  if (headers.get('cf-ray') || /cloudflare/i.test(server)) add('Cloudflare','Cloudflare response markers','High');
  return technologies;
}

export function extractSameHostLinks(baseUrl, html, max=80) {
  const base = new URL(baseUrl);
  const links = [];
  const $ = cheerio.load(html);
  $('a[href]').each((_,el)=>{
    if (links.length >= max) return false;
    try {
      const href = $(el).attr('href');
      const u = new URL(href, base);
      u.hash='';
      if (['http:','https:'].includes(u.protocol) && u.hostname===base.hostname && !links.includes(u.href)) links.push(u.href);
    } catch {}
  });
  return links;
}

export function extractApiHints(baseUrl, html) {
  const base = new URL(baseUrl);
  const set = new Set();
  const patterns = [
    /["'`](\/api\/[a-zA-Z0-9_\-\/.?=&%:{}]+)["'`]/g,
    /fetch\(\s*["']([^"']+)["']/g,
    /axios\.(?:get|post|put|patch|delete)\(\s*["']([^"']+)["']/g,
    /["'](https?:\/\/[^"']+\/api\/[^"']+)["']/g
  ];
  for (const pattern of patterns) {
    for (const match of html.matchAll(pattern)) {
      try {
        const u = new URL(match[1], base);
        if (u.hostname===base.hostname) set.add(u.pathname + u.search);
      } catch {}
    }
  }
  return [...set].slice(0,100);
}

export async function discoverCommonSubdomains(hostname) {
  const parts=hostname.split('.');
  const root=parts.length>2 ? parts.slice(-2).join('.') : hostname;
  const labels=['www','api','app','auth','login','portal','admin','dev','staging','status'];
  const found=[];
  for (const label of labels) {
    const host=label+'.'+root;
    try {
      const ips=await dns.resolve4(host);
      if (ips.length) found.push({host,ips:ips.slice(0,4)});
    } catch {}
  }
  return found;
}

export async function crawlPages(startUrl, firstHtml, maxPages=8) {
  const origin=new URL(startUrl).origin;
  const queue=extractSameHostLinks(startUrl,firstHtml,30);
  const seen=new Set([startUrl]);
  const pages=[{url:startUrl,status:200,html:firstHtml,source:'entry'}];

  while(queue.length && pages.length<maxPages){
    const href=queue.shift();
    if(seen.has(href)) continue;
    seen.add(href);
    try {
      const response=await safeFetch(href,{method:'GET',headers:{accept:'text/html,application/xhtml+xml'}},6000);
      const ct=response.headers.get('content-type')||'';
      if(!ct.includes('text/html')) continue;
      const html=(await response.text()).slice(0,1200000);
      pages.push({url:response.url||href,status:response.status,html,source:'crawl'});
      for(const next of extractSameHostLinks(response.url||href,html,20)){
        if(new URL(next).origin===origin && !seen.has(next) && queue.length<80) queue.push(next);
      }
    } catch {
      pages.push({url:href,status:0,html:'',source:'crawl'});
    }
  }
  return pages;
}
