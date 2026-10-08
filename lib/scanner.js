import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import tls from 'node:tls';
import * as cheerio from 'cheerio';
import { safeFetch, assertPublicTarget } from './net';
import { runBrowserChecks } from './browser';
import { crawlPages, discoverCommonSubdomains, extractApiHints, fingerprintTechnologies } from './discovery';

function fingerprint(parts) {
  return crypto.createHash('sha256').update(parts.join('|')).digest('hex').slice(0, 20);
}

export function finding(checkId, category, severity, title, summary, evidence, remediation, options = {}) {
  const location = options.location || '';
  return {
    id: crypto.randomUUID(),
    fingerprint: fingerprint([checkId, location, title]),
    checkId,
    category,
    severity,
    title,
    summary,
    impact: options.impact || summary,
    evidence,
    remediation,
    confidence: options.confidence || 'High',
    location,
    engine: options.engine || 'http',
    lifecycle: 'new'
  };
}

export function scoreFindings(findings) {
  const weights = { Critical: 24, High: 12, Medium: 6, Low: 2, Informational: 0.5 };
  const penalty = findings.reduce((sum, item) => sum + (weights[item.severity] || 0), 0);
  return Math.max(0, Math.round(100 - penalty));
}

function summarize(findings) {
  const out = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  for (const item of findings) {
    const key = item.severity.toLowerCase();
    if (key in out) out[key] += 1;
  }
  return out;
}

async function tlsInfo(url) {
  if (url.protocol !== 'https:') return { enabled: false };
  await assertPublicTarget(url);
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: url.hostname,
      port: Number(url.port || 443),
      servername: url.hostname,
      rejectUnauthorized: false,
      timeout: 6000
    }, () => {
      const cert = socket.getPeerCertificate();
      const result = {
        enabled: true,
        authorized: socket.authorized,
        protocol: socket.getProtocol(),
        cipher: socket.getCipher()?.name || '',
        validFrom: cert?.valid_from || '',
        validTo: cert?.valid_to || '',
        issuer: cert?.issuer?.O || cert?.issuer?.CN || '',
        subject: cert?.subject?.CN || ''
      };
      socket.end();
      resolve(result);
    });
    socket.on('timeout', () => { socket.destroy(); resolve({ enabled: true, error: 'TLS timeout' }); });
    socket.on('error', (error) => resolve({ enabled: true, error: error.message }));
  });
}

async function dnsInfo(hostname) {
  const settled = await Promise.allSettled([
    dns.resolve4(hostname),
    dns.resolve6(hostname),
    dns.resolveMx(hostname),
    dns.resolveNs(hostname),
    dns.resolveTxt(hostname)
  ]);
  const val = (idx) => settled[idx].status === 'fulfilled' ? settled[idx].value : [];
  return {
    a: val(0),
    aaaa: val(1),
    mx: val(2),
    ns: val(3),
    txt: val(4).flat?.() || val(4)
  };
}

function headerFindings(response, html, url) {
  const items = [];
  const h = response.headers;
  const csp = h.get('content-security-policy') || '';
  const setCookies = typeof h.getSetCookie === 'function' ? h.getSetCookie() : [];
  const add = (id, severity, title, summary, evidence, remediation, extra = {}) =>
    items.push(finding(id, 'Security', severity, title, summary, evidence, remediation, { location: url.href, ...extra }));

  if (url.protocol === 'https:' && !h.get('strict-transport-security')) {
    add('SEC-HSTS','Medium','HSTS is not enabled','HTTPS is served without HSTS.','Strict-Transport-Security header not present.','Add HSTS after confirming HTTPS coverage.');
  }
  if (!csp) {
    add('SEC-CSP','High','Content Security Policy is missing','No CSP was detected.','Content-Security-Policy header not present.','Deploy a restrictive CSP, preferably nonce/hash based.');
  }
  if (!h.get('x-frame-options') && !/frame-ancestors/i.test(csp)) {
    add('SEC-FRAME','Medium','Clickjacking protection is not evident','The response does not restrict framing.','No X-Frame-Options header and no CSP frame-ancestors directive.','Set CSP frame-ancestors to trusted origins.');
  }
  if ((h.get('x-content-type-options') || '').toLowerCase() !== 'nosniff') {
    add('SEC-NOSNIFF','Low','MIME sniffing protection is missing','nosniff was not detected.','X-Content-Type-Options is missing or not nosniff.','Return X-Content-Type-Options: nosniff.');
  }
  if (!h.get('referrer-policy')) {
    add('SEC-REFERRER','Low','Referrer policy is not explicit','No Referrer-Policy was detected.','Referrer-Policy header not present.','Set strict-origin-when-cross-origin or a stricter policy.');
  }
  if (!h.get('permissions-policy')) {
    add('SEC-PERMISSIONS','Low','Browser feature permissions are not constrained','No Permissions-Policy was detected.','Permissions-Policy header not present.','Disable browser capabilities that are not required.',{confidence:'Medium'});
  }
  const server = h.get('server');
  const powered = h.get('x-powered-by');
  if (server || powered) {
    add('SEC-BANNER','Low','Technology details are exposed','Response headers reveal platform information.',`server: ${server || '(none)'}\nx-powered-by: ${powered || '(none)'}`,'Suppress unnecessary platform banners.',{confidence:'Medium'});
  }

  for (const cookie of setCookies.slice(0, 12)) {
    const name = cookie.split('=')[0] || 'cookie';
    if (url.protocol === 'https:' && !/;\s*secure\b/i.test(cookie)) {
      add('SEC-COOKIE-SECURE','Medium',`Cookie "${name}" lacks Secure`,'A cookie issued over HTTPS is not marked Secure.',cookie,'Mark authentication and session cookies Secure.',{location:url.href + '#cookie:' + name});
    }
    if (!/;\s*httponly\b/i.test(cookie)) {
      add('SEC-COOKIE-HTTPONLY','Low',`Cookie "${name}" lacks HttpOnly`,'A cookie is readable by client-side scripts.',cookie,'Use HttpOnly for cookies that do not require JavaScript access.',{location:url.href + '#cookie:' + name,confidence:'Medium'});
    }
  }

  const $ = cheerio.load(html);
  const mixed = [];
  $('[src],[href]').each((_, el) => {
    const value = $(el).attr('src') || $(el).attr('href');
    if (url.protocol === 'https:' && value?.startsWith('http://') && mixed.length < 10) mixed.push(value);
  });
  if (mixed.length) {
    add('SEC-MIXED','Medium','Mixed content references detected','HTTPS page references insecure HTTP resources.',mixed.join('\n'),'Serve all subresources over HTTPS.');
  }

  $('form').each((idx, el) => {
    const action = $(el).attr('action');
    if (!action) return;
    try {
      const resolved = new URL(action, url);
      if (url.protocol === 'https:' && resolved.protocol === 'http:') {
        add('SEC-INSECURE-FORM','High','Form submits over HTTP','A form on an HTTPS page posts to an insecure endpoint.',resolved.href,'Submit sensitive forms only to HTTPS endpoints.',{location:url.href + '#form:' + idx});
      }
    } catch {}
  });

  return items;
}

async function corsFindings(url) {
  try {
    const response = await safeFetch(url.href, {
      method: 'GET',
      headers: { origin: 'https://inspector.invalid', accept: 'text/html,*/*' }
    }, 6500);
    const allowOrigin = response.headers.get('access-control-allow-origin');
    const allowCreds = (response.headers.get('access-control-allow-credentials') || '').toLowerCase() === 'true';
    if (allowOrigin === '*' && allowCreds) {
      return [finding('SEC-CORS-CREDS','Security','High','Dangerous CORS combination detected','Wildcard origin is paired with credential allowance.',`Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true`,'Use an explicit allowlist and never combine wildcard origins with credentials.',{location:url.href})];
    }
    if (allowOrigin === 'https://inspector.invalid' && allowCreds) {
      return [finding('SEC-CORS-REFLECT','Security','High','CORS appears to reflect arbitrary origins','The test Origin value was reflected while credentials were allowed.',`Access-Control-Allow-Origin: ${allowOrigin}\nAccess-Control-Allow-Credentials: true`,'Validate origins against a strict allowlist before reflecting them.',{location:url.href,confidence:'Medium'})];
    }
  } catch {}
  return [];
}

async function publicEndpointFindings(url) {
  const probes = [
    ['/.env','SEC-EXPOSED-ENV','Potential environment file exposure'],
    ['/.git/HEAD','SEC-EXPOSED-GIT','Potential Git metadata exposure'],
    ['/server-status','SEC-SERVER-STATUS','Server status endpoint is public'],
    ['/phpinfo.php','SEC-PHPINFO','phpinfo endpoint is public'],
    ['/openapi.json','INFO-OPENAPI','OpenAPI specification is public'],
    ['/swagger.json','INFO-SWAGGER','Swagger specification is public']
  ];
  const out = [];
  for (const [path, id, title] of probes) {
    try {
      const target = new URL(path, url);
      const response = await safeFetch(target.href, { method: 'HEAD' }, 3200);
      if (response.status >= 200 && response.status < 300) {
        const sensitive = id.startsWith('SEC-');
        out.push(finding(id, sensitive ? 'Security' : 'Discovery', sensitive ? 'High' : 'Informational', title,
          `${path} returned HTTP ${response.status} to an unauthenticated HEAD request.`,
          `HTTP ${response.status}; content-type: ${response.headers.get('content-type') || 'unknown'}`,
          sensitive ? 'Remove the public endpoint or restrict it to trusted administrators.' : 'Review whether public API documentation is intentional.',
          { location: target.href, confidence: 'Medium', engine: 'probe' }));
      }
    } catch {}
  }
  return out;
}

async function linkChecks(baseUrl, html) {
  const $ = cheerio.load(html);
  const links = [];
  $('a[href]').each((_, el) => {
    if (links.length >= 12) return;
    try {
      const u = new URL($(el).attr('href'), baseUrl);
      if (['http:','https:'].includes(u.protocol) && u.hostname === baseUrl.hostname && !links.includes(u.href)) links.push(u.href);
    } catch {}
  });
  const results = [];
  for (const href of links) {
    try {
      const response = await safeFetch(href, { method: 'HEAD' }, 3200);
      results.push({ href, status: response.status });
    } catch { results.push({ href, status: 0 }); }
  }
  return results;
}

function browserFindings(browser, url) {
  const out = [];
  if (!browser.available) {
    out.push(finding('QA-BROWSER-DEGRADED','Quality','Informational','Browser QA engine was unavailable','The HTTP/security scan completed but Chromium checks could not run.',browser.error || 'Browser unavailable','Retry the scan; persistent failures should be reviewed in platform logs.',{location:url.href,confidence:'High',engine:'browser'}));
    return out;
  }
  const a = browser.accessibility || {};
  const add = (id, severity, title, summary, evidence, remediation) =>
    out.push(finding(id,'Quality',severity,title,summary,evidence,remediation,{location:browser.finalUrl || url.href,engine:'browser'}));

  if (a.unlabeledInputs > 0) add('QA-INPUT-LABELS','Medium','Form controls lack accessible labels',`${a.unlabeledInputs} visible form controls have no accessible label.`,`Unlabeled inputs: ${a.unlabeledInputs}`,'Associate labels or aria-label/aria-labelledby with each visible control.');
  if (a.unnamedButtons > 0) add('QA-BUTTON-NAMES','Medium','Buttons lack accessible names',`${a.unnamedButtons} visible buttons have no accessible name.`,`Unnamed buttons: ${a.unnamedButtons}`,'Give every interactive control a visible or programmatic name.');
  if (a.missingAlt > 0) add('QA-IMG-ALT','Medium','Images are missing alt attributes',`${a.missingAlt} images have no alt attribute.`,`Images missing alt: ${a.missingAlt}`,'Add useful alt text to meaningful images and empty alt to decorative images.');
  if (a.horizontalOverflow) add('QA-HORIZONTAL-OVERFLOW','Medium','Horizontal overflow detected','The rendered page is wider than the viewport.','document.scrollWidth exceeds viewport width.','Fix fixed-width or overflowing elements at desktop/mobile breakpoints.');
  if (browser.consoleErrors.length) add('QA-CONSOLE','Low','Browser console errors detected',`${browser.consoleErrors.length} console errors were observed.`,browser.consoleErrors.join('\n').slice(0,4000),'Resolve runtime errors and noisy production logging.');
  if (browser.pageErrors.length) add('QA-PAGE-ERROR','High','Unhandled page errors detected',`${browser.pageErrors.length} page-level JavaScript errors were observed.`,browser.pageErrors.join('\n').slice(0,4000),'Fix unhandled runtime exceptions and add error boundaries.');
  if (browser.failedRequests.length) add('QA-REQUEST-FAIL','Medium','Network requests failed in the browser',`${browser.failedRequests.length} resource/API requests failed during page load.`,browser.failedRequests.map(x=>`${x.method} ${x.url} — ${x.error}`).join('\n').slice(0,5000),'Review failed resources, CORS, API availability and deployment paths.');
  const load = browser.metrics?.loadMs;
  if (load && load > 4000) add('PERF-LOAD','Medium','Page load is slow',`Browser load event completed in about ${load} ms.`,`loadMs: ${load}\nresources: ${browser.metrics.resourceCount}\ntransferBytes: ${browser.metrics.transferBytes}`,'Reduce render-blocking work, large resources and unnecessary network requests.');
  return out;
}

function crawlQualityFindings(pages) {
  const out=[];
  for (const page of pages.slice(1)) {
    if (!page.html) {
      out.push(finding('QA-CRAWL-FAILED','Quality','Medium','Crawled page could not be loaded','A same-host page discovered during crawling did not return usable HTML.',String(page.status || 'network error'),'Review the page URL, redirects, availability and access rules.',{location:page.url,engine:'crawler',confidence:'Medium'}));
      continue;
    }
    const $=cheerio.load(page.html);
    if (!$('title').text().trim()) out.push(finding('QA-TITLE','Quality','Low','Page title is missing','A crawled page has no useful document title.','No non-empty <title> was found.','Add a concise, page-specific title.',{location:page.url,engine:'crawler'}));
    if (!$('html').attr('lang')) out.push(finding('QA-LANG','Quality','Low','Document language is not declared','A crawled page has no html lang attribute.','html[lang] was not present.','Declare the primary document language.',{location:page.url,engine:'crawler'}));
    if (!$('meta[name="viewport"]').length) out.push(finding('QA-VIEWPORT','Quality','Low','Responsive viewport metadata is missing','A crawled page does not declare viewport metadata.','meta[name=viewport] was not found.','Add width=device-width, initial-scale=1.',{location:page.url,engine:'crawler'}));
    const missingAlt=$('img').filter((_,el)=>!$(el).attr('alt')).length;
    if (missingAlt>0) out.push(finding('QA-IMG-ALT','Quality','Medium','Images are missing alt attributes',missingAlt+' images on this page have no alt attribute.','Missing alt count: '+missingAlt,'Add meaningful alt text to informative images and empty alt to decorative images.',{location:page.url,engine:'crawler'}));
  }
  return out;
}

function applyLifecycle(findings, previous) {
  const old = new Map((previous?.findings || []).map((item) => [item.fingerprint, item]));
  for (const item of findings) {
    const prior = old.get(item.fingerprint);
    item.lifecycle = prior ? 'open' : 'new';
    item.workflowStatus = prior?.workflowStatus || 'open';
  }
  const current = new Set(findings.map((item) => item.fingerprint));
  const resolved = (previous?.findings || []).filter((item) => !current.has(item.fingerprint)).map((item) => ({
    ...item, lifecycle: 'resolved', resolvedAt: new Date().toISOString()
  }));
  return { findings, resolved };
}

export async function runFullScan({ url, previousScan = null }) {
  const startedAt = new Date().toISOString();
  const target = new URL(url);
  await assertPublicTarget(target);

  const main = await safeFetch(target.href, { method: 'GET', headers: { accept: 'text/html,application/xhtml+xml' } }, 12000);
  const contentType = main.headers.get('content-type') || '';
  if (!contentType.includes('text/html')) throw new Error(`Target did not return HTML (${contentType || 'unknown'}).`);
  const html = (await main.text()).slice(0, 2500000);
  const finalUrl = new URL(main.url || target.href);

  const [tls, dnsData, cors, probes, links, browser, pages, commonSubdomains] = await Promise.all([
    tlsInfo(finalUrl),
    dnsInfo(finalUrl.hostname).catch(() => ({ a:[], aaaa:[], mx:[], ns:[], txt:[] })),
    corsFindings(finalUrl),
    publicEndpointFindings(finalUrl),
    linkChecks(finalUrl, html),
    runBrowserChecks(finalUrl.href),
    crawlPages(finalUrl.href, html, 8),
    discoverCommonSubdomains(finalUrl.hostname)
  ]);

  const technologies = fingerprintTechnologies(main.headers, html);
  const apiEndpoints = [...new Set(pages.flatMap((page)=>page.html ? extractApiHints(page.url,page.html) : []))].slice(0,100);

  let findings = [
    ...headerFindings(main, html, finalUrl),
    ...cors,
    ...probes,
    ...browserFindings(browser, finalUrl),
    ...crawlQualityFindings(pages)
  ];

  if (tls.enabled) {
    if (tls.error || !tls.authorized) {
      findings.push(finding('TLS-TRUST','Security','High','TLS certificate validation failed','The HTTPS certificate could not be validated.',tls.error || 'Certificate not trusted.','Install a valid publicly trusted certificate and complete the chain.',{location:finalUrl.origin,engine:'tls'}));
    }
    if (tls.validTo) {
      const days = Math.ceil((new Date(tls.validTo).getTime() - Date.now()) / 86400000);
      if (days < 21) findings.push(finding('TLS-EXPIRY','Security',days < 7 ? 'High':'Medium','TLS certificate expires soon',`Certificate expires in about ${days} days.`,`Valid to: ${tls.validTo}`,'Renew and deploy the certificate before expiry.',{location:finalUrl.origin,engine:'tls'}));
    }
  }

  const broken = links.filter((item) => item.status === 0 || item.status >= 400);
  if (broken.length) {
    findings.push(finding('QA-BROKEN-LINKS','Quality','Medium','Broken internal links detected',`${broken.length} of ${links.length} sampled same-host links failed.`,broken.map(x=>`${x.status || 'ERR'} ${x.href}`).join('\n'),'Fix or remove the failing links and retest affected journeys.',{location:finalUrl.href,engine:'crawler'}));
  }

  const lifecycle = applyLifecycle(findings, previousScan);
  findings = lifecycle.findings;
  const summary = summarize(findings);
  const score = scoreFindings(findings);

  const priorities = findings
    .filter((item) => ['Critical','High','Medium'].includes(item.severity))
    .sort((a,b) => ({Critical:5,High:4,Medium:3}[b.severity] - {Critical:5,High:4,Medium:3}[a.severity]))
    .slice(0,5)
    .map((item) => ({ title: item.title, severity: item.severity, checkId: item.checkId }));

  return {
    id: crypto.randomUUID(),
    url: target.href,
    finalUrl: finalUrl.href,
    host: finalUrl.hostname,
    startedAt,
    completedAt: new Date().toISOString(),
    status: 'completed',
    httpStatus: main.status,
    score,
    summary,
    findings,
    resolvedFindings: lifecycle.resolved,
    priorities,
    metrics: {
      pagesCrawled: pages.filter((page)=>page.html).length,
      linksChecked: links.length,
      browserAvailable: browser.available,
      browserLoadMs: browser.metrics?.loadMs || null,
      resourceCount: browser.metrics?.resourceCount || 0,
      transferBytes: browser.metrics?.transferBytes || 0,
      consoleErrors: browser.consoleErrors?.length || 0,
      failedRequests: browser.failedRequests?.length || 0,
      dnsRecords: (dnsData.a?.length || 0) + (dnsData.aaaa?.length || 0) + (dnsData.mx?.length || 0) + (dnsData.ns?.length || 0),
      tlsProtocol: tls.protocol || null,
      apiEndpoints: apiEndpoints.length,
      technologies: technologies.length,
      subdomains: commonSubdomains.length
    },
    evidence: {
      tls,
      dns: dnsData,
      inventory: {
        technologies,
        apiEndpoints,
        commonSubdomains,
        pages: pages.map((page)=>({url:page.url,status:page.status,source:page.source}))
      },
      browser: {
        available: browser.available,
        finalUrl: browser.finalUrl,
        dom: browser.dom,
        metrics: browser.metrics
      }
    }
  };
}

export function dueForSchedule(project, lastScan, now = new Date()) {
  if (!project || project.schedule === 'manual') return false;
  if (!lastScan) return true;
  const ageHours = (now.getTime() - new Date(lastScan.completedAt || lastScan.startedAt).getTime()) / 3600000;
  return project.schedule === 'daily' ? ageHours >= 22 : ageHours >= 24 * 6.5;
}

export function buildExecutiveSummary(scan) {
  if (!scan) return 'No scan data is available yet.';
  const risk = scan.summary.critical + scan.summary.high;
  const quality = scan.findings.filter((f) => f.category === 'Quality' && ['High','Medium'].includes(f.severity)).length;
  const newCount = scan.findings.filter((f) => f.lifecycle === 'new').length;
  const resolved = scan.resolvedFindings?.length || 0;
  const inventory = scan.evidence?.inventory || {};
  return `Assurance score is ${scan.score}/100. The scan found ${risk} critical/high security issues and ${quality} material quality issues across ${scan.metrics.pagesCrawled || 1} crawled pages. ${newCount} findings are new since the previous scan and ${resolved} previously observed findings are no longer present. ${inventory.apiEndpoints?.length || 0} API paths and ${inventory.technologies?.length || 0} technology signals were inventoried.`;
}
