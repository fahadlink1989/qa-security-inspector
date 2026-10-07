import crypto from 'node:crypto';
import { safeFetch } from './net';

function finding(checkId, category, severity, title, summary, impact, evidence, remediation, confidence = 'High') {
  return {
    id: crypto.randomUUID(),
    checkId,
    category,
    severity,
    title,
    summary,
    impact,
    evidence,
    remediation,
    confidence
  };
}

function count(html, regex) {
  return Array.from(html.matchAll(regex)).length;
}

function stripTags(value = '') {
  return value.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
}

export function score(findings) {
  const weights = { Critical: 25, High: 14, Medium: 7, Low: 3, Informational: 1 };
  const penalty = findings.reduce((total, item) => total + weights[item.severity], 0);
  return Math.max(0, Math.min(100, 100 - penalty));
}

async function sampleInternalLinks(baseUrl, html) {
  const base = new URL(baseUrl);
  const links = [];
  const matches = html.matchAll(/<a\b[^>]*href=["']([^"'#]+)["'][^>]*>/gi);

  for (const match of matches) {
    try {
      const url = new URL(match[1], base);
      if ((url.protocol === 'http:' || url.protocol === 'https:') &&
          url.hostname === base.hostname &&
          !links.includes(url.href)) {
        links.push(url.href);
      }
    } catch {}

    if (links.length >= 6) break;
  }

  const results = [];
  for (const href of links) {
    try {
      const response = await safeFetch(href, { method: 'HEAD' }, 3500);
      results.push({ href, status: response.status });
    } catch {
      results.push({ href, status: 0 });
    }
  }
  return results;
}

export async function analyzeResponse(response, html) {
  const findings = [];
  const headers = response.headers;
  const finalUrl = new URL(response.url);
  const csp = headers.get('content-security-policy') || '';

  if (finalUrl.protocol === 'https:' && !headers.get('strict-transport-security')) {
    findings.push(finding(
      'SEC-HSTS',
      'Security',
      'Medium',
      'HSTS is not enabled',
      'The HTTPS response does not advertise HTTP Strict Transport Security.',
      'Browsers may be more susceptible to downgrade or first-visit interception scenarios.',
      'Strict-Transport-Security header was not present.',
      'Add a Strict-Transport-Security policy after confirming all relevant subdomains support HTTPS.'
    ));
  }

  if (!csp) {
    findings.push(finding(
      'SEC-CSP',
      'Security',
      'High',
      'Content Security Policy is missing',
      'No Content-Security-Policy header was detected.',
      'A strong CSP reduces the impact of cross-site scripting and malicious resource injection.',
      'Content-Security-Policy header was not present.',
      'Define a restrictive CSP using nonces or hashes where appropriate.'
    ));
  }

  if (!headers.get('x-frame-options') && !/frame-ancestors/i.test(csp)) {
    findings.push(finding(
      'SEC-FRAME',
      'Security',
      'Medium',
      'Clickjacking protection is not evident',
      'Neither X-Frame-Options nor CSP frame-ancestors was detected.',
      'The page may be embeddable in an attacker-controlled frame.',
      'No X-Frame-Options header and no frame-ancestors directive in CSP.',
      'Set CSP frame-ancestors to the intended origins.'
    ));
  }

  if ((headers.get('x-content-type-options') || '').toLowerCase() !== 'nosniff') {
    findings.push(finding(
      'SEC-NOSNIFF',
      'Security',
      'Low',
      'MIME sniffing protection is missing',
      'X-Content-Type-Options: nosniff was not detected.',
      'Browsers may infer content types in ways that expand the impact of content-type mistakes.',
      'X-Content-Type-Options was missing or not set to nosniff.',
      'Return X-Content-Type-Options: nosniff.'
    ));
  }

  if (!headers.get('referrer-policy')) {
    findings.push(finding(
      'SEC-REFERRER',
      'Security',
      'Low',
      'Referrer policy is not explicit',
      'No Referrer-Policy header was detected.',
      'URLs and paths may be disclosed to external destinations more broadly than intended.',
      'Referrer-Policy header was not present.',
      'Set an explicit policy such as strict-origin-when-cross-origin.'
    ));
  }

  if (!headers.get('permissions-policy')) {
    findings.push(finding(
      'SEC-PERMISSIONS',
      'Security',
      'Low',
      'Browser feature permissions are not constrained',
      'No Permissions-Policy header was detected.',
      'Unneeded browser capabilities may remain available to page content.',
      'Permissions-Policy header was not present.',
      'Disable or scope browser features your application does not require.',
      'Medium'
    ));
  }

  const server = headers.get('server');
  const poweredBy = headers.get('x-powered-by');
  if (server || poweredBy) {
    findings.push(finding(
      'SEC-BANNER',
      'Security',
      'Low',
      'Technology banner is exposed',
      'The response reveals server or framework information.',
      'Technology disclosure can make reconnaissance easier.',
      'server: ' + (server || '(not set)') + '\nx-powered-by: ' + (poweredBy || '(not set)'),
      'Suppress unnecessary server and framework banners where practical.',
      'Medium'
    ));
  }

  const title = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const lang = html.match(/<html\b[^>]*\blang=["']([^"']+)["']/i);
  const viewport = /<meta\s+[^>]*name=["']viewport["']/i.test(html);
  const h1Count = count(html, /<h1\b[^>]*>/gi);
  const imageCount = count(html, /<img\b[^>]*>/gi);
  const missingAlt = count(html, /<img\b(?![^>]*\balt\s*=)[^>]*>/gi);

  if (!title || !stripTags(title[1])) {
    findings.push(finding(
      'UX-TITLE',
      'Usability',
      'Medium',
      'Page title is missing',
      'The document does not provide a useful title.',
      'Page titles help orientation, browser tabs and accessibility.',
      'No non-empty title element was detected.',
      'Add a concise, page-specific document title.'
    ));
  }

  if (!lang) {
    findings.push(finding(
      'UX-LANG',
      'Usability',
      'Medium',
      'Document language is not declared',
      'The html element has no lang attribute.',
      'Assistive technologies may interpret content incorrectly.',
      'No lang attribute was detected on html.',
      'Set the html lang attribute to the primary language.'
    ));
  }

  if (!viewport) {
    findings.push(finding(
      'UX-VIEWPORT',
      'Usability',
      'Medium',
      'Responsive viewport metadata is missing',
      'The page does not declare a viewport meta tag.',
      'Mobile browsers may render the page at an unexpected scale or width.',
      'No viewport meta tag was detected.',
      'Add width=device-width, initial-scale=1.'
    ));
  }

  if (h1Count === 0) {
    findings.push(finding(
      'UX-H1',
      'Usability',
      'Low',
      'No primary heading was detected',
      'The page has no H1 heading.',
      'A clear primary heading improves page orientation and semantic structure.',
      'H1 count: 0',
      'Add one meaningful top-level heading.'
    ));
  }

  if (missingAlt > 0) {
    findings.push(finding(
      'UX-IMG-ALT',
      'Usability',
      'Medium',
      'Images are missing alt attributes',
      String(missingAlt) + ' of ' + String(imageCount) + ' detected images do not declare alt attributes.',
      'Meaningful images may be inaccessible to screen-reader users.',
      'Images detected: ' + String(imageCount) + '\nImages missing alt attribute: ' + String(missingAlt),
      'Add descriptive alt text for meaningful images and empty alt text for decorative images.'
    ));
  }

  const linkResults = await sampleInternalLinks(response.url, html);
  const broken = linkResults.filter((item) => item.status === 0 || item.status >= 400);
  if (broken.length) {
    findings.push(finding(
      'UX-BROKEN-LINK',
      'Usability',
      'Medium',
      'Broken internal links detected',
      String(broken.length) + ' of ' + String(linkResults.length) + ' sampled internal links failed.',
      'Broken navigation interrupts task completion and can reduce user trust.',
      broken.map((item) => String(item.status || 'ERR') + ' ' + item.href).join('\n'),
      'Fix or remove the failing links, then retest the affected user journeys.'
    ));
  }

  return {
    findings,
    linksChecked: linkResults.length
  };
}
