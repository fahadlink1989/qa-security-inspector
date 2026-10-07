import chromiumBinary from '@sparticuz/chromium';
import { chromium as playwrightChromium } from 'playwright-core';
import { assertPublicTarget } from './net';

export async function runBrowserChecks(targetUrl) {
  const result = {
    engine: 'chromium',
    available: false,
    consoleErrors: [],
    pageErrors: [],
    failedRequests: [],
    badResponses: [],
    metrics: {},
    accessibility: {},
    dom: {},
    finalUrl: targetUrl
  };

  let browser;
  const hostCache = new Map();

  try {
    browser = await playwrightChromium.launch({
      args: chromiumBinary.args,
      executablePath: await chromiumBinary.executablePath(),
      headless: true
    });

    const context = await browser.newContext({
      viewport: { width: 1365, height: 768 },
      userAgent: 'InspectorBrowser/1.0 (+authorized QA checks)'
    });
    const page = await context.newPage();

    await page.route('**/*', async (route) => {
      try {
        const url = new URL(route.request().url());
        if (['data:', 'blob:'].includes(url.protocol)) return route.continue();
        if (!['http:', 'https:'].includes(url.protocol)) return route.abort();
        const key = url.hostname.toLowerCase();
        if (!hostCache.has(key)) {
          await assertPublicTarget(url);
          hostCache.set(key, true);
        }
        return route.continue();
      } catch {
        return route.abort();
      }
    });

    page.on('console', (msg) => {
      if (msg.type() === 'error' && result.consoleErrors.length < 12) {
        result.consoleErrors.push(msg.text().slice(0, 500));
      }
    });
    page.on('pageerror', (error) => {
      if (result.pageErrors.length < 10) result.pageErrors.push(String(error.message || error).slice(0, 500));
    });
    page.on('requestfailed', (request) => {
      if (result.failedRequests.length < 15) {
        result.failedRequests.push({
          url: request.url(),
          method: request.method(),
          error: request.failure()?.errorText || 'failed'
        });
      }
    });
    page.on('response', (response) => {
      if (response.status() >= 400 && result.badResponses.length < 20) {
        result.badResponses.push({ url: response.url(), status: response.status() });
      }
    });

    await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 18000 });
    await page.waitForTimeout(1200);

    result.available = true;
    result.finalUrl = page.url();

    const evaluated = await page.evaluate(() => {
      const all = (selector) => Array.from(document.querySelectorAll(selector));
      const inputs = all('input,select,textarea');
      const buttons = all('button,[role="button"]');
      const images = all('img');
      const forms = all('form');
      const links = all('a[href]');
      const nav = performance.getEntriesByType('navigation')[0];
      const resources = performance.getEntriesByType('resource');
      const labelTextFor = (el) => {
        const id = el.getAttribute('id');
        if (id) {
          const label = document.querySelector('label[for="' + CSS.escape(id) + '"]');
          if (label && label.textContent?.trim()) return true;
        }
        return Boolean(el.closest('label')) ||
          Boolean(el.getAttribute('aria-label')) ||
          Boolean(el.getAttribute('aria-labelledby')) ||
          Boolean(el.getAttribute('title'));
      };
      const visible = (el) => {
        const r = el.getBoundingClientRect();
        const s = getComputedStyle(el);
        return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
      };
      const buttonNamed = (el) => Boolean(
        el.textContent?.trim() ||
        el.getAttribute('aria-label') ||
        el.getAttribute('aria-labelledby') ||
        el.getAttribute('title')
      );

      return {
        title: document.title,
        h1Count: all('h1').length,
        forms: forms.length,
        links: links.length,
        images: images.length,
        inputs: inputs.length,
        buttons: buttons.length,
        unlabeledInputs: inputs.filter((el) => visible(el) && !labelTextFor(el)).length,
        unnamedButtons: buttons.filter((el) => visible(el) && !buttonNamed(el)).length,
        missingAlt: images.filter((el) => !el.hasAttribute('alt')).length,
        horizontalOverflow: document.documentElement.scrollWidth > window.innerWidth + 4,
        insecureForms: forms.filter((form) => {
          try {
            const action = new URL(form.getAttribute('action') || location.href, location.href);
            return location.protocol === 'https:' && action.protocol === 'http:';
          } catch { return false; }
        }).length,
        passwordFields: all('input[type="password"]').length,
        viewport: Boolean(document.querySelector('meta[name="viewport"]')),
        lang: document.documentElement.lang || '',
        metrics: {
          domContentLoadedMs: nav ? Math.round(nav.domContentLoadedEventEnd) : null,
          loadMs: nav ? Math.round(nav.loadEventEnd || nav.duration) : null,
          transferBytes: Math.round(resources.reduce((sum, entry) => sum + (entry.transferSize || 0), 0)),
          resourceCount: resources.length
        }
      };
    });

    result.dom = evaluated;
    result.metrics = evaluated.metrics;
    result.accessibility = {
      unlabeledInputs: evaluated.unlabeledInputs,
      unnamedButtons: evaluated.unnamedButtons,
      missingAlt: evaluated.missingAlt,
      horizontalOverflow: evaluated.horizontalOverflow,
      insecureForms: evaluated.insecureForms
    };

    await context.close();
  } catch (error) {
    result.error = String(error?.message || error).slice(0, 800);
  } finally {
    if (browser) await browser.close().catch(() => {});
  }

  return result;
}
