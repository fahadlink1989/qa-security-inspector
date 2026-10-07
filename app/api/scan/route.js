import crypto from 'node:crypto';
import { assertPublicTarget, safeFetch } from '../../../lib/net';
import { analyzeResponse, score } from '../../../lib/analyze';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 60;

function summarize(findings) {
  return {
    critical: findings.filter((item) => item.severity === 'Critical').length,
    high: findings.filter((item) => item.severity === 'High').length,
    medium: findings.filter((item) => item.severity === 'Medium').length,
    low: findings.filter((item) => item.severity === 'Low').length,
    informational: findings.filter((item) => item.severity === 'Informational').length
  };
}

export async function POST(request) {
  try {
    const body = await request.json();

    if (body.authorized !== true) {
      return Response.json({ error: 'Authorization confirmation is required.' }, { status: 400 });
    }

    if (!body.url || typeof body.url !== 'string') {
      return Response.json({ error: 'A target URL is required.' }, { status: 400 });
    }

    let target;
    try {
      target = new URL(body.url);
    } catch {
      return Response.json({ error: 'Enter a valid URL including https:// or http://.' }, { status: 400 });
    }

    if (!['http:', 'https:'].includes(target.protocol)) {
      return Response.json({ error: 'Only http:// and https:// targets are supported.' }, { status: 400 });
    }

    await assertPublicTarget(target);

    const response = await safeFetch(
      target.href,
      {
        method: 'GET',
        headers: { accept: 'text/html,application/xhtml+xml' }
      },
      10000
    );

    const contentType = response.headers.get('content-type') || '';
    if (!contentType.includes('text/html')) {
      return Response.json(
        { error: 'The target did not return an HTML page (' + (contentType || 'unknown content type') + ').' },
        { status: 422 }
      );
    }

    const declaredLength = Number(response.headers.get('content-length') || 0);
    if (declaredLength > 2000000) {
      return Response.json({ error: 'Page is too large for the MVP scanner (2 MB limit).' }, { status: 422 });
    }

    const html = (await response.text()).slice(0, 2000000);
    const analysis = await analyzeResponse(response, html);
    const findings = analysis.findings;

    const result = {
      id: crypto.randomUUID(),
      url: target.href,
      finalUrl: response.url,
      host: new URL(response.url).hostname,
      scannedAt: new Date().toISOString(),
      httpStatus: response.status,
      score: score(findings),
      summary: summarize(findings),
      findings,
      metrics: {
        securityHeaderChecks: 7,
        usabilityChecks: 5,
        linksChecked: analysis.linksChecked,
        usabilityFindings: findings.filter((item) => item.category === 'Usability').length
      }
    };

    return Response.json(result, {
      headers: { 'cache-control': 'no-store' }
    });
  } catch (error) {
    const message = error && error.name === 'AbortError'
      ? 'The target timed out during the scan.'
      : (error && error.message) || 'Scan failed.';

    return Response.json({ error: message }, { status: 400 });
  }
}
