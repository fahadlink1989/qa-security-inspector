import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';
import { latestScanForProject, readState } from '../../../../lib/store';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 30;

function wrap(text, max = 86) {
  const words = String(text || '').replace(/\s+/g, ' ').trim().split(' ');
  const lines = [];
  let line = '';
  for (const word of words) {
    if (!word) continue;
    if ((line + ' ' + word).trim().length > max) {
      if (line) lines.push(line);
      line = word;
    } else {
      line = (line + ' ' + word).trim();
    }
  }
  if (line) lines.push(line);
  return lines;
}

export async function GET(request) {
  try {
    const projectId = new URL(request.url).searchParams.get('projectId');
    if (!projectId) return new Response('projectId is required', { status: 400 });

    const state = await readState();
    const project = state.projects.find((item) => item.id === projectId);
    if (!project) return new Response('Project not found', { status: 404 });
    const scan = latestScanForProject(state, projectId);
    if (!scan) return new Response('No completed scan is available', { status: 404 });

    const pdf = await PDFDocument.create();
    const regular = await pdf.embedFont(StandardFonts.Helvetica);
    const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
    const pageSize = [612, 792];

    let page = pdf.addPage(pageSize);
    let y = 742;
    const margin = 46;

    const addLine = (text, size = 10, font = regular, gap = 15) => {
      if (y < 65) {
        page = pdf.addPage(pageSize);
        y = 742;
      }
      page.drawText(String(text), { x: margin, y, size, font, color: rgb(0.12,0.14,0.18) });
      y -= gap;
    };

    addLine('INSPECTOR — WEB ASSURANCE REPORT', 17, bold, 24);
    addLine(project.name, 15, bold, 20);
    addLine(scan.finalUrl || scan.url, 9, regular, 18);
    addLine('Generated: ' + new Date().toISOString(), 8, regular, 22);

    addLine('Executive summary', 12, bold, 18);
    for (const line of wrap(scan.executiveSummary || '')) addLine(line, 9, regular, 13);
    y -= 7;

    addLine('Assurance score: ' + scan.score + '/100', 14, bold, 20);
    addLine(
      'Critical ' + scan.summary.critical +
      '   High ' + scan.summary.high +
      '   Medium ' + scan.summary.medium +
      '   Low ' + scan.summary.low,
      9, regular, 22
    );

    addLine('Top findings', 12, bold, 18);
    const rank = { Critical:5, High:4, Medium:3, Low:2, Informational:1 };
    const top = [...scan.findings].sort((a,b) => rank[b.severity] - rank[a.severity]).slice(0, 24);
    top.forEach((finding, index) => {
      addLine((index + 1) + '. [' + finding.severity + '] ' + finding.title, 9, bold, 14);
      for (const line of wrap(finding.summary, 90).slice(0, 3)) addLine(line, 8, regular, 11);
      addLine('Fix: ' + wrap(finding.remediation, 82)[0], 8, regular, 13);
      y -= 4;
    });

    y -= 5;
    addLine('Scan coverage', 12, bold, 18);
    addLine('Links checked: ' + (scan.metrics.linksChecked || 0), 8);
    addLine('Browser engine: ' + (scan.metrics.browserAvailable ? 'available' : 'degraded'), 8);
    addLine('Browser resources: ' + (scan.metrics.resourceCount || 0), 8);
    addLine('DNS records observed: ' + (scan.metrics.dnsRecords || 0), 8);
    addLine('TLS protocol: ' + (scan.metrics.tlsProtocol || 'n/a'), 8);

    const bytes = await pdf.save();
    return new Response(bytes, {
      headers: {
        'content-type': 'application/pdf',
        'content-disposition': 'attachment; filename="inspector-' + project.name.toLowerCase().replace(/[^a-z0-9]+/g,'-') + '.pdf"',
        'cache-control': 'no-store'
      }
    });
  } catch (error) {
    return new Response(error.message || 'Report generation failed', { status: 500 });
  }
}
