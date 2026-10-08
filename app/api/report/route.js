import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';
import { latestScanForProject, readState } from '../../../lib/store';
import { scoreFindings } from '../../../lib/scanner';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 30;

function wrap(text,max=86){
  const words=String(text||'').replace(/\s+/g,' ').trim().split(' ');
  const lines=[]; let line='';
  for(const word of words){
    if(!word) continue;
    if((line+' '+word).trim().length>max){if(line) lines.push(line); line=word;}
    else line=(line+' '+word).trim();
  }
  if(line) lines.push(line);
  return lines;
}
function escapeHtml(value){
  return String(value??'').replace(/[&<>"']/g,(char)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
}
function csvCell(value){
  const text=String(value??'');
  return /[",\n]/.test(text)?'"'+text.replace(/"/g,'""')+'"':text;
}
function reportFindings(sourceFindings,project,scan){
  return [...(sourceFindings||[])].sort((a,b)=>{
    const rank={Critical:5,High:4,Medium:3,Low:2,Informational:1};
    return (rank[b.severity]||0)-(rank[a.severity]||0);
  }).map((finding)=>({
    severity:finding.severity,
    title:finding.title,
    category:finding.category,
    engine:finding.engine,
    target:finding.location||scan.finalUrl||scan.url||scan.target||project.assets?.[0]?.url||'',
    status:finding.workflowStatus||'open',
    summary:finding.summary,
    remediation:finding.remediation,
    checkId:finding.checkId,
    evidence:finding.evidence,
    cve:finding.cve||finding.cveId,
    cvss:finding.cvssScore||finding.cvss,
    cwe:finding.cwe||finding.cweId
  }));
}

function currentWorkspaceFindings(state,project){
  const items=[];
  const latestByAsset=new Map();
  for(const scan of (state.scans||[])
    .filter((item)=>item.projectId===project.id)
    .sort((a,b)=>String(b.completedAt||b.startedAt||'').localeCompare(String(a.completedAt||a.startedAt||'')))){
    if(!latestByAsset.has(scan.assetId)) latestByAsset.set(scan.assetId,scan);
  }
  for(const scan of latestByAsset.values()) items.push(...(scan.findings||[]));

  const auth=project.authScans?.[0];
  if(auth) items.push(...(auth.findings||[]));
  const code=project.codeScans?.[0];
  if(code) items.push(...(code.findings||[]));

  const latestNetworks=new Map();
  for(const scan of project.networkScans||[]){
    if(!latestNetworks.has(scan.networkTargetId)) latestNetworks.set(scan.networkTargetId,scan);
  }
  for(const scan of latestNetworks.values()) items.push(...(scan.findings||[]));

  const map=new Map();
  for(const finding of items){
    const key=finding.fingerprint||finding.id||[finding.engine,finding.checkId,finding.title,finding.location].join('|');
    if(!map.has(key)) map.set(key,finding);
  }
  return [...map.values()];
}

function summarize(findings){
  const out={critical:0,high:0,medium:0,low:0,informational:0};
  for(const finding of findings||[]){
    const key=String(finding.severity||'Informational').toLowerCase();
    if(key in out) out[key]+=1;
  }
  return out;
}

export async function GET(request){
  try{
    const url=new URL(request.url);
    const projectId=url.searchParams.get('projectId');
    const format=(url.searchParams.get('format')||'pdf').toLowerCase();
    const preview=url.searchParams.get('preview')==='1';
    if(!projectId) return new Response('projectId is required',{status:400});

    const state=await readState();
    const project=state.projects.find((item)=>item.id===projectId);
    if(!project) return new Response('Project not found',{status:404});
    const scan=latestScanForProject(state,projectId);
    const rawFindings=currentWorkspaceFindings(state,project);
    if(!scan && !rawFindings.length) return new Response('No completed scan is available',{status:404});

    const fallbackScan=scan||project.networkScans?.[0]||project.authScans?.[0]||project.codeScans?.[0]||{};
    const severityFilter=url.searchParams.get('severity')||'All';
    const statusFilter=url.searchParams.get('status')||'All';
    const section=url.searchParams.get('section')||'all';
    let findings=reportFindings(rawFindings,project,fallbackScan);
    if(severityFilter!=='All') findings=findings.filter((finding)=>finding.severity===severityFilter);
    if(statusFilter==='Open') findings=findings.filter((finding)=>['open','in_progress'].includes(finding.status));
    if(statusFilter==='Accepted') findings=findings.filter((finding)=>finding.status==='accepted');
    if(statusFilter==='Closed') findings=findings.filter((finding)=>['resolved','false_positive'].includes(finding.status));
    if(section==='security') findings=findings.filter((finding)=>finding.severity!=='Informational');
    const summary=summarize(findings);
    const score=findings.length?scoreFindings(findings):(fallbackScan.score||0);
    const executiveSummary='Inspector currently tracks '+findings.length+' normalized risks across '+((project.assets?.length||0)+(project.networks?.length||0))+' registered targets. '+summary.critical+' Critical, '+summary.high+' High and '+summary.medium+' Medium findings are represented in this report.';
    const slug=project.name.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'')||'workspace';

    if(format==='csv'){
      const rows=[
        ['Severity','Title','Category','Engine','Target','Status','Check ID','Summary','Remediation',...(section==='technical'?['Evidence','CVE','CVSS','CWE']:[])],
        ...findings.map(f=>[f.severity,f.title,f.category,f.engine,f.target,f.status,f.checkId,f.summary,f.remediation,...(section==='technical'?[f.evidence,f.cve,f.cvss,f.cwe]:[])])
      ];
      const body=rows.map(row=>row.map(csvCell).join(',')).join('\n');
      return new Response(body,{
        headers:{
          'content-type':'text/csv; charset=utf-8',
          'content-disposition':'attachment; filename="inspector-'+slug+'.csv"',
          'cache-control':'no-store'
        }
      });
    }

    if(format==='html'){
      const cards=[
        ['Critical',summary.critical||0,'#d98af4'],
        ['High',summary.high||0,'#ff6266'],
        ['Medium',summary.medium||0,'#ffb365'],
        ['Low',summary.low||0,'#fae64a']
      ].map(([label,count,color])=>'<div style="background:'+color+';padding:18px;border-radius:10px"><div style="font-size:13px">'+label+'</div><div style="font-size:34px;text-align:right">'+count+'</div></div>').join('');
      const rows=findings.slice(0,200).map((f)=>'<tr><td><strong>'+escapeHtml(f.severity)+'</strong></td><td><strong>'+escapeHtml(f.title)+'</strong><br><span>'+escapeHtml(f.summary)+'</span></td><td>'+escapeHtml(f.target)+'</td><td>'+escapeHtml(f.status)+'</td><td>'+escapeHtml(f.remediation)+'</td></tr>').join('');
      const html='<!doctype html><html><head><meta charset="utf-8"><title>Inspector report</title><style>body{font-family:Arial,sans-serif;color:#172033;margin:0;background:#f3f5f8}.wrap{max-width:1100px;margin:32px auto;background:white;padding:36px;border-radius:12px}.top{display:flex;justify-content:space-between;gap:30px}.score{font-size:48px;font-weight:700}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:26px 0}table{width:100%;border-collapse:collapse;font-size:12px}th,td{text-align:left;vertical-align:top;padding:12px;border-bottom:1px solid #e4e8ee}th{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:#6b7280}td span{font-size:11px;color:#687384;line-height:1.45}.meta{color:#718096;font-size:12px}.summary{line-height:1.6;color:#495565}@media(max-width:700px){.cards{grid-template-columns:1fr 1fr}.top{display:block}}</style></head><body><div class="wrap"><div class="top"><div><div style="font-size:11px;letter-spacing:.15em;color:#6c7481">INSPECTOR SECURITY REPORT</div><h1>'+escapeHtml(project.name)+'</h1><div class="meta">'+escapeHtml(fallbackScan.finalUrl||fallbackScan.url||fallbackScan.target||project.assets?.[0]?.url||'')+' · '+escapeHtml(new Date(fallbackScan.completedAt||fallbackScan.scannedAt||Date.now()).toLocaleString())+'</div></div><div><div class="score">'+escapeHtml(score)+'</div><div class="meta">Assurance score / 100</div></div></div><h2>Executive summary</h2><p class="summary">'+escapeHtml(executiveSummary)+'</p><div class="cards">'+cards+'</div><h2>Findings</h2><table><thead><tr><th>Severity</th><th>Finding</th><th>Target</th><th>Status</th><th>Recommended fix</th></tr></thead><tbody>'+rows+'</tbody></table></div></body></html>';
      return new Response(html,{
        headers:{
          'content-type':'text/html; charset=utf-8',
          'content-disposition':preview?'inline':'attachment; filename="inspector-'+slug+'.html"',
          'cache-control':'no-store'
        }
      });
    }

    const pdf=await PDFDocument.create();
    const regular=await pdf.embedFont(StandardFonts.Helvetica);
    const bold=await pdf.embedFont(StandardFonts.HelveticaBold);
    const pageSize=[612,792];
    let page=pdf.addPage(pageSize);
    let y=742;
    const margin=46;

    const addLine=(text,size=10,font=regular,gap=15)=>{
      if(y<65){page=pdf.addPage(pageSize);y=742;}
      page.drawText(String(text),{x:margin,y,size,font,color:rgb(.12,.14,.18)});
      y-=gap;
    };

    addLine('INSPECTOR — SECURITY REPORT',17,bold,24);
    addLine(project.name,15,bold,20);
    addLine(fallbackScan.finalUrl||fallbackScan.url||fallbackScan.target||project.assets?.[0]?.url||'',9,regular,18);
    addLine('Generated: '+new Date().toISOString(),8,regular,22);
    addLine('Executive summary',12,bold,18);
    for(const line of wrap(executiveSummary)) addLine(line,9,regular,13);
    y-=7;
    addLine('Assurance score: '+score+'/100',14,bold,20);
    addLine('Critical '+(summary.critical||0)+'   High '+(summary.high||0)+'   Medium '+(summary.medium||0)+'   Low '+(summary.low||0),9,regular,22);
    addLine('Top findings',12,bold,18);
    findings.slice(0,30).forEach((finding,index)=>{
      addLine((index+1)+'. ['+finding.severity+'] '+finding.title,9,bold,14);
      for(const line of wrap(finding.summary,90).slice(0,3)) addLine(line,8,regular,11);
      const fix=wrap(finding.remediation,82)[0];
      if(fix) addLine('Fix: '+fix,8,regular,13);
      if(section==='technical'&&finding.evidence) addLine('Evidence: '+wrap(finding.evidence,82)[0],8,regular,13);
      y-=4;
    });
    y-=5;
    addLine('Coverage',12,bold,18);
    addLine('Pages crawled: '+(fallbackScan.metrics?.pagesCrawled||fallbackScan.metrics?.domainPagesCrawled||0),8);
    addLine('Browser renders: '+(fallbackScan.metrics?.browserPages||0),8);
    addLine('API paths observed: '+(fallbackScan.metrics?.apiEndpoints||fallbackScan.metrics?.domainApiEndpoints||0),8);
    addLine('DNS records observed: '+(fallbackScan.metrics?.dnsRecords||0),8);
    addLine('TLS protocol: '+(fallbackScan.metrics?.tlsProtocol||'n/a'),8);

    const bytes=await pdf.save();
    return new Response(bytes,{
      headers:{
        'content-type':'application/pdf',
        'content-disposition':'attachment; filename="inspector-'+slug+'.pdf"',
        'cache-control':'no-store'
      }
    });
  }catch(error){
    return new Response(error.message||'Report generation failed',{status:500});
  }
}
