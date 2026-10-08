'use client';

import { useEffect, useMemo, useState } from 'react';

const severityRank = { Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1 };

function Badge({ children, tone = 'neutral' }) {
  return <span className={'badge ' + tone}>{children}</span>;
}

function Severity({ value }) {
  const tone = value === 'Critical' ? 'critical' :
    value === 'High' ? 'high' :
    value === 'Medium' ? 'medium' :
    value === 'Low' ? 'low' : 'info';
  return <Badge tone={tone}>{value}</Badge>;
}

function formatDate(value) {
  if (!value) return '—';
  try { return new Date(value).toLocaleString(); } catch { return value; }
}

export default function Home() {
  const [data, setData] = useState({ projects: [], scans: [], workspace: {} });
  const [tab, setTab] = useState('overview');
  const [selectedProjectId, setSelectedProjectId] = useState('');
  const [selectedScanId, setSelectedScanId] = useState('');
  const [finding, setFinding] = useState(null);
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [retesting, setRetesting] = useState(false);
  const [notice, setNotice] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');

  const [projectForm, setProjectForm] = useState({
    name: '',
    url: '',
    description: '',
    schedule: 'manual'
  });
  const [assetUrl, setAssetUrl] = useState('');
  const [settings, setSettings] = useState({ name: '', schedule: 'manual', webhookUrl: '' });

  async function refresh(preferredProjectId, preferredScanId) {
    setLoading(true);
    try {
      const response = await fetch('/api/workspace', { cache: 'no-store' });
      const next = await response.json();
      if (!response.ok) throw new Error(next.error || 'Could not load workspace.');
      setData(next);

      const projectId = preferredProjectId ||
        selectedProjectId ||
        next.projects?.[0]?.id ||
        '';
      setSelectedProjectId(projectId);

      const projectScans = (next.scans || []).filter((scan) => scan.projectId === projectId);
      const scanId = preferredScanId ||
        selectedScanId ||
        projectScans?.[0]?.id ||
        '';
      setSelectedScanId(scanId);

      const project = next.projects.find((item) => item.id === projectId);
      if (project) setSettings({ name: project.name, schedule: project.schedule, webhookUrl: '' });
    } catch (error) {
      setNotice(error.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { refresh(); }, []);

  const project = useMemo(
    () => data.projects.find((item) => item.id === selectedProjectId) || null,
    [data.projects, selectedProjectId]
  );

  const projectScans = useMemo(
    () => (data.scans || []).filter((item) => item.projectId === selectedProjectId),
    [data.scans, selectedProjectId]
  );

  const scan = useMemo(
    () => projectScans.find((item) => item.id === selectedScanId) || projectScans[0] || null,
    [projectScans, selectedScanId]
  );

  const findings = useMemo(() => {
    if (!scan) return [];
    return [...scan.findings]
      .filter((item) => severityFilter === 'All' || item.severity === severityFilter || item.category === severityFilter || item.lifecycle === severityFilter)
      .sort((a, b) => severityRank[b.severity] - severityRank[a.severity]);
  }, [scan, severityFilter]);

  const dashboard = useMemo(() => {
    const latest = data.projects.map((item) => {
      return (data.scans || [])
        .filter((scanItem) => scanItem.projectId === item.id)
        .sort((a,b) => String(b.completedAt).localeCompare(String(a.completedAt)))[0];
    }).filter(Boolean);
    const scores = latest.map((item) => item.score);
    const open = latest.flatMap((item) => item.findings || []).filter((item) => (item.workflowStatus || 'open') === 'open').length;
    return {
      projects: data.projects.length,
      assets: data.projects.reduce((sum, item) => sum + (item.assets?.length || 0), 0),
      avgScore: scores.length ? Math.round(scores.reduce((a,b) => a+b, 0) / scores.length) : 0,
      open,
      lastScan: latest.sort((a,b)=>String(b.completedAt).localeCompare(String(a.completedAt)))[0]?.completedAt || null
    };
  }, [data]);

  async function api(body) {
    const response = await fetch('/api/workspace', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body)
    });
    const json = await response.json();
    if (!response.ok) throw new Error(json.error || 'Request failed.');
    return json.result;
  }

  async function createProject(event) {
    event.preventDefault();
    setNotice('');
    try {
      const created = await api({ action: 'create_project', ...projectForm });
      setProjectForm({ name:'', url:'', description:'', schedule:'manual' });
      await refresh(created.id);
      setTab('overview');
      setNotice('Project created. Confirm authorization and run the first scan.');
    } catch (error) { setNotice(error.message); }
  }

  async function addAsset(event) {
    event.preventDefault();
    if (!project || !assetUrl) return;
    setNotice('');
    try {
      await api({ action:'add_asset', projectId:project.id, url:assetUrl });
      setAssetUrl('');
      await refresh(project.id);
      setNotice('Asset added.');
    } catch (error) { setNotice(error.message); }
  }

  async function saveSettings(event) {
    event.preventDefault();
    if (!project) return;
    setNotice('');
    try {
      const patch = { name: settings.name, schedule: settings.schedule };
      if (settings.webhookUrl) patch.webhookUrl = settings.webhookUrl;
      await api({ action:'update_project', projectId:project.id, patch });
      setSettings((prev) => ({ ...prev, webhookUrl:'' }));
      await refresh(project.id);
      setNotice('Project settings saved.');
    } catch (error) { setNotice(error.message); }
  }

  async function runScan(assetId) {
    if (!project || !authorized) return;
    const asset = project.assets.find((item) => item.id === assetId) || project.assets[0];
    if (!asset) return;
    setScanning(true);
    setNotice('Running security, browser QA, TLS, DNS and link checks…');
    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'content-type':'application/json' },
        body: JSON.stringify({ projectId:project.id, assetId:asset.id, authorized:true })
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Scan failed.');
      await refresh(project.id, result.id);
      setTab('findings');
      setNotice('Scan completed.');
    } catch (error) {
      setNotice(error.message);
    } finally {
      setScanning(false);
    }
  }

  async function setFindingStatus(status) {
    if (!scan || !finding) return;
    try {
      await api({ action:'finding_status', scanId:scan.id, fingerprint:finding.fingerprint, status });
      setFinding((prev) => ({ ...prev, workflowStatus:status }));
      await refresh(project.id, scan.id);
    } catch (error) { setNotice(error.message); }
  }

  async function retestCurrentFinding() {
    if (!scan || !finding || !authorized) return;
    setRetesting(true);
    setNotice('Retesting this finding against the current asset…');
    try {
      const result = await api({ action:'retest_finding', scanId:scan.id, fingerprint:finding.fingerprint });
      await refresh(project.id, result.scan.id);
      setFinding(result.currentFinding || null);
      setTab('findings');
      setNotice(result.status === 'resolved' ? 'Retest passed: the finding is no longer present.' : 'Retest completed: the finding is still present.');
    } catch (error) {
      setNotice(error.message);
    } finally {
      setRetesting(false);
    }
  }

  function selectProject(id) {
    setSelectedProjectId(id);
    const nextScan = (data.scans || []).find((item) => item.projectId === id);
    setSelectedScanId(nextScan?.id || '');
    const nextProject = data.projects.find((item) => item.id === id);
    if (nextProject) setSettings({ name:nextProject.name, schedule:nextProject.schedule, webhookUrl:'' });
    setFinding(null);
  }

  return (
    <main className="appShell">
      <aside className="sidebar">
        <div className="brand">
          <div className="logo">I</div>
          <div><strong>Inspector</strong><span>Web Security & Quality</span></div>
        </div>

        <nav className="nav">
          {[
            ['overview','Overview'],
            ['assets','Assets'],
            ['scans','Scans'],
            ['findings','Findings'],
            ['quality','Browser QA'],
            ['surface','Discovery'],
            ['reports','Reports'],
            ['settings','Settings']
          ].map(([key,label]) => (
            <button key={key} className={tab === key ? 'active' : ''} onClick={() => setTab(key)}>
              <span>{label}</span>
              {key === 'findings' && scan ? <em>{scan.findings.length}</em> : null}
            </button>
          ))}
        </nav>

        <div className="projectPicker">
          <label>Project</label>
          <select value={selectedProjectId} onChange={(e)=>selectProject(e.target.value)}>
            <option value="">Select project</option>
            {data.projects.map((item)=><option key={item.id} value={item.id}>{item.name}</option>)}
          </select>
        </div>

        <div className="guardrail">
          <strong>Authorized targets only</strong>
          <span>Private-network destinations and unsafe redirect targets are blocked by the scanner.</span>
        </div>
      </aside>

      <section className="main">
        <header className="topbar">
          <div>
            <span className="eyebrow">CONTINUOUS WEB ASSURANCE</span>
            <h1>{project ? project.name : 'Inspector workspace'}</h1>
            <p>{project ? project.description || project.assets?.[0]?.url : 'Security, browser QA, performance and regression tracking in one place.'}</p>
          </div>
          <div className="topActions">
            <Badge tone="success">Live beta</Badge>
            {project?.assets?.[0] ? (
              <button className="primary" disabled={!authorized || scanning} onClick={()=>runScan(project.assets[0].id)}>
                {scanning ? 'Scanning…' : 'Run scan'}
              </button>
            ) : null}
          </div>
        </header>

        <label className="authorization">
          <input type="checkbox" checked={authorized} onChange={(e)=>setAuthorized(e.target.checked)} />
          I confirm I own or have explicit permission to test the selected asset.
        </label>

        {notice ? <div className="notice">{notice}</div> : null}

        {loading ? <div className="loading">Loading workspace…</div> : null}

        {!loading && tab === 'overview' ? (
          <>
            <section className="metricGrid">
              <article><span>Projects</span><strong>{dashboard.projects}</strong><small>monitored workspaces</small></article>
              <article><span>Assets</span><strong>{dashboard.assets}</strong><small>web targets</small></article>
              <article><span>Avg assurance</span><strong>{dashboard.avgScore || '—'}</strong><small>{dashboard.avgScore ? '/100' : 'run a scan'}</small></article>
              <article><span>Open findings</span><strong>{dashboard.open}</strong><small>latest project scans</small></article>
            </section>

            {project && scan ? (
              <>
                <section className="heroResult">
                  <div>
                    <span className="eyebrow">LATEST SCAN</span>
                    <h2>{scan.finalUrl}</h2>
                    <p>{formatDate(scan.completedAt)} · {scan.trigger || 'manual'} · HTTP {scan.httpStatus}</p>
                    <div className="summaryText">{scan.executiveSummary}</div>
                  </div>
                  <div className="scoreRing">
                    <strong>{scan.score}</strong><span>/100</span><small>Assurance</small>
                  </div>
                </section>

                <section className="riskGrid">
                  <article className="risk critical"><span>Critical</span><strong>{scan.summary.critical}</strong></article>
                  <article className="risk high"><span>High</span><strong>{scan.summary.high}</strong></article>
                  <article className="risk medium"><span>Medium</span><strong>{scan.summary.medium}</strong></article>
                  <article className="risk low"><span>Low</span><strong>{scan.summary.low}</strong></article>
                  <article className="risk quality"><span>Resolved</span><strong>{scan.resolvedFindings?.length || 0}</strong></article>
                </section>

                <section className="coveragePanel">
                  <div className="sectionHead"><div><span className="eyebrow">ENGINE COVERAGE</span><h3>What ran</h3></div></div>
                  <div className="coverageGrid">
                    <div><span>Browser QA</span><b>{scan.metrics.browserAvailable ? 'Chromium' : 'Degraded'}</b></div>
                    <div><span>Page load</span><b>{scan.metrics.browserLoadMs ? scan.metrics.browserLoadMs + ' ms' : '—'}</b></div>
                    <div><span>Resources</span><b>{scan.metrics.resourceCount || 0}</b></div>
                    <div><span>Links checked</span><b>{scan.metrics.linksChecked || 0}</b></div>
                    <div><span>DNS records</span><b>{scan.metrics.dnsRecords || 0}</b></div>
                    <div><span>TLS</span><b>{scan.metrics.tlsProtocol || '—'}</b></div>
                  </div>
                </section>
              </>
            ) : (
              <section className="onboarding">
                <div>
                  <span className="eyebrow">GET STARTED</span>
                  <h2>Create your first project</h2>
                  <p>Add an authorized public web target. The platform will persist assets, scans, findings and regression history.</p>
                </div>
                <form onSubmit={createProject} className="formStack">
                  <input placeholder="Project name (optional)" value={projectForm.name} onChange={(e)=>setProjectForm({...projectForm,name:e.target.value})} />
                  <input required placeholder="https://app.example.com" value={projectForm.url} onChange={(e)=>setProjectForm({...projectForm,url:e.target.value})} />
                  <textarea placeholder="Description (optional)" value={projectForm.description} onChange={(e)=>setProjectForm({...projectForm,description:e.target.value})} />
                  <select value={projectForm.schedule} onChange={(e)=>setProjectForm({...projectForm,schedule:e.target.value})}>
                    <option value="manual">Manual scans</option>
                    <option value="daily">Daily monitoring</option>
                    <option value="weekly">Weekly monitoring</option>
                  </select>
                  <button className="primary">Create project</button>
                </form>
              </section>
            )}

            {data.projects.length > 0 && (
              <section className="projectList panel">
                <div className="sectionHead"><div><span className="eyebrow">PORTFOLIO</span><h3>Projects</h3></div></div>
                {data.projects.map((item)=>(
                  <button key={item.id} className={'projectRow ' + (item.id === selectedProjectId ? 'selected' : '')} onClick={()=>selectProject(item.id)}>
                    <div><strong>{item.name}</strong><span>{item.assets?.[0]?.url}</span></div>
                    <div><b>{item.latestScan?.score ?? '—'}</b><small>{item.latestScan ? 'score' : 'not scanned'}</small></div>
                  </button>
                ))}
              </section>
            )}
          </>
        ) : null}

        {!loading && tab === 'assets' ? (
          <section className="panel">
            <div className="sectionHead">
              <div><span className="eyebrow">ATTACK SURFACE</span><h2>Assets</h2><p>Public web targets included in this project.</p></div>
            </div>
            {!project ? <div className="empty">Select or create a project first.</div> : (
              <>
                <div className="assetList">
                  {project.assets.map((asset)=>(
                    <div className="assetRow" key={asset.id}>
                      <div><Badge tone="success">{asset.type}</Badge><strong>{asset.label}</strong><span>{asset.url}</span></div>
                      <button disabled={!authorized || scanning} onClick={()=>runScan(asset.id)}>Scan now</button>
                    </div>
                  ))}
                </div>
                <form className="inlineForm" onSubmit={addAsset}>
                  <input placeholder="https://another.example.com" value={assetUrl} onChange={(e)=>setAssetUrl(e.target.value)} />
                  <button className="secondary">Add asset</button>
                </form>
              </>
            )}
          </section>
        ) : null}

        {!loading && tab === 'scans' ? (
          <section className="panel">
            <div className="sectionHead"><div><span className="eyebrow">HISTORY & REGRESSIONS</span><h2>Scans</h2></div></div>
            {!projectScans.length ? <div className="empty">No scans for this project yet.</div> : (
              <div className="scanList">
                {projectScans.map((item)=>(
                  <button key={item.id} className={'scanRow ' + (item.id === scan?.id ? 'selected' : '')} onClick={()=>{setSelectedScanId(item.id);setTab('findings')}}>
                    <div><strong>{item.finalUrl}</strong><span>{formatDate(item.completedAt)} · {item.trigger}</span></div>
                    <div className="scanStats"><span>Score <b>{item.score}</b></span><span>New <b>{item.findings.filter(f=>f.lifecycle==='new').length}</b></span><span>Resolved <b>{item.resolvedFindings?.length || 0}</b></span></div>
                  </button>
                ))}
              </div>
            )}
          </section>
        ) : null}

        {!loading && tab === 'findings' ? (
          <section className="panel findingsPanel">
            <div className="sectionHead">
              <div><span className="eyebrow">NORMALIZED FINDINGS</span><h2>Findings</h2><p>{scan ? formatDate(scan.completedAt) : 'Run a scan first.'}</p></div>
              <select value={severityFilter} onChange={(e)=>setSeverityFilter(e.target.value)}>
                <option>All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option>
                <option>Security</option><option>Quality</option><option>new</option><option>open</option>
              </select>
            </div>
            {!scan ? <div className="empty">No scan selected.</div> : (
              <div className="tableWrap">
                <table>
                  <thead><tr><th>Finding</th><th>Engine</th><th>Lifecycle</th><th>Severity</th><th>Status</th></tr></thead>
                  <tbody>
                    {findings.map((item)=>(
                      <tr key={item.id} onClick={()=>setFinding(item)}>
                        <td><strong>{item.title}</strong><span>{item.summary}</span></td>
                        <td>{item.engine}</td>
                        <td><Badge tone={item.lifecycle === 'new' ? 'purple' : item.lifecycle === 'resolved' ? 'success' : 'neutral'}>{item.lifecycle}</Badge></td>
                        <td><Severity value={item.severity}/></td>
                        <td>{item.workflowStatus || 'open'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        ) : null}


        {!loading && tab === 'quality' ? (
          <section className="panel">
            <div className="sectionHead"><div><span className="eyebrow">REAL BROWSER ENGINE</span><h2>Browser QA</h2><p>Rendered Chromium signals, runtime errors, network failures and basic accessibility checks.</p></div></div>
            {!scan ? <div className="empty">Run a scan to populate browser QA.</div> : (
              <>
                <div className="coverageGrid">
                  <div><span>Engine</span><b>{scan.metrics.browserAvailable ? 'Chromium' : 'Degraded'}</b></div>
                  <div><span>Load time</span><b>{scan.metrics.browserLoadMs ? scan.metrics.browserLoadMs + ' ms' : '—'}</b></div>
                  <div><span>Resources</span><b>{scan.metrics.resourceCount || 0}</b></div>
                  <div><span>Transfer</span><b>{scan.metrics.transferBytes ? Math.round(scan.metrics.transferBytes/1024) + ' KB' : '—'}</b></div>
                  <div><span>Console errors</span><b>{scan.metrics.consoleErrors || 0}</b></div>
                  <div><span>Failed requests</span><b>{scan.metrics.failedRequests || 0}</b></div>
                </div>
                <div className="assetList">
                  {(scan.findings || []).filter((item)=>item.engine==='browser').map((item)=>(
                    <button className="assetRow" key={item.id} onClick={()=>setFinding(item)}>
                      <div><Severity value={item.severity}/><strong>{item.title}</strong><span>{item.summary}</span></div>
                    </button>
                  ))}
                </div>
              </>
            )}
          </section>
        ) : null}

        {!loading && tab === 'surface' ? (
          <section className="panel">
            <div className="sectionHead"><div><span className="eyebrow">DISCOVERY & INVENTORY</span><h2>Attack surface</h2><p>Crawled pages, API paths, technology signals and common public subdomains observed by the scan.</p></div></div>
            {!scan ? <div className="empty">Run a scan to populate discovery.</div> : (
              <>
                <div className="coverageGrid">
                  <div><span>Pages crawled</span><b>{scan.metrics.pagesCrawled || 0}</b></div>
                  <div><span>API paths</span><b>{scan.metrics.apiEndpoints || 0}</b></div>
                  <div><span>Technologies</span><b>{scan.metrics.technologies || 0}</b></div>
                  <div><span>Subdomains</span><b>{scan.metrics.subdomains || 0}</b></div>
                </div>
                <div className="projectList">
                  <div className="sectionHead"><div><h3>Technology signals</h3></div></div>
                  {(scan.evidence?.inventory?.technologies || []).map((item)=>(
                    <div className="projectRow" key={item.name}><div><strong>{item.name}</strong><span>{item.evidence} · {item.confidence} confidence</span></div></div>
                  ))}
                  <div className="sectionHead"><div><h3>API paths</h3></div></div>
                  {(scan.evidence?.inventory?.apiEndpoints || []).map((path)=>(
                    <div className="projectRow" key={path}><div><strong>{path}</strong><span>Observed in same-host application markup/scripts</span></div></div>
                  ))}
                  <div className="sectionHead"><div><h3>Discovered subdomains</h3></div></div>
                  {(scan.evidence?.inventory?.commonSubdomains || []).map((item)=>(
                    <div className="projectRow" key={item.host}><div><strong>{item.host}</strong><span>{(item.ips || []).join(', ')}</span></div></div>
                  ))}
                  <div className="sectionHead"><div><h3>Crawled pages</h3></div></div>
                  {(scan.evidence?.inventory?.pages || []).map((item)=>(
                    <div className="projectRow" key={item.url}><div><strong>{item.url}</strong><span>HTTP {item.status || 'ERR'} · {item.source}</span></div></div>
                  ))}
                </div>
              </>
            )}
          </section>
        ) : null}

        {!loading && tab === 'reports' ? (
          <section className="panel reportPanel">
            <div><span className="eyebrow">EXECUTIVE + TECHNICAL</span><h2>Reports</h2><p>Export the latest project state for stakeholders or remediation tracking.</p></div>
            {project && scan ? (
              <div className="reportCard">
                <div><strong>{project.name} assurance report</strong><span>Latest scan: {formatDate(scan.completedAt)}</span><p>{scan.executiveSummary}</p></div>
                <a className="primary linkButton" href={'/api/report?projectId=' + encodeURIComponent(project.id)}>Download PDF</a>
              </div>
            ) : <div className="empty">A completed scan is required before a report can be generated.</div>}
          </section>
        ) : null}

        {!loading && tab === 'settings' ? (
          <section className="panel settingsPanel">
            <div className="sectionHead"><div><span className="eyebrow">MONITORING & INTEGRATIONS</span><h2>Project settings</h2></div></div>
            {!project ? <div className="empty">Select a project first.</div> : (
              <form className="settingsForm" onSubmit={saveSettings}>
                <label>Project name<input value={settings.name} onChange={(e)=>setSettings({...settings,name:e.target.value})}/></label>
                <label>Monitoring schedule<select value={settings.schedule} onChange={(e)=>setSettings({...settings,schedule:e.target.value})}>
                  <option value="manual">Manual</option><option value="daily">Daily</option><option value="weekly">Weekly</option>
                </select></label>
                <label>Alert webhook<input type="url" placeholder={project.webhookUrl ? 'Webhook configured — enter a new URL to replace it' : 'https://hooks.slack.com/... or generic HTTPS webhook'} value={settings.webhookUrl} onChange={(e)=>setSettings({...settings,webhookUrl:e.target.value})}/></label>
                <p className="help">New High/Critical findings are POSTed to the configured HTTPS webhook. Daily/weekly projects are evaluated by the scheduled scan dispatcher.</p>
                <button className="primary">Save settings</button>
              </form>
            )}
          </section>
        ) : null}
      </section>

      {finding ? (
        <div className="backdrop" onClick={()=>setFinding(null)}>
          <aside className="drawer" onClick={(e)=>e.stopPropagation()}>
            <button className="close" onClick={()=>setFinding(null)}>×</button>
            <div className="drawerBadges"><Severity value={finding.severity}/><Badge>{finding.engine}</Badge><Badge tone="purple">{finding.lifecycle}</Badge></div>
            <h2>{finding.title}</h2>
            <p className="lead">{finding.summary}</p>
            <section><h4>Why it matters</h4><p>{finding.impact}</p></section>
            <section><h4>Evidence</h4><pre>{finding.evidence}</pre></section>
            <section><h4>Affected location</h4><p>{finding.location || scan?.finalUrl}</p></section>
            <section><h4>Recommended fix</h4><p>{finding.remediation}</p></section>
            <section><h4>Workflow</h4><div className="statusActions">
              <button onClick={()=>setFindingStatus('open')}>Open</button>
              <button onClick={()=>setFindingStatus('resolved')}>Resolved</button>
              <button onClick={()=>setFindingStatus('accepted')}>Accept risk</button>
              <button onClick={()=>setFindingStatus('false_positive')}>False positive</button>
              <button disabled={!authorized || retesting} onClick={retestCurrentFinding}>{retesting ? 'Retesting…' : 'Retest finding'}</button>
            </div></section>
            <div className="drawerFooter"><span>{finding.checkId}</span><span>{finding.confidence} confidence</span></div>
          </aside>
        </div>
      ) : null}
    </main>
  );
}
