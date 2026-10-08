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

function ResultTabs({ scan, active, onChange }) {
  if (!scan) return null;
  const items = [
    ['findings','All findings',scan.findings?.length || 0,true],
    ['attackPaths','Attack paths',scan.attackPaths?.length || 0,scan.mode==='deep'],
    ['exposures','Exposures',(scan.findings || []).filter((item)=>item.category==='Exposure').length,scan.mode==='deep'],
    ['apiSecurity','API security',(scan.findings || []).filter((item)=>item.category==='API Security').length,scan.mode==='deep'],
    ['vulnerabilities','CVEs',scan.metrics?.cvesMatched || 0,scan.mode==='deep'],
    ['quality','Browser QA',null,true],
    ['surface','Discovery',null,true]
  ].filter((item)=>item[3]);

  return (
    <div className="resultNav">
      {items.map(([key,label,count])=>(
        <button key={key} className={active===key?'active':''} onClick={()=>onChange(key)}>
          {label}{count !== null ? <span>{count}</span> : null}
        </button>
      ))}
    </div>
  );
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
  const [activeScanMode, setActiveScanMode] = useState('');
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
  const [codeForm, setCodeForm] = useState({ repositoryUrl:'', token:'', authorized:false });
  const [codeScanning, setCodeScanning] = useState(false);
  const [authForm, setAuthForm] = useState({ method:'bearer', credential:'', authorized:false });
  const [authScanning, setAuthScanning] = useState(false);
  const [scanAssetId, setScanAssetId] = useState('');

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
      if (project) {
        setSettings({ name: project.name, schedule: project.schedule, webhookUrl: '' });
        setScanAssetId((current) => project.assets?.some((asset)=>asset.id===current) ? current : (project.assets?.[0]?.id || ''));
      }
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

  const findingGuidance = useMemo(
    () => finding ? scan?.remediationPlan?.findingGuidance?.[finding.fingerprint] || null : null,
    [scan, finding]
  );

  const latestCodeScan = useMemo(
    () => project?.codeScans?.[0] || null,
    [project]
  );

  const latestAuthScan = useMemo(
    () => project?.authScans?.[0] || null,
    [project]
  );

  const scanAsset = useMemo(
    () => project?.assets?.find((item)=>item.id===scanAssetId) || project?.assets?.[0] || null,
    [project, scanAssetId]
  );

  const hasDeepScan = useMemo(
    () => projectScans.some((item)=>item.mode==='deep'),
    [projectScans]
  );

  const journeyAction = useMemo(() => {
    if (!project) return null;
    if (!projectScans.length) return {
      eyebrow:'STEP 2 OF 4',
      title:'Run your first Baseline Scan',
      text:'Start with a quick baseline to check the selected site, browser behavior, security configuration, TLS/DNS and obvious application issues.',
      cta:'Choose a scan',
      target:'scans'
    };
    if (!hasDeepScan) return {
      eyebrow:'NEXT RECOMMENDED',
      title:'Expand to a Deep Scan',
      text:'Your baseline is ready. Deep Scan discovers the wider public attack surface: subdomains, APIs, exposures, CVEs and attack paths.',
      cta:'Run Deep Scan',
      target:'scans'
    };
    const openPriority=(scan?.findings || []).filter((item)=>['Critical','High','Medium'].includes(item.severity) && !['resolved','accepted','false_positive'].includes(item.workflowStatus || 'open')).length;
    if (openPriority) return {
      eyebrow:'NEXT RECOMMENDED',
      title:'Fix the highest-priority risks',
      text:openPriority+' important finding(s) are still open. Fix Center turns them into implementation and verification steps.',
      cta:'Open Fix Center',
      target:'remediation'
    };
    if (!latestAuthScan) return {
      eyebrow:'OPTIONAL NEXT LAYER',
      title:'Validate what happens after login',
      text:'Use a dedicated test session to compare anonymous vs authenticated behavior and identify protected application/API surfaces.',
      cta:'Set up Authenticated Scan',
      target:'authenticated'
    };
    return {
      eyebrow:'MONITOR',
      title:'Review results and keep monitoring',
      text:'Your major scan layers have run. Review current evidence, retest fixes, and schedule recurring monitoring if needed.',
      cta:'View Results',
      target:'findings'
    };
  }, [project, projectScans, hasDeepScan, scan, latestAuthScan]);

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
      setData((prev) => ({
        ...prev,
        projects: [{ ...created, latestScan: null }, ...(prev.projects || []).filter((item) => item.id !== created.id)]
      }));
      setSelectedProjectId(created.id);
      setSelectedScanId('');
      setSettings({ name: created.name, schedule: created.schedule, webhookUrl: '' });
      setAuthorized(false);
      setScanAssetId(created.assets?.[0]?.id || '');
      setTab('scans');
      setNotice('Project created. Choose the scan you want to run. Start with Baseline Scan, then use Deep Scan for full public attack-surface coverage.');
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

  async function runScan(assetId, mode='standard') {
    if (!project || !authorized) return;
    const asset = project.assets.find((item) => item.id === assetId) || project.assets[0];
    if (!asset) return;
    setScanning(true);
    setActiveScanMode(mode);
    setNotice(mode === 'deep'
      ? 'Deep Scan is discovering public subdomains, live hosts, pages, APIs, technologies, CVEs and remediation actions. This can take several minutes.'
      : 'Running Standard Scan: crawler, browser QA, accessibility, security validation, TLS/DNS and API discovery…');
    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'content-type':'application/json' },
        body: JSON.stringify({ projectId:project.id, assetId:asset.id, authorized:true, mode })
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Scan failed.');
      await refresh(project.id, result.id);
      setTab('findings');
      setNotice(mode === 'deep'
        ? 'Deep Scan completed. Start in Results, then move to Fix Center for prioritized remediation.'
        : 'Baseline Scan completed. Review Results. Run Deep Scan next when you want domain-wide discovery, exposures, CVEs and attack paths.');
    } catch (error) {
      setNotice(error.message);
    } finally {
      setScanning(false);
      setActiveScanMode('');
    }
  }

  async function runAuthenticatedSecurity(event) {
    event.preventDefault();
    if (!project || !project.assets?.length || !authForm.credential || !authForm.authorized) return;
    setAuthScanning(true);
    setNotice('Running authenticated comparison with an ephemeral test session. Credentials will not be persisted…');
    try {
      const asset = project.assets.find((item)=>item.id===scanAssetId) || project.assets[0];
      const response = await fetch('/api/auth-scan', {
        method:'POST',
        headers:{'content-type':'application/json'},
        body:JSON.stringify({
          projectId:project.id,
          assetId:asset.id,
          authorized:true,
          authType:authForm.method,
          credential:authForm.credential
        })
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Authenticated Scan failed.');
      setAuthForm((prev)=>({...prev,credential:''}));
      await refresh(project.id, scan?.id);
      setTab('authenticated');
      setNotice('Authenticated Scan completed. The supplied session credential was not stored.');
    } catch (error) {
      setNotice(error.message);
    } finally {
      setAuthScanning(false);
    }
  }

  async function setAuthFindingStatus(findingItem, status) {
    if (!project || !latestAuthScan || !findingItem) return;
    try {
      await api({
        action:'auth_finding_status',
        projectId:project.id,
        authScanId:latestAuthScan.id,
        fingerprint:findingItem.fingerprint,
        status
      });
      await refresh(project.id, scan?.id);
      setNotice('Authenticated finding marked ' + status.replaceAll('_',' ') + '. Use a fresh test session to validate the fix.');
    } catch (error) {
      setNotice(error.message);
    }
  }

  async function runCodeSecurity(event) {
    event.preventDefault();
    if (!project || !codeForm.repositoryUrl || !codeForm.authorized) return;
    setCodeScanning(true);
    setNotice('Scanning repository files, high-confidence secrets, security-sensitive code sinks and pinned dependencies…');
    try {
      const response = await fetch('/api/code-scan', {
        method:'POST',
        headers:{'content-type':'application/json'},
        body:JSON.stringify({
          projectId:project.id,
          repositoryUrl:codeForm.repositoryUrl,
          token:codeForm.token,
          authorized:true
        })
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Code Security scan failed.');
      setCodeForm((prev)=>({...prev,token:''}));
      await refresh(project.id, scan?.id);
      setTab('codeSecurity');
      setNotice('Code Security scan completed. Repository credentials were not persisted.');
    } catch (error) {
      setNotice(error.message);
    } finally {
      setCodeScanning(false);
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
    if (nextProject) {
      setSettings({ name:nextProject.name, schedule:nextProject.schedule, webhookUrl:'' });
      setScanAssetId(nextProject.assets?.[0]?.id || '');
    }
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
            ['scans','Scan Center'],
            ['findings','Results'],
            ['remediation','Fix Center'],
            ['reports','Reports'],
            ['settings','Settings']
          ].map(([key,label]) => {
            const resultViews=['findings','exposures','apiSecurity','attackPaths','vulnerabilities','quality','surface'];
            const scanViews=['scans','authenticated','codeSecurity'];
            const active = key==='findings' ? resultViews.includes(tab) : key==='scans' ? scanViews.includes(tab) : tab===key;
            return (
              <button key={key} className={active ? 'active' : ''} onClick={() => setTab(key)}>
                <span>{label}</span>
                {key === 'findings' && scan ? <em>{scan.findings.length}</em> : null}
              </button>
            );
          })}
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
            {project?.assets?.length ? <button className="primary" onClick={()=>setTab('scans')}>Start a scan</button> : null}
          </div>
        </header>

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

            {project && journeyAction ? (
              <section className="nextActionCard">
                <div><span className="eyebrow">{journeyAction.eyebrow}</span><h2>{journeyAction.title}</h2><p>{journeyAction.text}</p></div>
                <button className="primary" onClick={()=>setTab(journeyAction.target)}>{journeyAction.cta}</button>
              </section>
            ) : null}

            {project && scan ? (
              <>
                <section className="heroResult">
                  <div>
                    <span className="eyebrow">LATEST SCAN</span>
                    <h2>{scan.finalUrl}</h2>
                    <p>{formatDate(scan.completedAt)} · {scan.scanType || (scan.mode === 'deep' ? 'Deep Scan' : 'Standard Scan')} · {scan.status === 'completed_with_gaps' ? 'Completed with coverage gaps' : scan.status} · HTTP {scan.httpStatus}</p>
                    <div className="summaryText">{scan.executiveSummary}</div>
                  </div>
                  <div className="scoreRing">
                    <strong>{scan.score}</strong><span>/100</span><small>Assurance · {scan.scoreConfidence || 'medium'} confidence</small>
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
                    <div><span>Pages crawled</span><b>{scan.metrics.pagesCrawled || 0}</b></div>
                    <div><span>Browser renders</span><b>{scan.metrics.browserPages || 0}</b></div>
                    <div><span>Mobile renders</span><b>{scan.metrics.browserMobilePages || 0}</b></div>
                    <div><span>A11y violations</span><b>{scan.metrics.accessibilityViolations || 0}</b></div>
                    <div><span>API paths</span><b>{scan.metrics.apiEndpoints || 0}</b></div>
                    <div><span>JS bundles</span><b>{scan.metrics.jsBundles || 0}</b></div>
                    <div><span>Failed requests</span><b>{scan.metrics.failedRequests || 0}</b></div>
                    <div><span>DNS records</span><b>{scan.metrics.dnsRecords || 0}</b></div>
                    <div><span>TLS</span><b>{scan.metrics.tlsProtocol || '—'}</b></div>
                  </div>
                  <div className="engineHealth">
                    {Object.entries(scan.engineStatus || {}).map(([name, state]) => (
                      <div className="engineRow" key={name}>
                        <div><strong>{name}</strong><span>{state.pagesTested ? state.pagesTested + ' pages tested' : state.endpoints ? state.endpoints + ' endpoints' : state.protocol || ''}</span></div>
                        <Badge tone={state.status === 'complete' ? 'success' : state.status === 'failed' ? 'critical' : state.status === 'degraded' ? 'medium' : 'neutral'}>{state.status}</Badge>
                      </div>
                    ))}
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

            {project && !scan && journeyAction ? (
              <section className="nextActionCard">
                <div><span className="eyebrow">{journeyAction.eyebrow}</span><h2>{journeyAction.title}</h2><p>{journeyAction.text}</p></div>
                <button className="primary" onClick={()=>setTab(journeyAction.target)}>{journeyAction.cta}</button>
              </section>
            ) : null}

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
                      <div className="assetActions">
                        <button className="primary" onClick={()=>{setScanAssetId(asset.id);setTab('scans')}}>Scan this asset</button>
                      </div>
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
          <section className="panel scanCenter">
            <div className="sectionHead">
              <div>
                <span className="eyebrow">SCAN CENTER</span>
                <h2>What do you want Inspector to check?</h2>
                <p>Choose a scan based on the question you want answered. We’ll take you to Results automatically when the scan finishes.</p>
              </div>
            </div>

            {!project ? <div className="empty">Create or select a project first.</div> : (
              <>
                <div className="journeyStrip">
                  <div className="done"><span>1</span><strong>Asset</strong><small>{project.assets?.length ? 'Added' : 'Required'}</small></div>
                  <div className={projectScans.length ? 'done' : 'current'}><span>2</span><strong>Scan</strong><small>{projectScans.length ? 'Baseline ready' : 'Choose below'}</small></div>
                  <div className={projectScans.length ? 'current' : ''}><span>3</span><strong>Results</strong><small>Understand risk</small></div>
                  <div><span>4</span><strong>Fix & retest</strong><small>Close the loop</small></div>
                </div>

                <div className="scanTargetBar">
                  <label>
                    <span>Asset to scan</span>
                    <select value={scanAsset?.id || ''} onChange={(e)=>setScanAssetId(e.target.value)}>
                      {(project.assets || []).map((asset)=><option key={asset.id} value={asset.id}>{asset.label} · {asset.url}</option>)}
                    </select>
                  </label>
                  <label className="scanAuthorization">
                    <input type="checkbox" checked={authorized} onChange={(e)=>setAuthorized(e.target.checked)} />
                    <span><strong>Authorization confirmed</strong><small>I own or have explicit permission to test this asset.</small></span>
                  </label>
                </div>

                <div className="scanChoiceGrid">
                  <article className="scanChoice recommended">
                    <div className="scanChoiceTop"><Badge tone="success">Start here</Badge><span>Usually &lt; 1 min</span></div>
                    <h3>Baseline Scan</h3>
                    <p className="scanQuestion">“Is this website configured and behaving safely right now?”</p>
                    <ul>
                      <li>Selected site and linked pages</li>
                      <li>Browser/runtime and accessibility checks</li>
                      <li>Security headers, TLS/DNS and cookies</li>
                      <li>Basic API, JavaScript and broken-link discovery</li>
                    </ul>
                    <div className="scanOutcome"><strong>You’ll get</strong><span>Prioritized findings + browser QA + initial discovery.</span></div>
                    <button className="primary" disabled={!authorized || scanning || !scanAsset} onClick={()=>runScan(scanAsset?.id,'standard')}>
                      {scanning && activeScanMode==='standard' ? 'Running Baseline Scan…' : !authorized ? 'Confirm authorization to run' : 'Run Baseline Scan'}
                    </button>
                  </article>

                  <article className="scanChoice">
                    <div className="scanChoiceTop"><Badge tone="purple">Full public surface</Badge><span>Usually 1–3 min</span></div>
                    <h3>Deep Scan</h3>
                    <p className="scanQuestion">“What can an attacker discover across my public domain?”</p>
                    <ul>
                      <li>Public subdomains and live hosts</li>
                      <li>Pages, APIs, OpenAPI and JavaScript</li>
                      <li>Exposed artifacts, CVEs and configuration issues</li>
                      <li>Correlated attack paths and remediation priorities</li>
                    </ul>
                    <div className="scanOutcome"><strong>You’ll get</strong><span>Domain-wide Results views for Exposures, APIs, CVEs and Attack Paths.</span></div>
                    <button className="primary" disabled={!authorized || scanning || !scanAsset} onClick={()=>runScan(scanAsset?.id,'deep')}>
                      {scanning && activeScanMode==='deep' ? 'Running Deep Scan…' : !authorized ? 'Confirm authorization to run' : 'Run Deep Scan'}
                    </button>
                  </article>

                  <article className="scanChoice">
                    <div className="scanChoiceTop"><Badge tone="medium">Post-login</Badge><span>Best after Deep Scan</span></div>
                    <h3>Authenticated Scan</h3>
                    <p className="scanQuestion">“What changes after a user signs in?”</p>
                    <ul>
                      <li>Uses a dedicated test Bearer token or cookie</li>
                      <li>Compares anonymous vs authenticated access</li>
                      <li>Maps protected pages and APIs</li>
                      <li>Session credential is never persisted</li>
                    </ul>
                    <div className="scanOutcome"><strong>Requires</strong><span>A valid authorized test session. Read-only GET/HEAD checks only.</span></div>
                    <button className="secondary" onClick={()=>setTab('authenticated')}>Set up Authenticated Scan</button>
                  </article>

                  <article className="scanChoice">
                    <div className="scanChoiceTop"><Badge tone="neutral">Source code</Badge><span>GitHub</span></div>
                    <h3>Code Security</h3>
                    <p className="scanQuestion">“Does our repository expose secrets or vulnerable dependencies?”</p>
                    <ul>
                      <li>Committed secret patterns and risky artifacts</li>
                      <li>Pinned dependency advisories / CVEs</li>
                      <li>Security-sensitive code sinks for review</li>
                      <li>Private repo token is optional and never stored</li>
                    </ul>
                    <div className="scanOutcome"><strong>Requires</strong><span>A GitHub repository URL; token only for private repositories.</span></div>
                    <button className="secondary" onClick={()=>setTab('codeSecurity')}>Set up Code Security</button>
                  </article>
                </div>

                <div className="whatNext">
                  <strong>What happens after I click Run?</strong>
                  <span>Inspector scans the selected asset, saves the non-sensitive results to this project, then opens <b>Results</b>. From there, <b>Fix Center</b> explains what to change and how to verify the fix.</span>
                </div>

                <div className="scanHistoryBlock">
                  <div className="sectionHead"><div><span className="eyebrow">HISTORY</span><h3>Previous web scans</h3><p>Open any completed scan to compare findings and regressions.</p></div></div>
                  {!projectScans.length ? <div className="empty">No web scans yet. Start with Baseline Scan above.</div> : (
                    <div className="scanList">
                      {projectScans.map((item)=>(
                        <button key={item.id} className={'scanRow ' + (item.id === scan?.id ? 'selected' : '')} onClick={()=>{setSelectedScanId(item.id);setTab('findings')}}>
                          <div><strong>{item.scanType || (item.mode==='deep'?'Deep Scan':'Baseline Scan')}</strong><span>{item.finalUrl} · {formatDate(item.completedAt)} · {item.status === 'completed_with_gaps' ? 'completed with gaps' : item.status}</span></div>
                          <div className="scanStats"><span>Score <b>{item.score}</b></span><span>New <b>{item.findings.filter(f=>f.lifecycle==='new').length}</b></span><span>Resolved <b>{item.resolvedFindings?.length || 0}</b></span></div>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </>
            )}
          </section>
        ) : null}

        {!loading && tab === 'findings' ? (
          <section className="panel findingsPanel">
            <div className="sectionHead">
              <div><span className="eyebrow">SCAN RESULTS</span><h2>Results</h2><p>{scan ? (scan.scanType+' · '+formatDate(scan.completedAt)) : 'Run a scan first.'}</p></div>
              <select value={severityFilter} onChange={(e)=>setSeverityFilter(e.target.value)}>
                <option>All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option>
                <option>Security</option><option>Quality</option><option>new</option><option>open</option>
              </select>
            </div>
            <ResultTabs scan={scan} active="findings" onChange={setTab} />
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
                        <td><span>{item.workflowStatus || 'open'}</span><small className="evidenceMeta">{item.confidence} · {item.evidenceQuality || 'observed'}</small></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        ) : null}




        {!loading && tab === 'exposures' ? (
          <section className="panel">
            <div className="sectionHead">
              <div><span className="eyebrow">VALIDATED INTERNET EXPOSURES</span><h2>Exposures</h2><p>Public artifacts, administrative surfaces, debug endpoints and DNS conditions validated with low-impact requests.</p></div>
            </div>
            <ResultTabs scan={scan} active="exposures" onChange={setTab} />
            {!scan ? <div className="empty">Run a scan first.</div> : scan.mode !== 'deep' ? (
              <div className="empty">Run Deep Scan to validate exposures across discovered public hosts.</div>
            ) : (
              <>
                <div className="coverageGrid">
                  <div><span>Exposure findings</span><b>{scan.metrics.exposuresValidated || 0}</b></div>
                  <div><span>Hosts tested</span><b>{scan.evidence?.deep?.exposureValidation?.hostsTested || 0}</b></div>
                  <div><span>Live hosts</span><b>{scan.metrics.liveHosts || 0}</b></div>
                  <div><span>Attack paths</span><b>{scan.metrics.attackPaths || 0}</b></div>
                </div>
                <div className="assetList">
                  {(scan.findings || []).filter((item)=>item.category==='Exposure').length ? (
                    (scan.findings || []).filter((item)=>item.category==='Exposure').map((item)=>(
                      <button className="assetRow" key={item.id} onClick={()=>setFinding(item)}>
                        <div><Severity value={item.severity}/><strong>{item.title}</strong><span>{item.summary}</span></div>
                        <Badge tone={item.evidenceQuality === 'validated' ? 'success' : 'medium'}>{item.evidenceQuality}</Badge>
                      </button>
                    ))
                  ) : <div className="empty">No validated high-confidence exposure finding was produced by this Deep Scan.</div>}
                </div>
              </>
            )}
          </section>
        ) : null}

        {!loading && tab === 'apiSecurity' ? (
          <section className="panel">
            <div className="sectionHead">
              <div><span className="eyebrow">SAFE AUTHORIZATION VALIDATION</span><h2>API Security</h2><p>Inspector tests only safe first-party GET/HEAD endpoints and never sends state-changing API payloads.</p></div>
            </div>
            <ResultTabs scan={scan} active="apiSecurity" onChange={setTab} />
            {!scan ? <div className="empty">Run a scan first.</div> : scan.mode !== 'deep' ? (
              <div className="empty">Run Deep Scan to classify and safely validate discovered APIs.</div>
            ) : (
              <>
                <div className="coverageGrid">
                  <div><span>Domain APIs</span><b>{scan.metrics.domainApiEndpoints || 0}</b></div>
                  <div><span>Safely tested</span><b>{scan.metrics.apiSecurityEndpointsTested || 0}</b></div>
                  <div><span>Security findings</span><b>{(scan.findings || []).filter((item)=>item.category==='API Security').length}</b></div>
                  <div><span>OpenAPI sources</span><b>{(scan.evidence?.deep?.hosts || []).reduce((sum,h)=>sum+(h.openApiSpecs?.length || 0),0)}</b></div>
                </div>
                <div className="assetList">
                  {(scan.findings || []).filter((item)=>item.category==='API Security').map((item)=>(
                    <button className="assetRow" key={item.id} onClick={()=>setFinding(item)}>
                      <div><Severity value={item.severity}/><strong>{item.title}</strong><span>{item.summary}</span></div>
                    </button>
                  ))}
                  {!(scan.findings || []).some((item)=>item.category==='API Security') ? <div className="empty">No unauthenticated API exposure was validated in the endpoints safe to test.</div> : null}
                </div>
                <div className="projectList">
                  <div className="sectionHead"><div><h3>Validated endpoint responses</h3></div></div>
                  {(scan.evidence?.deep?.apiSecurity?.coverage || []).slice(0,80).map((item)=>(
                    <div className="projectRow" key={item.url}>
                      <div><strong>HTTP {item.status} · {item.endpoint?.classification || 'Unknown'} · {item.url}</strong><span>{item.bodyKind}{item.sensitiveKeys?.length ? ' · sensitive field names: '+item.sensitiveKeys.join(', ') : ''}</span></div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </section>
        ) : null}

        {!loading && tab === 'attackPaths' ? (
          <section className="panel">
            <div className="sectionHead">
              <div><span className="eyebrow">EVIDENCE → CORRELATION → IMPACT</span><h2>Attack Paths</h2><p>Correlated public evidence that could create a plausible route to application, account or infrastructure impact. Modeled steps are clearly labeled.</p></div>
            </div>
            <ResultTabs scan={scan} active="attackPaths" onChange={setTab} />
            {!scan ? <div className="empty">Run a scan first.</div> : scan.mode !== 'deep' ? (
              <div className="empty">Run Deep Scan to correlate domain-wide evidence into attack paths.</div>
            ) : (scan.attackPaths || []).length ? (
              <div className="pathList">
                {(scan.attackPaths || []).map((path)=>(
                  <article className="pathCard" key={path.id}>
                    <div className="pathHead">
                      <div><Severity value={path.risk}/><h3>{path.title}</h3></div>
                      <div><Badge>{path.confidence} confidence</Badge><Badge tone={path.status === 'validated' ? 'success' : 'medium'}>{path.status}</Badge></div>
                    </div>
                    <p>{path.summary}</p>
                    <div className="pathSteps">
                      {(path.steps || []).map((step,index)=>(
                        <div className={'pathStep '+step.type} key={index}>
                          <Badge tone={step.type === 'observed' ? 'success' : step.type === 'impact' ? 'high' : step.type === 'correlated' ? 'purple' : 'medium'}>{step.type}</Badge>
                          <strong>{step.label}</strong>
                          <span>{step.evidence}</span>
                        </div>
                      ))}
                    </div>
                    <div className="pathImpact"><strong>Potential impact</strong><p>{path.impact}</p></div>
                    <div className="pathImpact"><strong>Recommended action</strong><p>{path.remediation}</p></div>
                  </article>
                ))}
              </div>
            ) : <div className="empty">No meaningful multi-step attack path was correlated from this scan.</div>}
          </section>
        ) : null}

        {!loading && tab === 'codeSecurity' ? (
          <section className="panel">
            <div className="sectionHead">
              <div><span className="eyebrow">SCAN CENTER / CODE SECURITY</span><h2>Code Security</h2><p>Scan an authorized GitHub repository for committed secrets, risky artifacts, security-sensitive sinks and pinned dependency advisories.</p><button className="textLink" onClick={()=>setTab('scans')}>← Back to Scan Center</button></div>
              {latestCodeScan?.remediationPlan?.mode ? <Badge tone={latestCodeScan.remediationPlan.mode === 'ai' ? 'success' : 'neutral'}>{latestCodeScan.remediationPlan.mode === 'ai' ? 'OpenAI generated fixes' : 'Rules remediation'}</Badge> : null}
            </div>
            {!project ? <div className="empty">Select a project first.</div> : (
              <>
                <form className="settingsForm codeForm" onSubmit={runCodeSecurity}>
                  <label>GitHub repository URL<input type="url" required placeholder="https://github.com/org/repository" value={codeForm.repositoryUrl} onChange={(e)=>setCodeForm({...codeForm,repositoryUrl:e.target.value})}/></label>
                  <label>Private repository token (optional)<input type="password" autoComplete="off" placeholder="Used only for this request; never stored" value={codeForm.token} onChange={(e)=>setCodeForm({...codeForm,token:e.target.value})}/></label>
                  <label className="confirm"><input type="checkbox" checked={codeForm.authorized} onChange={(e)=>setCodeForm({...codeForm,authorized:e.target.checked})}/>I own this repository or have explicit permission to scan its source.</label>
                  <p className="help">Inspector never persists the supplied GitHub token or secret values found in files. Secret findings contain only pattern type, file and line.</p>
                  <button className="primary" disabled={!codeForm.authorized || codeScanning}>{codeScanning ? 'Scanning repository…' : 'Run Code Security'}</button>
                </form>

                {latestCodeScan ? (
                  <>
                    <div className="coverageGrid codeMetrics">
                      <div><span>Repository files</span><b>{latestCodeScan.stats?.repositoryFiles || 0}</b></div>
                      <div><span>Files inspected</span><b>{latestCodeScan.stats?.filesScanned || 0}</b></div>
                      <div><span>Dependencies checked</span><b>{latestCodeScan.stats?.dependenciesChecked || 0}</b></div>
                      <div><span>Advisories</span><b>{latestCodeScan.stats?.advisories || 0}</b></div>
                    </div>
                    <div className="fixSummary"><strong>{latestCodeScan.repository?.owner}/{latestCodeScan.repository?.repo}</strong><p>{latestCodeScan.remediationPlan?.executiveSummary || 'Review findings below.'}</p><span>{formatDate(latestCodeScan.scannedAt)} · {latestCodeScan.private ? 'private repository' : 'public repository'}</span></div>
                    <div className="assetList">
                      {(latestCodeScan.findings || []).map((item)=>(
                        <div className="assetRow" key={item.id}>
                          <div><Severity value={item.severity}/><strong>{item.title}</strong><span>{item.location} · {item.summary}</span><small className="evidenceMeta">{item.confidence} · {item.evidenceQuality}</small></div>
                          <div className="codeFix"><strong>Fix</strong><span>{item.remediation}</span></div>
                        </div>
                      ))}
                      {!(latestCodeScan.findings || []).length ? <div className="empty">No high-confidence repository finding was detected within the bounded code scan.</div> : null}
                    </div>
                  </>
                ) : <div className="empty">No Code Security scan has been run for this project yet.</div>}
              </>
            )}
          </section>
        ) : null}


        {!loading && tab === 'authenticated' ? (
          <section className="panel authPanel">
            <div className="sectionHead">
              <div>
                <span className="eyebrow">SCAN CENTER / POST-LOGIN VALIDATION</span>
                <h2>Authenticated Scan</h2>
                <p>Compare public and authenticated behavior using a dedicated test session. Inspector sends only read-only GET/HEAD requests and never persists the credential.</p>
                <button className="textLink" onClick={()=>setTab('scans')}>← Back to Scan Center</button>
              </div>
              <div className="authBadges">
                {latestAuthScan ? <Badge tone={latestAuthScan.status === 'completed' ? 'success' : 'medium'}>{latestAuthScan.status === 'completed_with_gaps' ? 'Completed with gaps' : latestAuthScan.status}</Badge> : null}
                {latestAuthScan?.remediationPlan?.mode ? <Badge tone={latestAuthScan.remediationPlan.mode === 'ai' ? 'success' : 'neutral'}>{latestAuthScan.remediationPlan.mode === 'ai' ? 'OpenAI fixes' : 'Rules fixes'}</Badge> : null}
              </div>
            </div>

            {!project ? <div className="empty">Select a project first.</div> : (
              <>
                <form className="settingsForm authForm" onSubmit={runAuthenticatedSecurity}>
                  <label>Session type
                    <select value={authForm.method} onChange={(e)=>setAuthForm({...authForm,method:e.target.value})}>
                      <option value="bearer">Bearer token</option>
                      <option value="cookie">Cookie header</option>
                    </select>
                  </label>
                  <label>{authForm.method === 'cookie' ? 'Cookie header' : 'Bearer token'}
                    <input
                      type="password"
                      autoComplete="off"
                      placeholder={authForm.method === 'cookie' ? 'session=…; other_cookie=…' : 'eyJ… or application test token'}
                      value={authForm.credential}
                      onChange={(e)=>setAuthForm({...authForm,credential:e.target.value})}
                    />
                  </label>
                  <label className="confirm"><input type="checkbox" checked={authForm.authorized} onChange={(e)=>setAuthForm({...authForm,authorized:e.target.checked})}/>I confirm this is an authorized test account/session and I have permission to assess post-login behavior.</label>
                  <p className="help">The credential is kept in memory only for this request, injected only into first-party requests, and removed from the UI immediately after completion. It is never written to project state or scan history.</p>
                  <button className="primary" disabled={!authForm.authorized || !authForm.credential || authScanning}>{authScanning ? 'Authenticated scanning…' : 'Run Authenticated Scan'}</button>
                </form>

                {latestAuthScan ? (
                  <>
                    <div className="coverageGrid authMetrics">
                      <div><span>Authenticated pages</span><b>{latestAuthScan.metrics?.authenticatedPages || 0}</b></div>
                      <div><span>Protected pages</span><b>{latestAuthScan.metrics?.protectedPages || 0}</b></div>
                      <div><span>APIs compared</span><b>{latestAuthScan.metrics?.endpointsTested || 0}</b></div>
                      <div><span>Protected APIs</span><b>{latestAuthScan.metrics?.protectedEndpoints || 0}</b></div>
                      <div><span>Needs validation</span><b>{latestAuthScan.metrics?.suspiciousPublicEndpoints || 0}</b></div>
                      <div><span>Browser renders</span><b>{latestAuthScan.metrics?.browserPages || 0}</b></div>
                      <div><span>Session effect</span><b>{latestAuthScan.metrics?.sessionEffectConfirmed ? 'Confirmed' : 'Unconfirmed'}</b></div>
                    </div>

                    <div className="fixSummary">
                      <strong>Authenticated coverage</strong>
                      <p>{latestAuthScan.executiveSummary}</p>
                      <span>{formatDate(latestAuthScan.completedAt)} · {latestAuthScan.auth?.method} session · credential not persisted</span>
                    </div>

                    <div className="sectionHead authSubhead"><div><h3>Authorization findings</h3><p>Only findings supported by public-vs-authenticated comparison are shown here.</p></div></div>
                    <div className="assetList">
                      {(latestAuthScan.findings || []).length ? (latestAuthScan.findings || []).map((item)=>(
                        <div className="assetRow authFindingRow" key={item.id}>
                          <div><Severity value={item.severity}/><strong>{item.title}</strong><span>{item.summary}</span><small className="evidenceMeta">{item.location} · {item.confidence} · {item.evidenceQuality} · {item.workflowStatus || 'open'}</small></div>
                          <div className="authFindingActions">
                            <div className="codeFix"><strong>Fix</strong><span>{latestAuthScan.remediationPlan?.findingGuidance?.[item.fingerprint]?.fixSummary || item.remediation}</span></div>
                            <div className="miniStatusActions">
                              <button onClick={()=>setAuthFindingStatus(item,'open')}>Open</button>
                              <button onClick={()=>setAuthFindingStatus(item,'in_progress')}>In progress</button>
                              <button onClick={()=>setAuthFindingStatus(item,'resolved')}>Resolved</button>
                              <button onClick={()=>setAuthFindingStatus(item,'accepted')}>Accept</button>
                              <button onClick={()=>setAuthFindingStatus(item,'false_positive')}>False positive</button>
                            </div>
                          </div>
                        </div>
                      )) : <div className="empty">No authorization weakness was validated with the supplied session.</div>}
                    </div>

                    {(latestAuthScan.remediationPlan?.actions || []).length ? (
                      <div className="authRemediation">
                        <div className="sectionHead authSubhead"><div><h3>Fix authenticated risks</h3><p>Grounded remediation for the current post-login findings. A fresh test session is required for re-validation.</p></div></div>
                        <div className="actionList">
                          {latestAuthScan.remediationPlan.actions.slice(0,6).map((action)=>(
                            <article className="actionCard" key={action.id}>
                              <div className="actionHead">
                                <div><Badge tone={action.priority === 'P0' ? 'critical' : action.priority === 'P1' ? 'high' : action.priority === 'P2' ? 'medium' : 'neutral'}>{action.priority}</Badge><h3>{action.title}</h3></div>
                                <div className="actionOwner"><span>{action.owner}</span><small>{action.effort}</small></div>
                              </div>
                              <p>{action.why}</p>
                              <div className="actionColumns">
                                <div><strong>Implementation</strong><ol>{(action.steps || []).map((step,i)=><li key={i}>{step}</li>)}</ol></div>
                                <div><strong>Verify</strong><ol>{(action.verification || []).map((step,i)=><li key={i}>{step}</li>)}</ol></div>
                              </div>
                            </article>
                          ))}
                        </div>
                      </div>
                    ) : null}

                    <div className="authColumns">
                      <div className="projectList">
                        <div className="sectionHead"><div><h3>Protected pages</h3></div></div>
                        {(latestAuthScan.protectedSurface?.pages || []).length ? (latestAuthScan.protectedSurface.pages || []).map((item)=>(
                          <div className="projectRow" key={item.url}><div><strong>{item.url}</strong><span>Public HTTP {item.unauthStatus ?? '—'} → session HTTP {item.authStatus ?? '—'}{item.title ? ' · '+item.title : ''}</span></div></div>
                        )) : <div className="empty">No page was confirmed as session-protected in this run.</div>}
                      </div>

                      <div className="projectList">
                        <div className="sectionHead"><div><h3>Protected APIs</h3></div></div>
                        {(latestAuthScan.protectedSurface?.endpoints || []).length ? (latestAuthScan.protectedSurface.endpoints || []).map((item)=>(
                          <div className="projectRow" key={item.method+' '+item.url}><div><strong>{item.method} {item.url}</strong><span>{item.classification} · public HTTP {item.unauthStatus ?? '—'} → session HTTP {item.authStatus ?? '—'}</span></div></div>
                        )) : <div className="empty">No API endpoint was confirmed as session-protected in this run.</div>}
                      </div>
                    </div>

                    <div className="projectList">
                      <div className="sectionHead"><div><h3>Endpoint comparison</h3><p>Response values are not stored; only status, schema-like field names and comparison signals are retained.</p></div></div>
                      {(latestAuthScan.endpointCoverage || []).slice(0,100).map((item)=>(
                        <div className="projectRow" key={item.method+' '+item.url}>
                          <div><strong>{item.method} {item.url}</strong><span>{item.classification || 'Unknown'} · public {item.unauthStatus ?? '—'} · session {item.authStatus ?? '—'}{item.protected ? ' · protected' : ''}{item.sameAsUnauthenticated ? ' · same response signature' : ''}</span></div>
                        </div>
                      ))}
                    </div>
                  </>
                ) : (
                  <div className="empty">Run Deep Scan first for the richest endpoint inventory, then use a dedicated test session here to validate the post-login surface.</div>
                )}
              </>
            )}
          </section>
        ) : null}

        {!loading && tab === 'vulnerabilities' ? (
          <section className="panel">
            <div className="sectionHead">
              <div><span className="eyebrow">VERSION-AWARE CVE ENRICHMENT</span><h2>Vulnerabilities</h2><p>CVEs are shown only when Inspector has a versioned technology match that can be checked against NVD.</p></div>
            </div>
            <ResultTabs scan={scan} active="vulnerabilities" onChange={setTab} />
            {!scan ? <div className="empty">Run a scan first.</div> : scan.mode !== 'deep' ? (
              <div className="empty">Run Deep Scan to perform version-aware CVE enrichment across discovered hosts.</div>
            ) : (
              <>
                <div className="coverageGrid">
                  <div><span>Products queried</span><b>{scan.metrics.cveProductsQueried || 0}</b></div>
                  <div><span>CVEs matched</span><b>{scan.metrics.cvesMatched || 0}</b></div>
                  <div><span>Hosts scanned</span><b>{scan.metrics.hostsScanned || 0}</b></div>
                  <div><span>Domain pages</span><b>{scan.metrics.domainPagesCrawled || 0}</b></div>
                </div>
                <div className="vulnList">
                  {(scan.evidence?.deep?.cves?.vulnerabilities || []).length ? (
                    (scan.evidence.deep.cves.vulnerabilities || []).map((item)=>(
                      <article className="vulnCard" key={item.id}>
                        <div className="vulnTop">
                          <div><strong>{item.id}</strong><span>{item.technology} {item.version}</span></div>
                          <div className="cvss"><b>{item.cvss?.score ?? '—'}</b><span>CVSS</span></div>
                        </div>
                        <p>{item.description}</p>
                        <div className="vulnMeta">
                          <Badge tone={(item.cvss?.score || 0) >= 9 ? 'critical' : (item.cvss?.score || 0) >= 7 ? 'high' : (item.cvss?.score || 0) >= 4 ? 'medium' : 'low'}>{item.cvss?.severity || 'Unscored'}</Badge>
                          <span>{(item.cwes || []).join(', ') || 'CWE not specified'}</span>
                        </div>
                        <p className="help">Recommended action: confirm the deployed version, review the vendor/NVD advisory, upgrade outside the affected range, then rerun Deep Scan.</p>
                      </article>
                    ))
                  ) : <div className="empty">No CVEs were matched to the versioned technologies Inspector could confidently identify.</div>}
                  {(scan.evidence?.deep?.cves?.errors || []).length ? (
                    <div className="notice">CVE lookup was incomplete for {scan.evidence.deep.cves.errors.length} detected product(s). Inspector did not invent fallback CVEs.</div>
                  ) : null}
                </div>
              </>
            )}
          </section>
        ) : null}

        {!loading && tab === 'remediation' ? (
          <section className="panel fixCenter">
            <div className="sectionHead">
              <div><span className="eyebrow">OPENAI REMEDIATION COPILOT</span><h2>Fix Center</h2><p>Prioritized actions grounded in the current scan evidence, with ownership and verification steps.</p></div>
              {scan?.remediationPlan?.mode ? <Badge tone={scan.remediationPlan.mode === 'ai' ? 'success' : 'neutral'}>{scan.remediationPlan.mode === 'ai' ? 'OpenAI generated' : 'Rules fallback'}</Badge> : null}
            </div>
            {!scan ? <div className="empty">Run a scan first.</div> : (
              <>
                <div className="fixSummary">
                  <strong>What to do next</strong>
                  <p>{scan.remediationPlan?.executiveSummary || scan.executiveSummary}</p>
                </div>
                <div className="actionList">
                  {(scan.remediationPlan?.actions || []).length ? scan.remediationPlan.actions.map((action)=>(
                    <article className="actionCard" key={action.id}>
                      <div className="actionHead">
                        <div><Badge tone={action.priority === 'P0' ? 'critical' : action.priority === 'P1' ? 'high' : action.priority === 'P2' ? 'medium' : 'neutral'}>{action.priority}</Badge><h3>{action.title}</h3></div>
                        <div className="actionOwner"><span>{action.owner}</span><small>{action.effort}</small></div>
                      </div>
                      <p>{action.why}</p>
                      <div className="actionColumns">
                        <div><strong>Implementation</strong><ol>{(action.steps || []).map((step,i)=><li key={i}>{step}</li>)}</ol></div>
                        <div><strong>Verify the fix</strong><ol>{(action.verification || []).map((step,i)=><li key={i}>{step}</li>)}</ol></div>
                      </div>
                      <div className="actionLinks"><span>{(action.relatedFindings || []).length} linked finding(s)</span>{(action.relatedCves || []).length ? <span>{action.relatedCves.join(', ')}</span> : null}</div>
                    </article>
                  )) : <div className="empty">No prioritized remediation actions were generated for this scan.</div>}
                </div>
              </>
            )}
          </section>
        ) : null}

        {!loading && tab === 'quality' ? (
          <section className="panel">
            <div className="sectionHead"><div><span className="eyebrow">REAL BROWSER ENGINE</span><h2>Browser QA</h2><p>Rendered Chromium signals, runtime errors, network failures and basic accessibility checks.</p></div></div>
            <ResultTabs scan={scan} active="quality" onChange={setTab} />
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
                  {(scan.findings || []).filter((item)=>['browser','browser-mobile','browser-performance','axe'].includes(item.engine)).map((item)=>(
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
            <ResultTabs scan={scan} active="surface" onChange={setTab} />
            {!scan ? <div className="empty">Run a scan to populate discovery.</div> : (
              <>
                <div className="coverageGrid">
                  <div><span>Pages crawled</span><b>{scan.mode === 'deep' ? (scan.metrics.domainPagesCrawled || scan.metrics.pagesCrawled || 0) : (scan.metrics.pagesCrawled || 0)}</b></div>
                  <div><span>API paths</span><b>{scan.mode === 'deep' ? (scan.metrics.domainApiEndpoints || 0) : (scan.metrics.apiEndpoints || 0)}</b></div>
                  <div><span>Technologies</span><b>{scan.metrics.technologies || 0}</b></div>
                  <div><span>Live hosts</span><b>{scan.mode === 'deep' ? (scan.metrics.liveHosts || 0) : (scan.metrics.subdomains || 0)}</b></div>
                </div>
                <div className="projectList">
                  <div className="sectionHead"><div><h3>Technology signals</h3></div></div>
                  {(scan.evidence?.inventory?.technologies || []).map((item)=>(
                    <div className="projectRow" key={item.name}><div><strong>{item.name}</strong><span>{item.evidence} · {item.confidence} confidence</span></div></div>
                  ))}
                  <div className="sectionHead"><div><h3>API paths</h3></div></div>
                  {((scan.mode === 'deep' ? scan.evidence?.deep?.endpoints : scan.evidence?.inventory?.apiEndpoints) || []).map((item)=>(
                    <div className="projectRow" key={(item.hostname || '') + (item.method || 'OBSERVE') + ' ' + item.path}>
                      <div><strong>{item.method || 'OBSERVE'} {item.hostname ? item.hostname : ''}{item.path}</strong><span>{item.classification || 'Unknown'} · observed via {item.source || 'application evidence'}</span></div>
                    </div>
                  ))}
                  <div className="sectionHead"><div><h3>Discovered subdomains</h3></div></div>
                  {((scan.mode === 'deep' ? scan.evidence?.deep?.liveHosts : scan.evidence?.inventory?.commonSubdomains) || []).map((item)=>(
                    <div className="projectRow" key={item.hostname || item.host}><div><strong>{item.hostname || item.host}</strong><span>{scan.mode === 'deep' ? ('HTTP ' + (item.status || 'ERR') + ' · ' + (item.contentType || 'unknown')) : (item.ips || []).join(', ')}</span></div></div>
                  ))}
                  <div className="sectionHead"><div><h3>Crawled pages</h3></div></div>
                  {(scan.mode === 'deep'
                    ? (scan.evidence?.deep?.hosts || []).flatMap((host)=>(host.pages || []).map((item)=>({...item,hostname:host.hostname})))
                    : (scan.evidence?.inventory?.pages || [])
                  ).slice(0,250).map((item)=>(
                    <div className="projectRow" key={(item.hostname || '') + item.url}><div><strong>{item.url}</strong><span>HTTP {item.status || 'ERR'} · {item.hostname ? item.hostname + ' · ' : ''}{item.source}</span></div></div>
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
            <div className="drawerBadges"><Severity value={finding.severity}/><Badge>{finding.engine}</Badge><Badge>{finding.confidence} confidence</Badge><Badge>{finding.evidenceQuality || 'observed'} evidence</Badge><Badge tone="purple">{finding.lifecycle}</Badge></div>
            <h2>{finding.title}</h2>
            <p className="lead">{finding.summary}</p>
            <section><h4>Why it matters</h4><p>{finding.impact}</p></section>
            <section><h4>Evidence</h4><pre>{finding.evidence}</pre></section>
            <section><h4>Affected locations</h4>
              <p>{(finding.affectedLocations || [finding.location || scan?.finalUrl]).slice(0,12).join('\n')}</p>
            </section>
            <section><h4>Recommended fix</h4><p>{findingGuidance?.fixSummary || finding.remediation}</p></section>
            {findingGuidance ? (
              <section className="aiGuidance">
                <h4>OpenAI implementation plan</h4>
                <div className="guidanceMeta"><span>{findingGuidance.owner}</span><span>{findingGuidance.effort}</span></div>
                <strong>Steps</strong>
                <ol>{(findingGuidance.steps || []).map((step,i)=><li key={i}>{step}</li>)}</ol>
                <strong>Verify</strong>
                <ol>{(findingGuidance.verification || []).map((step,i)=><li key={i}>{step}</li>)}</ol>
              </section>
            ) : null}
            <section><h4>Workflow</h4><div className="statusActions">
              <button onClick={()=>setFindingStatus('open')}>Open</button>
              <button onClick={()=>setFindingStatus('in_progress')}>In progress</button>
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
