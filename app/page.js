'use client';

import { useEffect, useMemo, useState } from 'react';

const ranks = { Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1 };

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

export default function Home() {
  const [target, setTarget] = useState('https://example.com');
  const [authorized, setAuthorized] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState('');
  const [scans, setScans] = useState([]);
  const [selected, setSelected] = useState(null);
  const [finding, setFinding] = useState(null);
  const [filter, setFilter] = useState('All');

  useEffect(() => {
    try {
      const saved = JSON.parse(localStorage.getItem('inspector-scans') || '[]');
      setScans(saved);
      if (saved[0]) setSelected(saved[0].id);
    } catch {}
  }, []);

  const scan = useMemo(
    () => scans.find((item) => item.id === selected) || scans[0] || null,
    [scans, selected]
  );

  const visibleFindings = useMemo(() => {
    if (!scan) return [];
    return scan.findings
      .filter((item) => filter === 'All' || item.severity === filter || item.category === filter)
      .sort((a, b) => ranks[b.severity] - ranks[a.severity]);
  }, [scan, filter]);

  function save(next) {
    setScans(next);
    localStorage.setItem('inspector-scans', JSON.stringify(next.slice(0, 10)));
  }

  async function runScan(event) {
    event.preventDefault();
    if (!authorized || !target.trim()) return;

    setScanning(true);
    setError('');
    setFinding(null);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url: target.trim(), authorized: true })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Scan failed');

      const next = [data].concat(scans.filter((item) => item.id !== data.id));
      save(next);
      setSelected(data.id);
      setFilter('All');
    } catch (scanError) {
      setError(scanError.message || 'Unable to scan this target');
    } finally {
      setScanning(false);
    }
  }

  const summary = scan ? scan.summary : {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0
  };

  return (
    <main className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="logo">I</div>
          <div><strong>Inspector</strong><span>Security + UX QA</span></div>
        </div>
        <nav>
          <a className="active">Overview</a>
          <a>Findings <span>{scan ? scan.findings.length : 0}</span></a>
          <a>Scans <span>{scans.length}</span></a>
        </nav>
        <div className="safe">
          <strong>Safe by design</strong>
          <span>Passive and low-impact checks only. Private-network targets are blocked.</span>
        </div>
      </aside>

      <section className="content">
        <header className="top">
          <div>
            <h1>Web assurance workspace</h1>
            <p>Find security misconfigurations and usability issues in one pass.</p>
          </div>
          <Badge tone="success">Authorized testing only</Badge>
        </header>

        <section className="scanCard">
          <div>
            <span className="eyebrow">NEW SCAN</span>
            <h2>Inspect a web application</h2>
            <p>Checks security headers, page structure, accessibility basics and a small sample of same-host links.</p>
          </div>

          <form onSubmit={runScan}>
            <label>Target URL</label>
            <div className="inputRow">
              <input
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                placeholder="https://app.example.com"
              />
              <button disabled={!authorized || scanning}>
                {scanning ? 'Scanning…' : 'Run scan'}
              </button>
            </div>
            <label className="confirm">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(event) => setAuthorized(event.target.checked)}
              />
              I confirm I own this target or have explicit permission to test it.
            </label>
            {error ? <div className="error">{error}</div> : null}
          </form>
        </section>

        {!scan ? (
          <section className="empty">
            <div className="emptyIcon">⌁</div>
            <h3>No scans yet</h3>
            <p>Run your first authorized scan to populate this workspace.</p>
          </section>
        ) : (
          <>
            <section className="resultHead">
              <div>
                <span className="eyebrow">LATEST RESULT</span>
                <h2>{scan.host}</h2>
                <p>{scan.finalUrl} · {new Date(scan.scannedAt).toLocaleString()}</p>
              </div>
              <div className="score"><span>Assurance score</span><strong>{scan.score}</strong><small>/100</small></div>
            </section>

            <section className="metrics">
              <article><span>Critical</span><strong>{summary.critical}</strong><small>Immediate attention</small></article>
              <article><span>High</span><strong>{summary.high}</strong><small>Material risk</small></article>
              <article><span>Medium</span><strong>{summary.medium}</strong><small>Review next</small></article>
              <article><span>Low + Info</span><strong>{summary.low + summary.informational}</strong><small>Hygiene</small></article>
              <article><span>UX signals</span><strong>{scan.metrics.usabilityFindings}</strong><small>Usability</small></article>
            </section>

            <section className="coverage">
              <div>
                <span className="eyebrow">SCAN COVERAGE</span>
                <h3>What we observed</h3>
              </div>
              <div className="coverageGrid">
                <div><span>Security checks</span><b>{scan.metrics.securityHeaderChecks}</b></div>
                <div><span>Usability checks</span><b>{scan.metrics.usabilityChecks}</b></div>
                <div><span>Links sampled</span><b>{scan.metrics.linksChecked}</b></div>
                <div><span>HTTP status</span><b>{scan.httpStatus}</b></div>
              </div>
            </section>

            <section className="findings">
              <div className="findingsHead">
                <div><span className="eyebrow">NORMALIZED FINDINGS</span><h3>Findings</h3></div>
                <select value={filter} onChange={(event) => setFilter(event.target.value)}>
                  <option>All</option>
                  <option>Critical</option>
                  <option>High</option>
                  <option>Medium</option>
                  <option>Low</option>
                  <option>Security</option>
                  <option>Usability</option>
                </select>
              </div>

              <div className="tableWrap">
                <table>
                  <thead><tr><th>Finding</th><th>Category</th><th>Severity</th><th>Confidence</th></tr></thead>
                  <tbody>
                    {visibleFindings.map((item) => (
                      <tr key={item.id} onClick={() => setFinding(item)}>
                        <td><strong>{item.title}</strong><span>{item.summary}</span></td>
                        <td>{item.category}</td>
                        <td><Severity value={item.severity} /></td>
                        <td>{item.confidence}</td>
                      </tr>
                    ))}
                    {!visibleFindings.length ? <tr><td colSpan="4" className="none">No findings match this filter.</td></tr> : null}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        )}
      </section>

      {finding ? (
        <div className="backdrop" onClick={() => setFinding(null)}>
          <aside className="drawer" onClick={(event) => event.stopPropagation()}>
            <button className="close" onClick={() => setFinding(null)}>×</button>
            <div className="drawerBadges"><Severity value={finding.severity} /><Badge>{finding.confidence} confidence</Badge></div>
            <h2>{finding.title}</h2>
            <p className="lead">{finding.summary}</p>
            <section><h4>Why it matters</h4><p>{finding.impact}</p></section>
            <section><h4>Evidence</h4><pre>{finding.evidence}</pre></section>
            <section><h4>Recommended fix</h4><p>{finding.remediation}</p></section>
            <div className="meta"><span>{finding.category}</span><b>{finding.checkId}</b></div>
          </aside>
        </div>
      ) : null}
    </main>
  );
}
