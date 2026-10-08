'use client';

import { useEffect, useMemo, useState } from 'react';

const severityOrder={Critical:5,High:4,Medium:3,Low:2,Informational:1};

function fmt(value){
  if(!value) return '—';
  try{return new Date(value).toLocaleString();}catch{return value;}
}
function shortDate(value){
  if(!value) return '—';
  try{return new Date(value).toLocaleDateString();}catch{return value;}
}
function Badge({children,tone='neutral'}){return <span className={'pill '+tone}>{children}</span>;}
function Sev({value}){return <span className={'sev '+String(value||'info').toLowerCase()}>{value||'Info'}</span>;}
function riskCount(findings,severity){return (findings||[]).filter(f=>f.severity===severity).length;}
function statusTone(status){
  return status==='completed'?'success':status==='completed_with_gaps'?'warning':status==='partial'?'warning':status==='failed'?'danger':'neutral';
}
function scanLabel(scan){
  if(!scan) return 'Scan';
  return scan.scanType || (scan.mode==='deep'?'Attack Surface Scan':'Web App Scan');
}

export default function Home(){
  const [data,setData]=useState({projects:[],scans:[],workspace:{}});
  const [view,setView]=useState('dashboard');
  const [selectedProjectId,setSelectedProjectId]=useState('');
  const [loading,setLoading]=useState(true);
  const [notice,setNotice]=useState('');
  const [newScanOpen,setNewScanOpen]=useState(false);
  const [addTargetOpen,setAddTargetOpen]=useState(false);
  const [onboardingOpen,setOnboardingOpen]=useState(false);
  const [onboardingChoice,setOnboardingChoice]=useState('');
  const [scanRunning,setScanRunning]=useState(false);
  const [scanTab,setScanTab]=useState('history');
  const [riskSeverity,setRiskSeverity]=useState('All');
  const [riskStatus,setRiskStatus]=useState('All');
  const [selectedRisk,setSelectedRisk]=useState(null);
  const [retesting,setRetesting]=useState(false);
  const [settings,setSettings]=useState({name:'',schedule:'manual',scheduledMode:'standard',webhookUrl:''});
  const [engineStatus,setEngineStatus]=useState(null);
  const [targetUrl,setTargetUrl]=useState('');
  const [networkForm,setNetworkForm]=useState({label:'',cidr:''});
  const [networkAuthorized,setNetworkAuthorized]=useState(false);
  const [networkScanningId,setNetworkScanningId]=useState('');
  const [newScan,setNewScan]=useState({
    type:'deep',
    assetId:'',
    authorized:false,
    authMethod:'bearer',
    credential:'',
    repositoryUrl:'',
    repositoryToken:'',
    networkTargetId:''
  });

  async function load(preferredProjectId){
    setLoading(true);
    try{
      const [response,engineResponse]=await Promise.all([
        fetch('/api/workspace',{cache:'no-store'}),
        fetch('/api/engine-status',{cache:'no-store'}).catch(()=>null)
      ]);
      const json=await response.json();
      if(!response.ok) throw new Error(json.error||'Could not load workspace.');
      setData(json);
      if(engineResponse?.ok) setEngineStatus(await engineResponse.json());
      const id=preferredProjectId || selectedProjectId || json.projects?.[0]?.id || '';
      setSelectedProjectId(id);
      const p=json.projects?.find(x=>x.id===id);
      if(p){
        setSettings({name:p.name,schedule:p.schedule||'manual',scheduledMode:p.scheduledMode||'standard',webhookUrl:''});
        setNewScan(prev=>({
          ...prev,
          assetId:p.assets?.some(a=>a.id===prev.assetId)?prev.assetId:(p.assets?.[0]?.id||''),
          networkTargetId:p.networks?.some(n=>n.id===prev.networkTargetId)?prev.networkTargetId:(p.networks?.[0]?.id||'')
        }));
      }
    }catch(error){setNotice(error.message);}
    finally{setLoading(false);}
  }

  useEffect(()=>{
    load();
    try{
      if(!localStorage.getItem('inspector-onboarding-v2')) setOnboardingOpen(true);
    }catch{}
  },[]);

  const project=useMemo(()=>data.projects.find(p=>p.id===selectedProjectId)||null,[data.projects,selectedProjectId]);
  const scans=useMemo(()=>(data.scans||[]).filter(s=>s.projectId===selectedProjectId).sort((a,b)=>String(b.completedAt||b.startedAt).localeCompare(String(a.completedAt||a.startedAt))),[data.scans,selectedProjectId]);
  const latestScan=useMemo(()=>scans[0]||null,[scans]);

  const scanRows=useMemo(()=>{
    const rows=[
      ...scans,
      ...(project?.networkScans||[]).map(item=>({...item,_kind:'network'})),
      ...(project?.authScans||[]).map(item=>({...item,_kind:'auth'})),
      ...(project?.codeScans||[]).map(item=>({...item,_kind:'code'}))
    ];
    return rows.sort((a,b)=>String(b.completedAt||b.scannedAt||b.startedAt||'').localeCompare(String(a.completedAt||a.scannedAt||a.startedAt||'')));
  },[scans,project]);

  const latestByAsset=useMemo(()=>{
    const map=new Map();
    for(const scan of scans){
      if(!map.has(scan.assetId)) map.set(scan.assetId,scan);
    }
    return map;
  },[scans]);

  const currentRisks=useMemo(()=>{
    const rows=[];
    for(const scan of latestByAsset.values()){
      for(const finding of scan.findings||[]) rows.push({...finding,_scanId:scan.id,_scan:scan});
    }
    const auth=project?.authScans?.[0];
    for(const finding of auth?.findings||[]) rows.push({...finding,_authScanId:auth.id,_auth:true,_scan:auth});
    const code=project?.codeScans?.[0];
    for(const finding of code?.findings||[]) rows.push({...finding,_code:true,_scan:code});
    const latestNetworks=new Map();
    for(const scan of project?.networkScans||[]){
      if(!latestNetworks.has(scan.networkTargetId)) latestNetworks.set(scan.networkTargetId,scan);
    }
    for(const networkScan of latestNetworks.values()){
      for(const finding of networkScan.findings||[]) rows.push({...finding,_network:true,_networkScanId:networkScan.id,_scan:networkScan});
    }
    const unique=new Map();
    for(const row of rows){
      const key=row.fingerprint||row.id;
      if(!unique.has(key) || (severityOrder[row.severity]||0)>(severityOrder[unique.get(key)?.severity]||0)) unique.set(key,row);
    }
    return [...unique.values()].sort((a,b)=>(severityOrder[b.severity]||0)-(severityOrder[a.severity]||0));
  },[latestByAsset,project]);

  const filteredRisks=useMemo(()=>currentRisks.filter(r=>{
    if(riskSeverity!=='All' && r.severity!==riskSeverity) return false;
    const status=r.workflowStatus||'open';
    if(riskStatus==='Open' && !['open','in_progress'].includes(status)) return false;
    if(riskStatus==='Accepted' && status!=='accepted') return false;
    if(riskStatus==='Closed' && !['resolved','false_positive'].includes(status)) return false;
    return true;
  }),[currentRisks,riskSeverity,riskStatus]);

  const summary=useMemo(()=>{
    const open=currentRisks.filter(r=>!['resolved','false_positive','accepted'].includes(r.workflowStatus||'open'));
    const accepted=currentRisks.filter(r=>(r.workflowStatus||'open')==='accepted').length;
    const closed=currentRisks.filter(r=>['resolved','false_positive'].includes(r.workflowStatus||'open')).length;
    const latestScores=[...latestByAsset.values()].map(s=>Number(s.score||0)).filter(Boolean);
    const health=latestScores.length?Math.round(latestScores.reduce((a,b)=>a+b,0)/latestScores.length):null;
    return {
      total:currentRisks.length,
      critical:riskCount(open,'Critical'),
      high:riskCount(open,'High'),
      medium:riskCount(open,'Medium'),
      low:riskCount(open,'Low'),
      accepted,closed,health
    };
  },[currentRisks,latestByAsset]);

  async function workspaceAction(body){
    const response=await fetch('/api/workspace',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
    const json=await response.json();
    if(!response.ok) throw new Error(json.error||'Request failed.');
    return json.result;
  }

  function selectProject(id){
    setSelectedProjectId(id);
    const p=data.projects.find(x=>x.id===id);
    if(p){
      setSettings({name:p.name,schedule:p.schedule||'manual',scheduledMode:p.scheduledMode||'standard',webhookUrl:''});
      setNewScan(prev=>({...prev,assetId:p.assets?.[0]?.id||'',networkTargetId:p.networks?.[0]?.id||''}));
    }
    setSelectedRisk(null);
  }

  async function addTarget(event){
    event.preventDefault();
    if(!project||!targetUrl) return;
    try{
      await workspaceAction({action:'add_asset',projectId:project.id,url:targetUrl});
      setTargetUrl('');
      setAddTargetOpen(false);
      await load(project.id);
      setNotice('Target added. You can start a scan now.');
    }catch(error){setNotice(error.message);}
  }

  async function addNetworkTarget(event){
    event.preventDefault();
    if(!project||!networkForm.cidr) return;
    try{
      await workspaceAction({
        action:'add_network_target',
        projectId:project.id,
        cidr:networkForm.cidr,
        label:networkForm.label
      });
      setNetworkForm({label:'',cidr:''});
      await load(project.id);
      setNotice('Internal network added. Connect an internal scanner worker and confirm authorization before scanning.');
    }catch(error){setNotice(error.message);}
  }

  async function runNetworkScan(networkTargetId){
    if(!project||!networkAuthorized) return;
    setNetworkScanningId(networkTargetId);
    setNotice('Internal network scan started. Naabu will perform rate-limited TCP discovery and Greenbone/OpenVAS will run when configured on the internal worker.');
    try{
      const response=await fetch('/api/network-scan',{
        method:'POST',
        headers:{'content-type':'application/json'},
        body:JSON.stringify({projectId:project.id,networkTargetId,authorized:true})
      });
      const result=await response.json();
      if(!response.ok) throw new Error(result.error||'Network scan failed.');
      await load(project.id);
      setView('risks');
      setNotice('Internal network scan completed. Review normalized risks and engine coverage.');
    }catch(error){setNotice(error.message);}
    finally{setNetworkScanningId('');}
  }

  async function saveSettings(event){
    event.preventDefault();
    if(!project) return;
    try{
      const patch={name:settings.name,schedule:settings.schedule,scheduledMode:settings.scheduledMode};
      if(settings.webhookUrl) patch.webhookUrl=settings.webhookUrl;
      await workspaceAction({action:'update_project',projectId:project.id,patch});
      setSettings(prev=>({...prev,webhookUrl:''}));
      await load(project.id);
      setNotice('Settings saved.');
    }catch(error){setNotice(error.message);}
  }

  async function runNewScan(){
    if(!project) return;
    const asset=project.assets.find(a=>a.id===newScan.assetId)||project.assets[0];
    if(!asset && !['code','network'].includes(newScan.type)) return;
    if(!newScan.authorized) return;
    setScanRunning(true);
    setNotice('Scan started. Inspector is collecting evidence and normalizing risks…');
    try{
      let response;
      if(newScan.type==='authenticated'){
        if(!newScan.credential) throw new Error('Enter an authorized test session first.');
        response=await fetch('/api/auth-scan',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({
          projectId:project.id,assetId:asset.id,authorized:true,authType:newScan.authMethod,credential:newScan.credential
        })});
      }else if(newScan.type==='code'){
        if(!newScan.repositoryUrl) throw new Error('Enter a GitHub repository URL.');
        response=await fetch('/api/code-scan',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({
          projectId:project.id,repositoryUrl:newScan.repositoryUrl,token:newScan.repositoryToken,authorized:true
        })});
      }else if(newScan.type==='network'){
        if(!newScan.networkTargetId) throw new Error('Add an internal network first.');
        response=await fetch('/api/network-scan',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({
          projectId:project.id,networkTargetId:newScan.networkTargetId,authorized:true
        })});
      }else{
        response=await fetch('/api/scan',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({
          projectId:project.id,assetId:asset.id,authorized:true,mode:newScan.type==='deep'?'deep':'standard'
        })});
      }
      const result=await response.json();
      if(!response.ok) throw new Error(result.error||'Scan failed.');
      setNewScan(prev=>({...prev,credential:'',repositoryToken:'',authorized:false}));
      setNewScanOpen(false);
      await load(project.id);
      setView(['code','authenticated','network'].includes(newScan.type)?'risks':'scans');
      setNotice('Scan completed. Review the risks and remediation guidance.');
    }catch(error){setNotice(error.message);}
    finally{setScanRunning(false);}
  }

  async function updateRiskStatus(risk,status){
    try{
      if(risk._auth){
        await workspaceAction({action:'auth_finding_status',projectId:project.id,authScanId:risk._authScanId,fingerprint:risk.fingerprint,status});
      }else if(risk._network){
        await workspaceAction({action:'network_finding_status',projectId:project.id,networkScanId:risk._networkScanId,fingerprint:risk.fingerprint,status});
      }else if(risk._scanId){
        await workspaceAction({action:'finding_status',scanId:risk._scanId,fingerprint:risk.fingerprint,status});
      }else{
        throw new Error('This finding does not support workflow updates yet.');
      }
      await load(project.id);
      setSelectedRisk(prev=>prev?{...prev,workflowStatus:status}:null);
    }catch(error){setNotice(error.message);}
  }

  async function retestRisk(){
    if(!selectedRisk?._scanId) return;
    setRetesting(true);
    try{
      const result=await workspaceAction({action:'retest_finding',scanId:selectedRisk._scanId,fingerprint:selectedRisk.fingerprint});
      await load(project.id);
      setNotice(result.status==='resolved'?'Retest passed — this risk is no longer present.':'Retest completed — the risk is still present.');
      if(result.currentFinding) setSelectedRisk({...result.currentFinding,_scanId:result.scan.id,_scan:result.scan});
      else setSelectedRisk(null);
    }catch(error){setNotice(error.message);}
    finally{setRetesting(false);}
  }

  function openNewScan(assetId){
    setNewScan(prev=>({...prev,assetId:assetId||prev.assetId||project?.assets?.[0]?.id||'',networkTargetId:prev.networkTargetId||project?.networks?.[0]?.id||'',authorized:false}));
    setNewScanOpen(true);
  }

  function finishOnboarding(){
    try{localStorage.setItem('inspector-onboarding-v2','1');}catch{}
    setOnboardingOpen(false);
  }

  if(loading) return <div className="loadingScreen">Loading Inspector…</div>;

  return (
    <main className="productShell">
      <aside className="leftRail">
        <div className="brandMark"><div className="brandIcon">I</div><strong>Inspector</strong></div>

        <div className="workspaceSelect">
          <label>Workspace</label>
          <select value={selectedProjectId} onChange={e=>selectProject(e.target.value)}>
            <option value="">Select workspace</option>
            {data.projects.map(p=><option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </div>

        <nav className="primaryNav">
          {[
            ['dashboard','▦','Dashboard'],
            ['targets','▣','Targets'],
            ['scans','◉','Scans'],
            ['risks','⚑','Risks'],
            ['reports','▤','Reports'],
            ['networks','⌘','Internal Networks'],
            ['settings','⚙','Settings']
          ].map(([key,icon,label])=>(
            <button key={key} className={view===key?'active':''} onClick={()=>setView(key)}>
              <span className="navIcon">{icon}</span><span>{label}</span>
              {key==='risks'&&summary.total?<em>{summary.total}</em>:null}
            </button>
          ))}
        </nav>

        <div className="gettingStarted">
          <div className="getHead"><strong>Getting started</strong><span>{latestScan?'2 of 2':'1 of 2'}</span></div>
          <div className="progressTrack"><i style={{width:latestScan?'100%':'50%'}}/></div>
          <button className={currentRisks.length?'done':''} onClick={()=>setView('risks')}><span>✓</span> Review your risks</button>
          <button className={latestScan?'done':''} onClick={()=>setView('reports')}><span>□</span> Generate a report</button>
        </div>

        <div className="railBottom">
          <button onClick={()=>setNotice('Support workflow can be connected to your helpdesk or email.')}>✉ Support</button>
          <button onClick={()=>setNotice('API access will use the same project and scan model as the dashboard.')}>⌘ API Docs</button>
          <button onClick={()=>setOnboardingOpen(true)}>？ Help Center</button>
        </div>
      </aside>

      <section className="workspace">
        <div className="trialBar">Inspector Security Platform · Authorized testing only</div>

        {notice?<div className="toastNotice"><span>{notice}</span><button onClick={()=>setNotice('')}>×</button></div>:null}

        {view==='dashboard'?(
          <section className="page">
            <header className="pageHeader">
              <div><h1>Dashboard</h1><p>Security posture across your current workspace.</p></div>
              <div className="headerActions">
                <span className="miniStat">▦ {scanRunning?'1 scan in progress':'No scans in progress'}</span>
                <span className="miniStat">{project?.schedule&&project.schedule!=='manual'?'1 scheduled scan':'Manual scans'}</span>
                <button className="primaryBtn" onClick={()=>openNewScan()}>＋ New Scan</button>
              </div>
            </header>

            {!project?(
              <div className="emptyState"><h2>Create or select a workspace</h2><p>Inspector organizes targets, scans, risks and reports by workspace.</p></div>
            ):(
              <>
                <div className="sectionTitle"><h2>Risks detected</h2><span>Total: {summary.total}</span></div>
                <div className="riskCards">
                  <button className="riskCard critical" onClick={()=>{setRiskSeverity('Critical');setRiskStatus('Open');setView('risks')}}><span>Critical</span><strong>{summary.critical}</strong></button>
                  <button className="riskCard high" onClick={()=>{setRiskSeverity('High');setRiskStatus('Open');setView('risks')}}><span>High</span><strong>{summary.high}</strong></button>
                  <button className="riskCard medium" onClick={()=>{setRiskSeverity('Medium');setRiskStatus('Open');setView('risks')}}><span>Medium</span><strong>{summary.medium}</strong></button>
                  <button className="riskCard low" onClick={()=>{setRiskSeverity('Low');setRiskStatus('Open');setView('risks')}}><span>Low</span><strong>{summary.low}</strong></button>
                  <div className="riskCardStack">
                    <button className="riskCard accepted" onClick={()=>{setRiskSeverity('All');setRiskStatus('Accepted');setView('risks')}}><span>Accepted</span><strong>{summary.accepted}</strong></button>
                    <button className="riskCard closed" onClick={()=>{setRiskSeverity('All');setRiskStatus('Closed');setView('risks')}}><span>Closed</span><strong>{summary.closed}</strong></button>
                  </div>
                </div>

                <div className="dashboardSplit">
                  <section className="cardBlock">
                    <div className="blockHead"><h2>Recent scans</h2><button onClick={()=>setView('scans')}>See all scans ›</button></div>
                    <div className="recentList">
                      {scanRows.slice(0,5).map(scan=>(
                        <button key={scan.id} className="recentScan" onClick={()=>setView('scans')}>
                          <div><strong>{scanLabel(scan)}</strong><span>{scan.finalUrl||scan.url}</span><small>{fmt(scan.completedAt||scan.startedAt)}</small></div>
                          <div className="scanRight"><Badge tone={statusTone(scan.status)}>{scan.status==='completed_with_gaps'?'Completed with gaps':scan.status}</Badge><span className="score">{scan.score??'—'}</span></div>
                        </button>
                      ))}
                      {!scanRows.length?<div className="emptyRow">No scans yet. Start with a Web App Scan.</div>:null}
                    </div>
                  </section>

                  <section className="cardBlock healthBlock">
                    <div className="blockHead"><h2>Health score</h2></div>
                    <div className="healthBody">
                      <div className="healthGauge" style={{'--score':summary.health??0}}><strong>{summary.health??'—'}</strong><span>{summary.health?'out of 100':'Run a scan'}</span></div>
                      <div className="healthLegend">
                        <div><i className="dot critical"/>Critical <b>{summary.critical}</b></div>
                        <div><i className="dot high"/>High <b>{summary.high}</b></div>
                        <div><i className="dot medium"/>Medium <b>{summary.medium}</b></div>
                        <div><i className="dot low"/>Low <b>{summary.low}</b></div>
                      </div>
                    </div>
                  </section>
                </div>

                <section className="cardBlock">
                  <div className="blockHead"><h2>Recent risks</h2><button onClick={()=>setView('risks')}>See all risks ›</button></div>
                  <div className="riskPreview">
                    {currentRisks.slice(0,6).map(r=>(
                      <button key={r.id||r.fingerprint} onClick={()=>setSelectedRisk(r)}>
                        <span className={'threatBars '+String(r.severity).toLowerCase()}><i/><i/><i/><i/></span>
                        <div><strong>{r.title}</strong><span>{r._scan?.finalUrl||r.location||project.assets?.[0]?.url}</span></div>
                        <Sev value={r.severity}/><span className="riskStatus">{(r.workflowStatus||'open').replaceAll('_',' ')}</span>
                      </button>
                    ))}
                    {!currentRisks.length?<div className="emptyRow">No current risks to show.</div>:null}
                  </div>
                </section>
              </>
            )}
          </section>
        ):null}

        {view==='targets'?(
          <section className="page">
            <header className="pageHeader">
              <div><h1>Targets</h1><p>Public assets included in this workspace.</p></div>
              <div className="headerActions"><button className="secondaryBtn" onClick={()=>setAddTargetOpen(true)}>＋ Add Target</button><button className="primaryBtn" onClick={()=>openNewScan()}>＋ New Scan</button></div>
            </header>
            {!project?<div className="emptyState">Select a workspace first.</div>:(
              <div className="dataCard">
                <div className="tableHeader targetGrid"><span>Target</span><span>Type</span><span>Last scanned</span><span>Created</span><span/></div>
                {(project.assets||[]).map(asset=>{
                  const last=latestByAsset.get(asset.id);
                  return <div className="tableRow targetGrid" key={asset.id}>
                    <div className="targetName"><span className="expand">›</span><div><strong>{asset.label}</strong><small>{asset.url}</small></div></div>
                    <span>Web</span><span>{last?fmt(last.completedAt):'Never'}</span><span>{shortDate(asset.createdAt)}</span>
                    <button className="rowMenu" onClick={()=>openNewScan(asset.id)}>Scan</button>
                  </div>;
                })}
                {!project.assets?.length?<div className="emptyRow">No targets have been added.</div>:null}
              </div>
            )}
          </section>
        ):null}

        {view==='scans'?(
          <section className="page">
            <header className="pageHeader">
              <div><h1>Scans</h1><p>Scan history, status and scheduled monitoring.</p></div>
              <button className="primaryBtn" onClick={()=>openNewScan()}>＋ New Scan</button>
            </header>
            <div className="tabs"><button className={scanTab==='history'?'active':''} onClick={()=>setScanTab('history')}>Scans</button><button className={scanTab==='scheduled'?'active':''} onClick={()=>setScanTab('scheduled')}>Scheduled Scans</button></div>
            {scanTab==='history'?(
              <div className="dataCard">
                <div className="tableHeader scanGrid"><span>Scan</span><span>Target(s)</span><span>Results</span><span>Created</span><span>Risks</span></div>
                {scanRows.map(scan=><div className="tableRow scanGrid" key={scan.id}>
                  <div className="targetName"><span className="expand">›</span><div><strong>{scanLabel(scan)}</strong><small>{scan.trigger||scan._kind||'manual'}</small>{scan.engineRuns?.length?<div className="engineChips">{scan.engineRuns.map(run=><span key={run.engine} className={'engineChip '+run.status}>{run.name||run.engine} · {run.status}</span>)}</div>:null}</div></div>
                  <span>{scan.finalUrl||scan.url||scan.target||scan.repository?.url||'Repository scan'}</span>
                  <div><Badge tone={statusTone(scan.status)}>{scan.status==='completed_with_gaps'?'Completed with gaps':scan.status}</Badge><small className="inlineMeta">Score {scan.score??'—'}</small></div>
                  <span>{fmt(scan.completedAt||scan.startedAt)}</span>
                  <div className="riskDots"><span className="dot critical"/>{scan.summary?.critical||0}<span className="dot high"/>{scan.summary?.high||0}<span className="dot medium"/>{scan.summary?.medium||0}<span className="dot low"/>{scan.summary?.low||0}</div>
                </div>)}
                {!scanRows.length?<div className="emptyRow">No scans yet.</div>:null}
              </div>
            ):(
              <div className="dataCard scheduledCard">
                <div><strong>{project?.schedule==='daily'?'Daily monitoring':project?.schedule==='weekly'?'Weekly monitoring':'No recurring scan scheduled'}</strong><span>{project?.schedule==='manual'?'Choose Daily or Weekly in Settings to enable recurring scans.':((project?.scheduledMode==='deep'?'Attack Surface Scan':'Web App Scan')+' will run against active web targets automatically.')}</span></div>
                <button className="secondaryBtn" onClick={()=>setView('settings')}>Manage schedule</button>
              </div>
            )}
          </section>
        ):null}

        {view==='risks'?(
          <section className="page">
            <header className="pageHeader">
              <div><h1>Risks</h1><p>Normalized security findings across the latest target scans.</p></div>
              <div className="headerActions"><button className="secondaryBtn" onClick={()=>{setRiskSeverity('All');setRiskStatus('All')}}>≡ Clear filters</button><button className="primaryBtn" onClick={()=>openNewScan()}>＋ New Scan</button></div>
            </header>
            <div className="filterBar">
              <select value={riskSeverity} onChange={e=>setRiskSeverity(e.target.value)}><option>All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Informational</option></select>
              <select value={riskStatus} onChange={e=>setRiskStatus(e.target.value)}><option>All</option><option>Open</option><option>Accepted</option><option>Closed</option></select>
              <span>{filteredRisks.length} risks</span>
            </div>
            <div className="dataCard">
              <div className="tableHeader riskGrid"><span>Threat</span><span>Vulnerability</span><span>Target</span><span>Detected</span><span>Status</span><span/></div>
              {filteredRisks.map(r=><div className="tableRow riskGrid riskTableRow" key={(r.fingerprint||r.id)+(r._scanId||r._authScanId||'')}>
                <span className={'threatBars '+String(r.severity).toLowerCase()}><i/><i/><i/><i/></span>
                <button className="riskTitle" onClick={()=>setSelectedRisk(r)}><small>{r.engine||r.category}</small><strong>{r.title}</strong>{r.checkId?<Badge tone="blue">{r.checkId}</Badge>:null}</button>
                <span>{r._scan?.finalUrl||r.location||project?.assets?.[0]?.url}</span>
                <span><small>First: {fmt(r.firstSeen||r._scan?.completedAt||r._scan?.scannedAt)}</small><small>Last: {fmt(r.lastSeen||r._scan?.completedAt||r._scan?.scannedAt)}</small></span>
                <Badge tone={(r.workflowStatus||'open')==='accepted'?'success':(r.workflowStatus||'open')==='resolved'?'neutral':'warning'}>{(r.workflowStatus||'open').replaceAll('_',' ')}</Badge>
                {!r._code?<button className="secondaryBtn smallBtn" onClick={()=>updateRiskStatus(r,'accepted')}>Accept Risk</button>:<span/>}
              </div>)}
              {!filteredRisks.length?<div className="emptyRow">No risks match these filters.</div>:null}
            </div>
          </section>
        ):null}

        {view==='reports'?(
          <section className="page">
            <header className="pageHeader"><div><h1>Reports</h1><p>Create stakeholder-ready reports from the latest workspace findings.</p></div></header>
            <div className="tabs"><button className="active">Reports</button><button>Scheduled Reports</button></div>
            {!project||!latestScan?<div className="emptyState"><h2>Run a scan first</h2><p>A completed scan is required before Inspector can build a report.</p></div>:(
              <div className="reportBuilder">
                <h2>Create a Report</h2>
                <label>Report scope<span>Latest completed scan for {project.name}</span></label>
                <label>Sections
                  <select defaultValue="all"><option value="all">Executive summary + all findings</option><option value="security">Security findings only</option><option value="technical">Technical evidence</option></select>
                </label>
                <div className="reportActions">
                  <a className="previewBtn" target="_blank" rel="noreferrer" href={'/api/report?projectId='+encodeURIComponent(project.id)+'&format=html&preview=1'}>Preview Report ({project.assets?.length||0} targets, {summary.total} risks)</a>
                  <div>
                    <a className="secondaryBtn linkBtn" href={'/api/report?projectId='+encodeURIComponent(project.id)+'&format=pdf'}>Download PDF ⇩</a>
                    <a className="secondaryBtn linkBtn" href={'/api/report?projectId='+encodeURIComponent(project.id)+'&format=csv'}>Download CSV ⇩</a>
                    <a className="secondaryBtn linkBtn" href={'/api/report?projectId='+encodeURIComponent(project.id)+'&format=html'}>Download HTML ⇩</a>
                  </div>
                </div>
              </div>
            )}
          </section>
        ):null}

        {view==='settings'?(
          <section className="page">
            <header className="pageHeader"><div><h1>Settings</h1><p>Monitoring, notifications and scanner platform configuration.</p></div></header>
            {!project?<div className="emptyState">Select a workspace first.</div>:(
              <div className="settingsGrid">
                <form className="settingsCard" onSubmit={saveSettings}>
                  <h2>Workspace</h2>
                  <label>Name<input value={settings.name} onChange={e=>setSettings({...settings,name:e.target.value})}/></label>
                  <label>Monitoring schedule<select value={settings.schedule} onChange={e=>setSettings({...settings,schedule:e.target.value})}><option value="manual">Manual</option><option value="daily">Daily</option><option value="weekly">Weekly</option></select></label>
                  <label>Scheduled scan profile<select value={settings.scheduledMode} onChange={e=>setSettings({...settings,scheduledMode:e.target.value})}><option value="standard">Web App Scan</option><option value="deep">Attack Surface Scan</option></select></label>
                  <label>Alert webhook<input type="url" placeholder={project.webhookUrl?'Webhook configured — enter a new URL to replace':'https://hooks.slack.com/...'} value={settings.webhookUrl} onChange={e=>setSettings({...settings,webhookUrl:e.target.value})}/></label>
                  <button className="primaryBtn">Save settings</button>
                </form>

                <section className="settingsCard">
                  <h2>Scanner stack</h2>
                  <p className="muted">Inspector normalizes results behind one risk model. Heavy open-source scanners should run in isolated container workers, not in the web application.</p>
                  <div className="engineRows">
                    <div><strong>Playwright + axe-core</strong><span>Rendered browser QA and accessibility</span><Badge tone="success">Connected</Badge></div>
                    <div><strong>OWASP ZAP</strong><span>Web application DAST / passive baseline</span><Badge tone={engineStatus?.worker?.configured?'success':'neutral'}>{engineStatus?.worker?.configured?'Connected':'Ready to connect'}</Badge></div>
                    <div><strong>Nuclei</strong><span>Template-driven vulnerability and exposure validation</span><Badge tone={engineStatus?.worker?.configured?'success':'neutral'}>{engineStatus?.worker?.configured?'Connected':'Ready to connect'}</Badge></div>
                    <div><strong>Naabu</strong><span>Rate-limited TCP port discovery</span><Badge tone={engineStatus?.worker?.configured?'success':'neutral'}>{engineStatus?.worker?.configured?'Connected':'Ready to connect'}</Badge></div>
                    <div><strong>Greenbone / OpenVAS</strong><span>Network vulnerability assessment</span><Badge tone={engineStatus?.worker?.configured?'success':'neutral'}>{engineStatus?.worker?.configured?'Connected':'Ready to connect'}</Badge></div>
                    <div><strong>Trivy + Gitleaks</strong><span>Dependencies, IaC, containers and secrets</span><Badge tone={engineStatus?.worker?.configured?'success':'neutral'}>{engineStatus?.worker?.configured?'Connected':'Ready to connect'}</Badge></div>
                  </div>
                  <p className="muted small">Commercial licensing should be reviewed before redistributing third-party binaries. Nmap is intentionally not an embedded default.</p>
                </section>
              </div>
            )}
          </section>
        ):null}
      </section>

      {newScanOpen?(
        <div className="modalBackdrop" onMouseDown={e=>{if(e.target===e.currentTarget&&!scanRunning)setNewScanOpen(false)}}>
          <section className="modal scanModal">
            <div className="modalHead"><div><span className="eyebrow">NEW SCAN</span><h2>Choose what you want to test</h2><p>Inspector will normalize all scanner evidence into the same Risks workflow.</p></div><button disabled={scanRunning} onClick={()=>setNewScanOpen(false)}>×</button></div>

            <div className="scanTypeGrid">
              {[
                ['standard','Web App Scan','Fast baseline','Headers, TLS/DNS, browser QA, accessibility, API discovery and safe exposure checks.'],
                ['deep','Attack Surface Scan','Recommended','Subdomains, live hosts, pages, APIs, CVEs, exposed artifacts and attack paths.'],
                ['authenticated','Authenticated Web/API','Post-login','Compare public vs authorized test-session behavior with read-only requests.'],
                ['code','Code & Dependencies','Repository','Secrets, risky files, pinned dependencies and security-sensitive code patterns.'],
                ['network','Internal Network','Private worker','Rate-limited port discovery plus Greenbone/OpenVAS from an authorized internal worker.']
              ].map(([key,title,kicker,desc])=><button key={key} className={newScan.type===key?'selected':''} onClick={()=>setNewScan({...newScan,type:key})}><span>{kicker}</span><strong>{title}</strong><small>{desc}</small></button>)}
            </div>

            {!['code','network'].includes(newScan.type)?<label className="field">Target<select value={newScan.assetId} onChange={e=>setNewScan({...newScan,assetId:e.target.value})}>{(project?.assets||[]).map(a=><option key={a.id} value={a.id}>{a.label} · {a.url}</option>)}</select></label>:null}
            {newScan.type==='network'?<label className="field">Internal network<select value={newScan.networkTargetId} onChange={e=>setNewScan({...newScan,networkTargetId:e.target.value})}><option value="">Select network</option>{(project?.networks||[]).map(n=><option key={n.id} value={n.id}>{n.label} · {n.cidr}</option>)}</select><small>Internal scans require the scanner worker to run where it can reach this private CIDR.</small></label>:null}

            {newScan.type==='authenticated'?<>
              <label className="field">Session type<select value={newScan.authMethod} onChange={e=>setNewScan({...newScan,authMethod:e.target.value})}><option value="bearer">Bearer token</option><option value="cookie">Cookie header</option></select></label>
              <label className="field">Authorized test session<input type="password" autoComplete="off" value={newScan.credential} onChange={e=>setNewScan({...newScan,credential:e.target.value})} placeholder={newScan.authMethod==='cookie'?'session=…':'eyJ… or application test token'}/><small>Used in memory for this scan only. Never persisted.</small></label>
            </>:null}

            {newScan.type==='code'?<>
              <label className="field">GitHub repository URL<input type="url" value={newScan.repositoryUrl} onChange={e=>setNewScan({...newScan,repositoryUrl:e.target.value})} placeholder="https://github.com/org/repository"/></label>
              <label className="field">Private repository token (optional)<input type="password" autoComplete="off" value={newScan.repositoryToken} onChange={e=>setNewScan({...newScan,repositoryToken:e.target.value})} placeholder="Used only for this request"/><small>Token values are never stored in scan history.</small></label>
            </>:null}

            <label className="authConfirm"><input type="checkbox" checked={newScan.authorized} onChange={e=>setNewScan({...newScan,authorized:e.target.checked})}/><span><strong>Authorization confirmed</strong><small>I own this target/repository or have explicit permission to test it.</small></span></label>

            <div className="modalFoot"><button className="secondaryBtn" disabled={scanRunning} onClick={()=>setNewScanOpen(false)}>Cancel</button><button className="primaryBtn" disabled={!newScan.authorized||scanRunning} onClick={runNewScan}>{scanRunning?'Scanning…':'Start Scan'}</button></div>
          </section>
        </div>
      ):null}

      {addTargetOpen?(
        <div className="modalBackdrop" onMouseDown={e=>{if(e.target===e.currentTarget)setAddTargetOpen(false)}}>
          <section className="modal smallModal">
            <div className="modalHead"><div><h2>Add Target</h2><p>Add a public HTTP(S) target to this workspace.</p></div><button onClick={()=>setAddTargetOpen(false)}>×</button></div>
            <form onSubmit={addTarget}><label className="field">Target URL<input type="url" required placeholder="https://app.example.com" value={targetUrl} onChange={e=>setTargetUrl(e.target.value)}/></label><div className="modalFoot"><button type="button" className="secondaryBtn" onClick={()=>setAddTargetOpen(false)}>Cancel</button><button className="primaryBtn">Add Target</button></div></form>
          </section>
        </div>
      ):null}

      {selectedRisk?(
        <div className="modalBackdrop riskBackdrop" onMouseDown={e=>{if(e.target===e.currentTarget)setSelectedRisk(null)}}>
          <aside className="riskDrawer">
            <div className="drawerTop"><div><Sev value={selectedRisk.severity}/><Badge tone="blue">{selectedRisk.engine||selectedRisk.category}</Badge></div><button onClick={()=>setSelectedRisk(null)}>×</button></div>
            <h2>{selectedRisk.title}</h2>
            <p className="lead">{selectedRisk.summary}</p>
            <section><h3>Why it matters</h3><p>{selectedRisk.impact||'Review the evidence and affected location to understand the potential security impact.'}</p></section>
            <section><h3>Evidence</h3><pre>{selectedRisk.evidence||selectedRisk.location||'Evidence is available in the scan record.'}</pre></section>
            <section><h3>Recommended fix</h3><p>{selectedRisk.remediation||'Review the upstream advisory or application control and remove the underlying exposure.'}</p></section>
            {selectedRisk._scan?.remediationPlan?.findingGuidance?.[selectedRisk.fingerprint]?<section><h3>Implementation guidance</h3><ol>{(selectedRisk._scan.remediationPlan.findingGuidance[selectedRisk.fingerprint].steps||[]).map((s,i)=><li key={i}>{s}</li>)}</ol></section>:null}
            <section><h3>Workflow</h3><div className="workflowButtons">
              {!selectedRisk._code?<><button onClick={()=>updateRiskStatus(selectedRisk,'open')}>Open</button><button onClick={()=>updateRiskStatus(selectedRisk,'in_progress')}>In progress</button><button onClick={()=>updateRiskStatus(selectedRisk,'resolved')}>Resolved</button><button onClick={()=>updateRiskStatus(selectedRisk,'accepted')}>Accept risk</button><button onClick={()=>updateRiskStatus(selectedRisk,'false_positive')}>False positive</button></>:null}
              {selectedRisk._scanId?<button className="primaryBtn" disabled={retesting} onClick={retestRisk}>{retesting?'Retesting…':'Retest finding'}</button>:null}
            </div></section>
          </aside>
        </div>
      ):null}

      {onboardingOpen?(
        <div className="modalBackdrop onboardingBackdrop">
          <section className="modal onboardingModal">
            <div className="modalHead"><div><h2>What would you like to secure first?</h2><p>This only changes the guidance we show you. You can use every scanner later.</p></div></div>
            <div className="onboardingChoices">
              {[
                ['surface','Monitor my public attack surface','Discover new public assets and exposures.'],
                ['web','Scan a web application or API','Find web, browser, API and configuration risks.'],
                ['code','Scan source code and dependencies','Detect secrets and vulnerable packages.'],
                ['monitor','Set up continuous monitoring','Track regressions and generate reports over time.']
              ].map(([key,title,desc])=><button key={key} className={onboardingChoice===key?'selected':''} onClick={()=>setOnboardingChoice(key)}><span className="choiceIcon">{key==='surface'?'◎':key==='web'?'</>':key==='code'?'⌘':'◷'}</span><div><strong>{title}</strong><span>{desc}</span></div><i>{onboardingChoice===key?'●':'○'}</i></button>)}
            </div>
            <div className="modalFoot"><button className="textBtn" onClick={finishOnboarding}>Skip</button><button className="primaryBtn" onClick={()=>{finishOnboarding(); if(onboardingChoice)setView(onboardingChoice==='surface'||onboardingChoice==='web'?'scans':onboardingChoice==='code'?'settings':'settings')}}>Continue</button></div>
          </section>
        </div>
      ):null}
    </main>
  );
}
