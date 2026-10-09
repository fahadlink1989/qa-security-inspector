'use client';
import PerformancePanel from './components/PerformancePanel';
import { currentRiskRows, coverageState } from '../lib/riskModel.mjs';

import { useEffect, useMemo, useRef, useState } from 'react';

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
  if(scan.scanType) return scan.scanType;
  if(scan._kind==='network'||scan.type==='network') return 'Internal Network Scan';
  if(scan._kind==='auth'||scan.type==='authenticated-security') return 'Authenticated Scan';
  if(scan._kind==='code'||scan.type==='code-security') return 'Code & Dependencies';
  return scan.mode==='deep'?'Attack Surface Scan':'Web App Scan';
}

export default function Home(){
  const loadEpoch=useRef(0);
  const workspaceSwitching=useRef(false);
  const [data,setData]=useState({projects:[],scans:[],jobs:[],workspace:{}});
  const [workspaceModal,setWorkspaceModal]=useState(false);
  const [workspaceName,setWorkspaceName]=useState('');
  const [workspaceBusy,setWorkspaceBusy]=useState(false);
  const [workspaceError,setWorkspaceError]=useState('');
  const [targetBusy,setTargetBusy]=useState(false);
  const [targetError,setTargetError]=useState('');
  const [scanAfterTarget,setScanAfterTarget]=useState(false);
  const [view,setView]=useState('dashboard');
  const [selectedProjectId,setSelectedProjectId]=useState('');
  const [loading,setLoading]=useState(true);
  const [loadError,setLoadError]=useState('');
  const [notice,setNotice]=useState('');
  const [newScanOpen,setNewScanOpen]=useState(false);
  const [addTargetOpen,setAddTargetOpen]=useState(false);
  const [onboardingOpen,setOnboardingOpen]=useState(false);
  const [onboardingChoice,setOnboardingChoice]=useState('');
  const [scanRunning,setScanRunning]=useState(false);
  const [scanTab,setScanTab]=useState('history');
  const [reportFilters,setReportFilters]=useState({severity:'All',status:'All',section:'all'});
  const [riskSeverity,setRiskSeverity]=useState('All');
  const [riskStatus,setRiskStatus]=useState('All');
  const [selectedRisk,setSelectedRisk]=useState(null);
  const [selectedTarget,setSelectedTarget]=useState(null);
  const [selectedScan,setSelectedScan]=useState(null);
  const [performanceTarget,setPerformanceTarget]=useState('');
  const [pageSpeedKey,setPageSpeedKey]=useState('');
  const [providerBusy,setProviderBusy]=useState(false);
  const [providerMessage,setProviderMessage]=useState('');
  const [riskDraft,setRiskDraft]=useState({owner:'',notes:''});
  const [riskSaving,setRiskSaving]=useState(false);
  const [riskError,setRiskError]=useState('');
  const [riskSearch,setRiskSearch]=useState('');
  const [scanError,setScanError]=useState('');
  useEffect(()=>{setRiskDraft({owner:selectedRisk?.owner||'',notes:selectedRisk?.notes||''});setRiskError('');},[selectedRisk?._riskKey]);
  useEffect(()=>{const close=e=>{if(e.key==='Escape'){setSelectedRisk(null);setSelectedTarget(null);setSelectedScan(null);setPerformanceTarget('');setPageSpeedKey('');setProviderMessage('');if(!scanRunning)setNewScanOpen(false);}};document.addEventListener('keydown',close);return()=>document.removeEventListener('keydown',close);});
  const [retesting,setRetesting]=useState(false);
  const [settings,setSettings]=useState({name:'',schedule:'manual',scheduledMode:'standard',webhookUrl:''});
  const [engineStatus,setEngineStatus]=useState(null);
  const [targetUrl,setTargetUrl]=useState('');
  const [targetLabel,setTargetLabel]=useState('');
  const [editTargetId,setEditTargetId]=useState('');
  const [networkForm,setNetworkForm]=useState({label:'',cidr:''});
  const [networkAuthorized,setNetworkAuthorized]=useState(false);
  const [networkScanningId,setNetworkScanningId]=useState('');
  const [newScan,setNewScan]=useState({
    type:'standard',
    timing:'now',
    assetId:'',
    authorized:false,
    authMethod:'bearer',
    credential:'',
    repositoryUrl:'',
    repositoryToken:'',
    networkTargetId:''
  });

  async function load(preferredProjectId,silent=false){
    if(silent&&workspaceSwitching.current)return;
    const epoch=++loadEpoch.current;
    if(!silent){setLoading(true);setLoadError('');}
    try{
      const [response,engineResponse]=await Promise.all([
        fetch('/api/workspace',{cache:'no-store'}),
        fetch('/api/engine-status',{cache:'no-store'}).catch(()=>null)
      ]);
      if(epoch!==loadEpoch.current)return;
      if(response.status===401){window.location.assign('/login');return;}
      const json=await response.json();
      if(!response.ok) throw new Error(json.error||'Could not load workspace.');
      if(epoch!==loadEpoch.current)return;
      setData(json);
      if(engineResponse?.ok) setEngineStatus(await engineResponse.json());
      const candidate=preferredProjectId||selectedProjectId;
      const id=json.projects?.some(p=>p.id===candidate)?candidate:(json.projects?.[0]?.id||'');
      setSelectedProjectId(id);
      const p=json.projects?.find(x=>x.id===id);
      if(p&&!silent){
        setSettings({name:p.name,schedule:p.schedule||'manual',scheduledMode:p.scheduledMode||'standard',webhookUrl:''});
        setNewScan(prev=>({
          ...prev,
          assetId:p.assets?.some(a=>a.id===prev.assetId)?prev.assetId:(p.assets?.[0]?.id||''),
          networkTargetId:p.networks?.some(n=>n.id===prev.networkTargetId)?prev.networkTargetId:(p.networks?.[0]?.id||'')
        }));
      }
    }catch(error){setNotice(error.message);if(!silent)setLoadError(error.message);}
    finally{if(!silent&&epoch===loadEpoch.current) setLoading(false);}
  }

  useEffect(()=>{
    load();

  },[]);

  const networkWorkerReady=Boolean(engineStatus?.worker?.connected&&engineStatus?.worker?.health?.allowPrivateTargets);
  const project=useMemo(()=>data.projects.find(p=>p.id===selectedProjectId)||null,[data.projects,selectedProjectId]);
  const scans=useMemo(()=>(data.scans||[]).filter(s=>s.projectId===selectedProjectId).sort((a,b)=>String(b.completedAt||b.startedAt).localeCompare(String(a.completedAt||a.startedAt))),[data.scans,selectedProjectId]);
  const latestScan=useMemo(()=>scans[0]||null,[scans]);

  const activeJobs=useMemo(
    ()=>(data.jobs||[]).filter(job=>job.projectId===selectedProjectId&&['queued','running'].includes(job.status))
      .sort((a,b)=>String(b.createdAt||'').localeCompare(String(a.createdAt||''))),
    [data.jobs,selectedProjectId]
  );

  useEffect(()=>{
    if(!selectedProjectId) return;
    const timer=setInterval(()=>load(selectedProjectId,true),activeJobs.length?2500:15000);
    return ()=>clearInterval(timer);
  },[activeJobs.length,selectedProjectId]);

  const scanRows=useMemo(()=>{
    const rows=[
      ...scans,
      ...(project?.performanceScans||[]).map(item=>({...item,_kind:'performance'})),
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

  const currentRisks=useMemo(()=>currentRiskRows(scans,project),[scans,project]);

  const filteredRisks=useMemo(()=>currentRisks.filter(r=>{
    if(riskSearch&&!JSON.stringify([r.title,r.engine,r.owner,r.location,r._scan?.url]).toLowerCase().includes(riskSearch.toLowerCase()))return false;
    if(riskSeverity!=='All' && r.severity!==riskSeverity) return false;
    const status=r.workflowStatus||'open';
    if(riskStatus==='Open' && !['open','in_progress'].includes(status)) return false;
    if(riskStatus==='Accepted' && status!=='accepted') return false;
    if(riskStatus==='Closed' && !['resolved','false_positive'].includes(status)) return false;
    return true;
  }),[currentRisks,riskSeverity,riskStatus,riskSearch]);

  const summary=useMemo(()=>{
    const open=currentRisks.filter(r=>!['resolved','false_positive','accepted'].includes(r.workflowStatus||'open'));
    const accepted=currentRisks.filter(r=>(r.workflowStatus||'open')==='accepted').length;
    const closed=currentRisks.filter(r=>['resolved','false_positive'].includes(r.workflowStatus||'open')).length;
    const latestScores=[...latestByAsset.values()].filter(s=>coverageState(s).complete&&Number.isFinite(s.score)).map(s=>s.score);
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

  async function runPerformance(assetId){
    const response=await fetch('/api/performance',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({projectId:project.id,assetId,authorized:true})});
    const result=await response.json();if(!response.ok)throw new Error(result.error||'Could not queue measurement.');await load(project.id,true);
  }
  async function configurePageSpeed(event,remove=false){
    event?.preventDefault();setProviderBusy(true);setProviderMessage('');
    try{const response=await fetch('/api/performance',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'configure',key:remove?'':pageSpeedKey})});const result=await response.json();if(!response.ok)throw new Error(result.error);setPageSpeedKey('');await load(project?.id,true);setProviderMessage(remove?'Workspace key removed.':'API key saved securely. Run a measurement to verify Google access.');}catch(error){setProviderMessage(error.message);}finally{setProviderBusy(false);}
  }
  function openScanDetails(scan){if(scan._kind==='performance'){setPerformanceTarget(scan.assetId);}else setSelectedScan(scan);}

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
    setSelectedRisk(null);setPerformanceTarget('');
  }

  async function changeWorkspace(body){
    workspaceSwitching.current=true;loadEpoch.current++;
    try{
    const response=await fetch('/api/account',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
    const result=await response.json();if(!response.ok)throw new Error(result.error);
    setSelectedProjectId('');setSelectedRisk(null);setSelectedTarget(null);setSelectedScan(null);setPerformanceTarget('');setPageSpeedKey('');setProviderMessage('');setNewScanOpen(false);setAddTargetOpen(false);
    setTargetUrl('');setTargetLabel('');setEditTargetId('');setScanAfterTarget(false);
    setNewScan(prev=>({...prev,assetId:'',networkTargetId:'',credential:'',repositoryToken:'',authorized:false}));
    setView('dashboard');await load('');
    }finally{workspaceSwitching.current=false;}
  }
  async function createWorkspace(event){
    event.preventDefault();setWorkspaceBusy(true);setWorkspaceError('');
    try{await changeWorkspace({action:'create_workspace',name:workspaceName});setWorkspaceModal(false);setWorkspaceName('');setNotice('Workspace created. Add your first target to get started.');}
    catch(error){setWorkspaceError(error.message);}finally{setWorkspaceBusy(false);}
  }
  async function addTarget(event){
    event.preventDefault();if(!targetUrl||targetBusy)return;
    setTargetBusy(true);setTargetError('');
    try{
      let projectId=project?.id,assetId;
      if(!project){
        const created=await workspaceAction({action:'create_project',name:'Web targets',url:targetUrl,label:targetLabel});
        projectId=created.id;assetId=created.assets[0].id;
      }else{
        const asset=await workspaceAction(editTargetId?{action:'update_asset',projectId,assetId:editTargetId,url:targetUrl,label:targetLabel}:{action:'add_asset',projectId,url:targetUrl,label:targetLabel});
        assetId=asset.id;
      }
      await load(projectId);
      setTargetUrl('');setTargetLabel('');setEditTargetId('');setAddTargetOpen(false);
      if(scanAfterTarget){setNewScan(prev=>({...prev,assetId,authorized:false}));setNewScanOpen(true);setScanAfterTarget(false);}
      else setView('targets');
      setNotice(editTargetId?'Target updated. Previous scan history is retained.':'Target saved. Select New Scan when you are ready; adding a target does not start a scan.');
    }catch(error){setTargetError(error.message);}finally{setTargetBusy(false);}
  }

  function openAddTarget(){setScanAfterTarget(false);setTargetError('');setAddTargetOpen(true);}
  function editTarget(asset){
    setScanAfterTarget(false);setTargetError('');
    setEditTargetId(asset.id);
    setTargetUrl(asset.url);
    setTargetLabel(asset.label||'');
    setAddTargetOpen(true);
  }

  async function removeTarget(asset){
    if(!project||!window.confirm('Remove '+asset.label+' from active targets? Existing scan history will be retained.')) return;
    try{
      await workspaceAction({action:'remove_asset',projectId:project.id,assetId:asset.id});
      await load(project.id);
      setNotice('Target removed from the active list. Previous scan history is retained.');
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
    setNotice('Queueing the internal scan on the authorized worker…');
    try{
      const response=await fetch('/api/network-scan',{
        method:'POST',
        headers:{'content-type':'application/json'},
        body:JSON.stringify({projectId:project.id,networkTargetId,authorized:true})
      });
      const result=await response.json();
      if(!response.ok) throw new Error(result.error||'Network scan failed.');
      await load(project.id,true);
      setView('scans');
      setScanTab('history');
      setNotice('Internal Network Scan queued. Progress and engine coverage will update here.');
    }catch(error){setNotice(error.message);}
    finally{setNetworkScanningId('');}
  }

  async function saveSettings(event){
    event.preventDefault();
    if(!project) return;
    try{
      const patch={name:settings.name,schedule:settings.schedule,scheduledMode:settings.scheduledMode,scheduleAuthorized:settings.scheduleAuthorized===true};
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
    setScanError('');setNotice('Submitting authorized scan…');
    try{
      if(newScan.timing!=='now'&&['standard','deep'].includes(newScan.type)){
        await workspaceAction({action:'schedule_asset',projectId:project.id,assetId:asset.id,frequency:newScan.timing,mode:newScan.type,authorized:true});
        setNewScanOpen(false);setNewScan(prev=>({...prev,authorized:false}));await load(project.id,true);setView('scans');setScanTab('scheduled');setNotice('Recurring scan saved. The first scan queues within a minute, then once per UTC schedule period.');return;
      }
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

      await load(project.id,true);
      setView('scans');
      setScanTab('history');
      setNotice((result.scanType||'Scan')+' queued. Progress and completion status will update here.');
    }catch(error){setScanError(error.message);}
    finally{setScanRunning(false);}
  }

  async function saveRisk(risk,status,details={}){
    setRiskSaving(true);setRiskError('');
    try{
      const updated=await workspaceAction({action:'risk_details',projectId:project.id,
        kind:risk._code?'code':risk._auth?'auth':risk._network?'network':'web',
        scanId:risk._scan.id,fingerprint:risk.fingerprint||risk.id,status,...details});
      await load(project.id,true);
      setSelectedRisk(prev=>prev?{...prev,...updated}:null);
      setNotice('Risk updated. Changes are saved across this target’s scan history.');
    }catch(error){setRiskError(error.message);setNotice(error.message);}
    finally{setRiskSaving(false);}
  }
  async function updateRiskStatus(risk,status){return saveRisk(risk,status);}

  async function retestRisk(){
    if(!selectedRisk?._scanId) return;
    setRetesting(true);
    try{
      const result=await workspaceAction({action:'retest_finding',scanId:selectedRisk._scanId,fingerprint:selectedRisk.fingerprint});
      await load(project.id);
      setNotice('Retest queued. Follow its progress in Scans; the risk status updates after verification.');
      setSelectedRisk(null);setView('scans');
    }catch(error){setNotice(error.message);}
    finally{setRetesting(false);}
  }

  function openNewScan(assetId){
    if(!project?.assets?.some(a=>a.status==='active')){setScanAfterTarget(true);setTargetError('');setAddTargetOpen(true);return;}
    setNewScan(prev=>({...prev,timing:'now',assetId:assetId||prev.assetId||project?.assets?.[0]?.id||'',networkTargetId:prev.networkTargetId||project?.networks?.[0]?.id||'',authorized:false}));
    setScanError('');setNewScanOpen(true);
  }

  function reportHref(format,preview=false){
    if(!project) return '#';
    const params=new URLSearchParams({projectId:project.id,format,section:reportFilters.section});
    if(preview) params.set('preview','1');
    if(reportFilters.severity!=='All') params.set('severity',reportFilters.severity);
    if(reportFilters.status!=='All') params.set('status',reportFilters.status);
    return '/api/report?'+params.toString();
  }

  function finishOnboarding(){
    try{localStorage.setItem('inspector-onboarding-v2','1');}catch{}
    setOnboardingOpen(false);
  }

  if(!loading&&loadError&&!data.workspace?.id)return <main className="emptyState"><h1>Could not load your workspace</h1><p>{loadError}</p><button className="primaryBtn" onClick={()=>load()}>Try again</button></main>;
  if(loading) return <div className="loadingScreen">Loading Inspector…</div>;

  return (
    <main className="productShell">
      <aside className="leftRail">
        <div className="brandMark"><div className="brandIcon">I</div><strong>Inspector</strong></div>

        <div className="workspaceSelect">
          <label htmlFor="workspace-picker">Workspace</label>
          <select id="workspace-picker" value={data.workspace?.id||''} disabled={workspaceBusy} onChange={async e=>{setWorkspaceBusy(true);try{await changeWorkspace({action:'switch_workspace',workspaceId:e.target.value});}catch(error){setNotice(error.message);}finally{setWorkspaceBusy(false);}}}>
            {(data.workspaces||[data.workspace]).filter(w=>w?.id).map(w=><option key={w.id} value={w.id}>{w.name}</option>)}
          </select>
          <button className="secondaryBtn" onClick={()=>{setWorkspaceError('');setWorkspaceModal(true);}}>＋ Create workspace</button>
          {data.projects.length>1?<><label htmlFor="target-group">Target group</label><select id="target-group" value={selectedProjectId} onChange={e=>selectProject(e.target.value)}>{data.projects.map(p=><option key={p.id} value={p.id}>{p.name}</option>)}</select></>:null}
        </div>

        <nav className="primaryNav">
          {[
            ['dashboard','▦','Dashboard'],
            ['targets','▣','Targets'],
            ['scans','◉','Scans'],
            ['risks','⚑','Risks'],
            ['reports','▤','Reports'],
            
            ['settings','⚙','Settings']
          ].map(([key,icon,label])=>(
            <button key={key} className={view===key?'active':''} onClick={()=>setView(key)}>
              <span className="navIcon">{icon}</span><span>{label}</span>
              {key==='risks'&&summary.total?<em>{summary.total}</em>:null}
            </button>
          ))}
        </nav>

        <div className="gettingStarted">
          <div className="getHead"><strong>Getting started</strong><span>{latestScan?'2 of 2':project?'1 of 2':'0 of 2'}</span></div>
          <div className="progressTrack"><i style={{width:latestScan?'100%':project?'50%':'0%'}}/></div>
          <button className={project?'done':''} onClick={openAddTarget}><span>{project?'✓':'1'}</span> Add a target</button>
          <button className={latestScan?'done':''} onClick={()=>openNewScan()}><span>{latestScan?'✓':'2'}</span> Run your first scan</button>
        </div>

        <div className="railBottom">
          <button onClick={()=>setOnboardingOpen(true)}>？ Getting started</button>
          <button onClick={async()=>{await fetch('/api/account',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'logout'})});window.location.assign('/login');}}>Sign out</button>
        </div>
      </aside>

      <section className="workspace">
        <div className="trialBar">Inspector Security Platform · Authorized testing only</div>

        {notice?<div className="toastNotice" role="status"><span>{notice}</span><button onClick={()=>setNotice('')}>×</button></div>:null}

        {view==='dashboard'?(
          <section className="page">
            <header className="pageHeader">
              <div><h1>Dashboard</h1><p>Security posture for {data.workspace?.name||'your workspace'}.</p></div>
              <div className="headerActions">
                <span className="miniStat">▦ {activeJobs.length?activeJobs.length+' scan'+(activeJobs.length===1?'':'s')+' in progress':'No scans in progress'}</span>
                <span className="miniStat">{project?.schedule&&project.schedule!=='manual'?'1 scheduled scan':'Manual scans'}</span>
                <button className="primaryBtn" onClick={()=>openNewScan()}>＋ New Scan</button>
              </div>
            </header>

            {!project?(
              <div className="emptyState"><h2>{data.workspace?.name} is ready</h2><p>Add a website or application you are authorized to test. Then choose a scan and review its results here.</p><button className="primaryBtn" onClick={()=>{setScanAfterTarget(false);setTargetError('');setAddTargetOpen(true);}}>Add your first target</button><p className="muted">1. Add target → 2. Run an authorized scan → 3. Review risks and reports</p></div>
            ):(
              <>
                <div className="journeyStrip"><div><span className="eyebrow">YOUR NEXT STEP</span><h2>{activeJobs.length?'Your scan is running':!scanRows.length?'Establish your security baseline':scanRows.some(s=>!coverageState(s).complete)?'Review gaps in scan coverage':summary.critical+summary.high?'Prioritize your highest risks':'Review findings and track remediation'}</h2><p>{activeJobs.length?'Open scan activity to follow progress. Results appear after evidence is saved.':!scanRows.length?'Run a non-destructive Web App Scan on your first target.':'A scan is a point-in-time assessment. Review both findings and the checks that could not run.'}</p></div><button className="primaryBtn" onClick={()=>activeJobs.length?setView('scans'):!scanRows.length?openNewScan():setView(scanRows.some(s=>!coverageState(s).complete)?'scans':'risks')}>{activeJobs.length?'View activity':!scanRows.length?'Choose a scan':'Review results'}</button></div>
                <div className="coverageStats"><span><b>{project.assets?.length||0}</b> targets</span><span><b>{[...(project.assets||[])].filter(a=>latestByAsset.has(a.id)).length}</b> scanned</span><span><b>{(project.assets||[]).filter(a=>!latestByAsset.has(a.id)).length}</b> unscanned</span><span><b>{[...latestByAsset.values()].filter(s=>!coverageState(s).complete).length}</b> with coverage gaps</span></div>
                <div className="sectionTitle"><h2>{scanRows.length?'Open risks':'Awaiting your first scan'}</h2><span>Total: {summary.total}</span></div>
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
                        <button key={scan.id} className="recentScan" onClick={()=>openScanDetails(scan)}>
                          <div><strong>{scanLabel(scan)}</strong><span>{scan.finalUrl||scan.url}</span><small>{fmt(scan.completedAt||scan.startedAt)}</small></div>
                          <div className="scanRight"><Badge tone={statusTone(scan.status)}>{scan.status==='completed_with_gaps'?'Completed with gaps':scan.status}</Badge><span className="score">{scan._kind==='performance'?'Speed':scan.score??'—'}</span></div>
                        </button>
                      ))}
                      {!scanRows.length?<div className="emptyRow">No scans yet. Start with a Web App Scan.</div>:null}
                    </div>
                  </section>

                  <section className="cardBlock healthBlock">
                    <div className="blockHead"><h2>Observed posture</h2></div>
                    <div className="healthBody">
                      <div className="healthGauge" style={{'--score':summary.health??0}}><strong>{summary.health??'—'}</strong><span>{summary.health!==null?'out of 100':'Not assessed'}</span></div>
                      <div className="healthLegend"><p className="muted">Based on completed web checks only. Unscanned targets and incomplete coverage are excluded; this is not a security certification.</p>
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
              <div className="headerActions"><button className="secondaryBtn" onClick={openAddTarget}>＋ Add Target</button><button className="primaryBtn" onClick={()=>openNewScan()}>＋ New Scan</button></div>
            </header>
            {!project?<div className="emptyState"><h2>No targets in {data.workspace?.name} yet</h2><p>Your workspace is created. Add your first target to begin.</p><button className="primaryBtn" onClick={openAddTarget}>Add your first target</button></div>:(
              <div className="dataCard">
                <div className="tableHeader targetGrid"><span>Target</span><span>Type</span><span>Last scanned</span><span>Created</span><span/></div>
                {(project.assets||[]).map(asset=>{
                  const last=latestByAsset.get(asset.id);
                  return <div className="tableRow targetGrid" key={asset.id}>
                    <button className="targetName detailLink" onClick={()=>setSelectedTarget(asset)}><span className="expand">›</span><div><strong>{asset.label}</strong><small>{asset.url}</small></div></button>
                    <span>Web</span><span>{last?fmt(last.completedAt):'Never'}</span><span>{shortDate(asset.createdAt)}</span>
                    <div className="targetActions"><button className="secondaryBtn smallBtn" onClick={()=>setPerformanceTarget(asset.id)}>Speed</button><button className="secondaryBtn smallBtn" onClick={()=>editTarget(asset)}>Edit</button><button className="rowMenu" onClick={()=>removeTarget(asset)}>Remove</button><button className="primaryBtn smallBtn" onClick={()=>openNewScan(asset.id)}>Scan</button></div>
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
                {activeJobs.map(job=><div className="tableRow scanGrid scanJobRow" key={job.id}>
                  <div className="targetName"><span className="progressSpinner"/><div><strong>{job.scanType}</strong><small>{job.stage}</small></div></div>
                  <span>{job.target}</span>
                  <div className="jobProgress"><div><i style={{width:(job.progress||0)+'%'}}/></div><small>{job.progress||0}% · {job.status}</small></div>
                  <span>{fmt(job.createdAt)}</span>
                  <span className="pendingText">Scanning…</span>
                </div>)}
                {(data.jobs||[]).filter(job=>job.projectId===selectedProjectId&&job.status==='failed'&&!scanRows.some(scan=>scan.id===job.scanId)).map(job=><div className="tableRow scanGrid" key={job.id}>
                  <div><strong>{job.scanType}</strong><small>{job.error||'Scan failed'}</small></div><span>{job.target}</span>
                  <Badge tone="danger">Failed after {job.attempts||1} attempt(s)</Badge><span>{fmt(job.completedAt)}</span>
                  <button className="secondaryBtn" onClick={()=>openNewScan(job.assetId)}>New scan</button>
                </div>)}
                {scanRows.map(scan=><div className="tableRow scanGrid" key={scan.id}>
                  <div className="targetName"><span className="expand">›</span><div><button className="detailLink" onClick={()=>openScanDetails(scan)}><strong>{scanLabel(scan)}</strong></button><small>{scan.trigger||scan._kind||'manual'}</small>{scan.engineRuns?.length?<div className="engineChips">{scan.engineRuns.map(run=><span key={run.engine} className={'engineChip '+run.status}>{run.name||run.engine} · {run.status}</span>)}</div>:null}</div></div>
                  <span>{scan.finalUrl||scan.url||scan.target||scan.repository?.url||'Repository scan'}</span>
                  <div><Badge tone={statusTone(scan.status)}>{scan.status==='completed_with_gaps'?'Completed with gaps':scan.status}</Badge><small className="inlineMeta">{scan._kind==='performance'?'Mobile '+(scan.devices?.mobile?.score??'—')+' · Desktop '+(scan.devices?.desktop?.score??'—'):'Score '+(scan.score??'—')}</small></div>
                  <span>{fmt(scan.completedAt||scan.startedAt)}</span>
                  <div className="riskDots">{scan._kind==='performance'?<span>Performance only</span>:<><span className="dot critical"/>{scan.summary?.critical||0}<span className="dot high"/>{scan.summary?.high||0}<span className="dot medium"/>{scan.summary?.medium||0}<span className="dot low"/>{scan.summary?.low||0}</>}</div>
                </div>)}
                {!scanRows.length?<div className="emptyRow">No completed scan results yet.</div>:null}
              </div>
            ):(
              <div className="dataCard"><div className="blockHead"><h2>Recurring target scans</h2><button onClick={()=>openNewScan()}>Create schedule</button></div>{(project?.assets||[]).map(asset=>{const frequency=asset.schedule??project.schedule;return <div className="historyItem" key={asset.id}><strong>{asset.label}</strong><span>{asset.url}</span><span>{['daily','weekly'].includes(frequency)?frequency+' · '+((asset.scheduledMode||project.scheduledMode)==='deep'?'Attack Surface Scan':'Web App Scan')+' · UTC periods':'Not scheduled'}</span>{['daily','weekly'].includes(frequency)?<button className="secondaryBtn" onClick={async()=>{try{await workspaceAction({action:'schedule_asset',projectId:project.id,assetId:asset.id,frequency:'manual'});await load(project.id,true);setNotice('Schedule stopped for '+asset.label);}catch(error){setNotice(error.message);}}}>Stop schedule</button>:null}</div>})}{!project?.assets?.length?<div className="emptyRow">Add a target before scheduling scans.</div>:null}</div>
            )}
          </section>
        ):null}

        {view==='risks'?(
          <section className="page">
            <header className="pageHeader">
              <div><h1>Risks</h1><p>Normalized security findings across the latest target scans.</p></div>
              <div className="headerActions"><button className="secondaryBtn" onClick={()=>{setRiskSeverity('All');setRiskStatus('All');setRiskSearch('')}}>≡ Clear filters</button><button className="primaryBtn" onClick={()=>openNewScan()}>＋ New Scan</button></div>
            </header>
            <div className="filterBar"><input aria-label="Search risks" placeholder="Search title, target, owner or scanner" value={riskSearch} onChange={e=>setRiskSearch(e.target.value)}/>
              <select aria-label="Risk severity" value={riskSeverity} onChange={e=>setRiskSeverity(e.target.value)}><option>All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Informational</option></select>
              <select aria-label="Risk status" value={riskStatus} onChange={e=>setRiskStatus(e.target.value)}><option>All</option><option>Open</option><option>Accepted</option><option>Closed</option></select>
              <span>{filteredRisks.length} risks</span>
            </div>
            <div className="dataCard">
              <div className="tableHeader riskGrid"><span>Threat</span><span>Vulnerability</span><span>Target</span><span>Detected</span><span>Status</span><span/></div>
              {filteredRisks.map(r=><div className="tableRow riskGrid riskTableRow" key={r._riskKey}>
                <span className={'threatBars '+String(r.severity).toLowerCase()}><i/><i/><i/><i/></span>
                <button className="riskTitle" onClick={()=>setSelectedRisk(r)}><small>{r.engine||r.category}</small><strong>{r.title}</strong>{r.checkId?<Badge tone="blue">{r.checkId}</Badge>:null}</button>
                <span>{r._scan?.finalUrl||r.location||project?.assets?.[0]?.url}</span>
                <span><small>First: {fmt(r.firstSeen||r._scan?.completedAt||r._scan?.scannedAt)}</small><small>Last: {fmt(r.lastSeen||r._scan?.completedAt||r._scan?.scannedAt)}</small></span>
                <Badge tone={(r.workflowStatus||'open')==='accepted'?'success':(r.workflowStatus||'open')==='resolved'?'neutral':'warning'}>{(r.workflowStatus||'open').replaceAll('_',' ')}</Badge>
                <button className="secondaryBtn smallBtn" onClick={()=>setSelectedRisk(r)}>Review</button>
              </div>)}
              {!filteredRisks.length?<div className="emptyRow">No risks match these filters.</div>:null}
            </div>
          </section>
        ):null}

        {view==='reports'?(
          <section className="page">
            <header className="pageHeader"><div><h1>Reports</h1><p>Create stakeholder-ready reports from the latest workspace findings.</p></div></header>
            <div className="tabs"><button className="active">Reports</button><button disabled title="Scheduled report delivery is not available yet">Scheduled Reports · Coming later</button></div>
            {!project||!scanRows.some(s=>s._kind!=='performance')?<div className="emptyState"><h2>Run a scan first</h2><p>A completed scan is required before Inspector can build a report.</p><button className="primaryBtn" onClick={()=>openNewScan()}>{project?'Choose a scan':'Add your first target'}</button></div>:(
              <div className="reportBuilder">
                <h2>Create a Report</h2>
                <label>Report scope<span>Current findings across scan profiles in {project.name}</span></label>
                <div className="reportFilters">
                  <label>Severity<select value={reportFilters.severity} onChange={e=>setReportFilters({...reportFilters,severity:e.target.value})}><option>All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Informational</option></select></label>
                  <label>Status<select value={reportFilters.status} onChange={e=>setReportFilters({...reportFilters,status:e.target.value})}><option>All</option><option>Open</option><option>Accepted</option><option>Closed</option></select></label>
                  <label>Sections<select value={reportFilters.section} onChange={e=>setReportFilters({...reportFilters,section:e.target.value})}><option value="all">Executive summary + all findings</option><option value="security">Security findings only</option><option value="technical">Technical evidence</option></select></label>
                </div>
                <div className="reportActions">
                  <a className="previewBtn" target="_blank" rel="noreferrer" href={reportHref('html',true)}>Preview Report ({project.assets?.length||0} targets, {summary.total} risks)</a>
                  <div>
                    <a className="secondaryBtn linkBtn" href={reportHref('pdf')}>Download PDF ⇩</a>
                    <a className="secondaryBtn linkBtn" href={reportHref('csv')}>Download CSV ⇩</a>
                    <a className="secondaryBtn linkBtn" href={reportHref('html')}>Download HTML ⇩</a>
                  </div>
                </div>
              </div>
            )}
          </section>
        ):null}

        {view==='networks'?(
          <section className="page">
            <header className="pageHeader">
              <div><h1>Internal Networks</h1><p>Scan private RFC1918 networks from a worker deployed where those networks are reachable.</p></div>
              <div className="headerActions">
              <Badge tone={networkWorkerReady?'success':'warning'}>{networkWorkerReady?'Scanner worker connected':'Worker connection required'}</Badge>
              </div>
            </header>

            {!project?<div className="emptyState"><h2>No targets in {data.workspace?.name} yet</h2><p>Your workspace is created. Add your first target to begin.</p><button className="primaryBtn" onClick={openAddTarget}>Add your first target</button></div>:(
              <>
                {!networkWorkerReady?(
                  <div className="networkCallout">
                    <div><strong>Connect an internal scanner worker</strong><span>Private targets are never routed through the public Vercel control plane. Deploy the Inspector scanner worker inside your VPC/network, enable private targets there, and connect it in Settings.</span></div>
                    <button className="secondaryBtn" onClick={()=>setView('settings')}>View scanner setup</button>
                  </div>
                ):null}

                <div className="networkLayout">
                  <form className="settingsCard" onSubmit={addNetworkTarget}>
                    <h2>Add internal network</h2>
                    <p className="muted">For safety, this beta accepts RFC1918 IPv4 ranges from /24 to /32 only.</p>
                    <label>Label<input placeholder="Office LAN" value={networkForm.label} onChange={e=>setNetworkForm({...networkForm,label:e.target.value})}/></label>
                    <label>Private CIDR<input required placeholder="10.20.30.0/24" value={networkForm.cidr} onChange={e=>setNetworkForm({...networkForm,cidr:e.target.value})}/></label>
                    <button className="primaryBtn">Add network</button>
                  </form>

                  <section className="settingsCard">
                    <h2>How internal scanning works</h2>
                    <div className="engineRows compact">
                      <div><strong>Naabu</strong><span>Rate-limited TCP CONNECT discovery across the top 100 ports.</span><Badge tone={networkWorkerReady?'success':'neutral'}>{networkWorkerReady?'Available':'Offline'}</Badge></div>
                      <div><strong>Greenbone / OpenVAS</strong><span>Deeper network vulnerability assessment when the Greenbone adapter is configured.</span><Badge tone={networkWorkerReady?'blue':'neutral'}>{networkWorkerReady&&engineStatus?.worker?.health?.engines?.openvas?'Available':'Unavailable'}</Badge></div>
                    </div>
                    <label className="authConfirm networkAuth"><input type="checkbox" checked={networkAuthorized} onChange={e=>setNetworkAuthorized(e.target.checked)}/><span><strong>Authorization confirmed</strong><small>I own these private networks or have explicit permission to scan them.</small></span></label>
                  </section>
                </div>

                <div className="sectionTitle"><h2>Networks</h2><span>{project.networks?.length||0} registered</span></div>
                <div className="dataCard">
                  <div className="tableHeader networkGrid"><span>Network</span><span>Last scanned</span><span>Open ports</span><span>Engine status</span><span/></div>
                  {(project.networks||[]).map(network=>{
                    const last=(project.networkScans||[]).find(scan=>scan.networkTargetId===network.id);
                    const naabu=last?.engineRuns?.find(run=>run.engine==='naabu');
                    const openvas=last?.engineRuns?.find(run=>run.engine==='openvas');
                    return <div className="tableRow networkGrid" key={network.id}>
                      <div className="targetName"><span className="expand">›</span><div><strong>{network.label}</strong><small>{network.cidr}</small></div></div>
                      <span>{last?fmt(last.completedAt):'Never'}</span>
                      <span>{last?.metrics?.openPorts??'—'}</span>
                      <div className="engineMini"><Badge tone={naabu?.status==='completed'?'success':'neutral'}>Naabu {naabu?.status||'not run'}</Badge><Badge tone={openvas?.status==='completed'?'success':openvas?.status==='failed'?'warning':'neutral'}>OpenVAS {openvas?.status||'not run'}</Badge></div>
                      <button className="primaryBtn smallBtn" disabled={!networkAuthorized||networkScanningId===network.id||!networkWorkerReady} onClick={()=>runNetworkScan(network.id)}>{networkScanningId===network.id?'Scanning…':'Scan'}</button>
                    </div>;
                  })}
                  {!project.networks?.length?<div className="emptyRow">No internal networks registered yet.</div>:null}
                </div>
              </>
            )}
          </section>
        ):null}

        {view==='settings'?(
          <section className="page">
            <header className="pageHeader"><div><h1>Settings</h1><p>Storage: {engineStatus?.orchestration?.storage||'checking'} · Scan consumer: {engineStatus?.orchestration?.consumerHealthy?'connected':'checking / unavailable'}</p><p>Monitoring, notifications and scanner platform configuration.</p><button className="secondaryBtn" onClick={()=>setView('networks')}>Internal network configuration</button></div></header>
            <form className="settingsCard performanceSettings" onSubmit={configurePageSpeed}><h2>Google PageSpeed Insights</h2><p>Measure mobile and desktop loading performance using Google’s real Lighthouse results.</p><p className="muted">{data.workspace?.performanceKeyConfigured?'API key configured.':'No API key configured. Unauthenticated requests may be quota-limited.'}</p><label>Google API key<input type="password" autoComplete="off" value={pageSpeedKey} onChange={e=>setPageSpeedKey(e.target.value)} placeholder="Paste a PageSpeed-enabled Google API key"/></label><p className="muted">Encrypted at rest and used only by the backend. Enable the PageSpeed Insights API in your Google Cloud project and restrict this key to that API.</p><a target="_blank" rel="noreferrer" href="https://developers.google.com/speed/docs/insights/v5/get-started">Google setup instructions ↗</a><div className="headerActions"><button className="primaryBtn" disabled={providerBusy||!pageSpeedKey}>Save API key</button><button type="button" className="secondaryBtn" disabled={providerBusy||!data.workspace?.performanceKeyConfigured} onClick={()=>configurePageSpeed(null,true)}>Remove workspace key</button></div>{providerMessage?<p role="status">{providerMessage}</p>:null}</form>
            {!project?<div className="emptyState"><h2>No targets in {data.workspace?.name} yet</h2><p>Your workspace is created. Add your first target to begin.</p><button className="primaryBtn" onClick={openAddTarget}>Add your first target</button></div>:(
              <div className="settingsGrid">
                <form className="settingsCard" onSubmit={saveSettings}>
                  <h2>Target monitoring</h2>
                  <label>Target group name<input value={settings.name} onChange={e=>setSettings({...settings,name:e.target.value})}/></label>
                  <label>Monitoring schedule<select value={settings.schedule} onChange={e=>setSettings({...settings,schedule:e.target.value})}><option value="manual">Manual</option><option value="daily">Daily</option><option value="weekly">Weekly</option></select></label>
                  <label>Scheduled scan profile<select value={settings.scheduledMode} onChange={e=>setSettings({...settings,scheduledMode:e.target.value})}><option value="standard">Web App Scan</option><option value="deep">Attack Surface Scan</option></select></label>
                  <label>Alert webhook<input type="url" placeholder={project.webhookUrl?'Webhook configured — enter a new URL to replace':'https://hooks.slack.com/...'} value={settings.webhookUrl} onChange={e=>setSettings({...settings,webhookUrl:e.target.value})}/></label>
                  <label><input type="checkbox" checked={settings.scheduleAuthorized||false} onChange={e=>setSettings({...settings,scheduleAuthorized:e.target.checked})}/> I authorize recurring non-destructive scans of this project’s active targets.</label><button className="primaryBtn">Save settings</button>
                </form>

                <section className="settingsCard">
                  <h2>Scanner stack</h2>
                  <p className="muted">Inspector normalizes results behind one risk model. Heavy open-source scanners should run in isolated container workers, not in the web application.</p>
                  <div className="engineRows">
                    <div><strong>Playwright + axe-core</strong><span>Rendered browser QA and accessibility</span><Badge tone="neutral">Built in · verified during scans</Badge></div>
                    {(engineStatus?.worker?.engines||[]).map(engine=><div key={engine.id}><strong>{engine.name}</strong><span>{engine.profile}</span><Badge tone={engine.available?'success':'neutral'}>{engine.available?'Available':'Unavailable'}</Badge></div>)}
                  </div>
                  <p className="muted small">Commercial licensing should be reviewed before redistributing third-party binaries. Nmap is intentionally not an embedded default.</p>
                </section>
              </div>
            )}
          </section>
        ):null}
      </section>

      {performanceTarget&&project?.assets?.some(a=>a.id===performanceTarget)?<PerformancePanel key={performanceTarget} asset={project.assets.find(a=>a.id===performanceTarget)} runs={project.performanceScans||[]} jobs={data.jobs||[]} onRun={runPerformance} onClose={()=>setPerformanceTarget('')} onSettings={()=>{setPerformanceTarget('');setView('settings');}}/>:null}
      {workspaceModal?<div className="modalBackdrop"><section className="modal smallModal" role="dialog" aria-modal="true" aria-labelledby="create-workspace-title">
        <div className="modalHead"><div><h2 id="create-workspace-title">Create workspace</h2><p>Keep a separate organization or client’s targets, scans, and risks together.</p></div><button aria-label="Close workspace dialog" disabled={workspaceBusy} onClick={()=>setWorkspaceModal(false)}>×</button></div>
        <form onSubmit={createWorkspace}><label className="field">Workspace name<input autoFocus required maxLength={100} value={workspaceName} onChange={e=>setWorkspaceName(e.target.value)} placeholder="Company or client name"/></label>{workspaceError?<p role="alert">{workspaceError}</p>:null}<div className="modalFoot"><button type="button" className="secondaryBtn" disabled={workspaceBusy} onClick={()=>setWorkspaceModal(false)}>Cancel</button><button className="primaryBtn" disabled={workspaceBusy}>{workspaceBusy?'Creating…':'Create workspace'}</button></div></form>
      </section></div>:null}
      {newScanOpen?(
        <div className="modalBackdrop" onMouseDown={e=>{if(e.target===e.currentTarget&&!scanRunning)setNewScanOpen(false)}}>
          <section className="modal scanModal" role="dialog" aria-modal="true" aria-label="New scan">
            <div className="modalHead"><div><span className="eyebrow">NEW SCAN</span><h2>Choose what you want to test</h2><p>Inspector will normalize all scanner evidence into the same Risks workflow.</p></div><button disabled={scanRunning} onClick={()=>setNewScanOpen(false)}>×</button></div>

            <div className="scanTypeGrid">
              {[
                ['standard','Web App Scan','Start here','Headers, TLS/DNS, browser QA, accessibility, API discovery and safe exposure checks.'],
                ['deep','Attack Surface Scan','Recommended','Subdomains, live hosts, pages, APIs, CVEs, exposed artifacts and attack paths.'],
                ['authenticated','Authenticated Web/API','Post-login','Compare public vs authorized test-session behavior with read-only requests.'],
                ['code','Code & Dependencies','Repository','Secrets, risky files, pinned dependencies and security-sensitive code patterns.'],
                ['network','Internal Network','Private worker','Rate-limited port discovery plus Greenbone/OpenVAS from an authorized internal worker.']
              ].map(([key,title,kicker,desc])=><button key={key} disabled={key==='network'&&!networkWorkerReady} className={newScan.type===key?'selected':''} onClick={()=>setNewScan({...newScan,type:key})}><span>{key==='network'&&!networkWorkerReady?'Unavailable · private worker required':kicker}</span><strong>{title}</strong><small>{desc}</small></button>)}
            </div>

            {!['code','network'].includes(newScan.type)?<label className="field">Target<select aria-label="Target" value={newScan.assetId} onChange={e=>setNewScan({...newScan,assetId:e.target.value})}>{(project?.assets||[]).map(a=><option key={a.id} value={a.id}>{a.label} · {a.url}</option>)}</select></label>:null}
            {newScan.type==='network'?<label className="field">Internal network<select value={newScan.networkTargetId} onChange={e=>setNewScan({...newScan,networkTargetId:e.target.value})}><option value="">Select network</option>{(project?.networks||[]).map(n=><option key={n.id} value={n.id}>{n.label} · {n.cidr}</option>)}</select><small>Internal scans require the scanner worker to run where it can reach this private CIDR.</small></label>:null}

            {newScan.type==='authenticated'?<>
              <label className="field">Session type<select value={newScan.authMethod} onChange={e=>setNewScan({...newScan,authMethod:e.target.value})}><option value="bearer">Bearer token</option><option value="cookie">Cookie header</option></select></label>
              <label className="field">Authorized test session<input type="password" autoComplete="off" value={newScan.credential} onChange={e=>setNewScan({...newScan,credential:e.target.value})} placeholder={newScan.authMethod==='cookie'?'session=…':'eyJ… or application test token'}/><small>Encrypted while queued and running, then removed when the job finishes.</small></label>
            </>:null}

            {newScan.type==='code'?<>
              <label className="field">GitHub repository URL<input type="url" value={newScan.repositoryUrl} onChange={e=>setNewScan({...newScan,repositoryUrl:e.target.value})} placeholder="https://github.com/org/repository"/></label>
              <label className="field">Private repository token (optional)<input type="password" autoComplete="off" value={newScan.repositoryToken} onChange={e=>setNewScan({...newScan,repositoryToken:e.target.value})} placeholder="Encrypted for this scan job"/><small>Token values are never stored in scan history.</small></label>
            </>:null}

            {['standard','deep'].includes(newScan.type)?<label className="field">When to run<select aria-label="When to run" value={newScan.timing} onChange={e=>setNewScan({...newScan,timing:e.target.value})}><option value="now">Run now</option><option value="daily">Daily monitoring</option><option value="weekly">Weekly monitoring</option></select>{newScan.timing!=='now'?<small>First scan queues within a minute. Runs once per UTC day or fixed seven-day period. Applies only to the selected target.</small>:null}</label>:null}
            <div className="scanExpectations"><h3>Scope and coverage</h3><p>{newScan.type==='standard'?'Read-only web checks, rendered browser QA, accessibility, ZAP passive checks.':newScan.type==='deep'?'Public discovery, web checks, ZAP passive checks and reviewed Nuclei templates. Only authorized public assets are assessed.':newScan.type==='code'?'Public repository analysis with Inspector, Trivy and Gitleaks. Private repositories use Inspector checks; skipped external engines are reported as gaps. No application code is executed.':'Only test sessions and targets you are authorized to assess.'}</p><div className="engineChips">{(engineStatus?.worker?.engines||[]).filter(e=>(newScan.type==='code'?['trivy','gitleaks']:newScan.type==='network'?['naabu','openvas']:newScan.type==='standard'?['zap']:newScan.type==='authenticated'?[]:['zap','nuclei']).includes(e.id)).map(e=><span className="engineChip" key={e.id}>{e.name} · {e.available?'Connected':'Unavailable'}</span>)}</div><p className="muted">Unavailable or failed checks are reported as coverage gaps. No scan proves the absence of vulnerabilities.</p></div>
            {scanError?<p role="alert" className="formError">{scanError}</p>:null}
            <label className="authConfirm"><input type="checkbox" checked={newScan.authorized} onChange={e=>setNewScan({...newScan,authorized:e.target.checked})}/><span><strong>Authorization confirmed</strong><small>I own this target/repository or have explicit permission to test it{newScan.timing!=='now'&&['standard','deep'].includes(newScan.type)?' on the recurring schedule selected above':''}.</small></span></label>

            <div className="modalFoot"><button className="secondaryBtn" disabled={scanRunning} onClick={()=>setNewScanOpen(false)}>Cancel</button><button className="primaryBtn" disabled={!newScan.authorized||scanRunning||(newScan.type==='network'&&!networkWorkerReady)} onClick={runNewScan}>{scanRunning?'Submitting…':newScan.timing!=='now'&&['standard','deep'].includes(newScan.type)?'Save schedule':'Start Scan'}</button></div>
          </section>
        </div>
      ):null}

      {addTargetOpen?(
        <div className="modalBackdrop" onMouseDown={e=>{if(e.target===e.currentTarget)setAddTargetOpen(false)}}>
          <section className="modal smallModal">
            <div className="modalHead"><div><h2>{editTargetId?'Edit Target':'Add Target'}</h2><p>{editTargetId?'Update the active target details. Previous scan history stays available.':'Add a public HTTP(S) target to this workspace.'}</p></div><button onClick={()=>{setAddTargetOpen(false);setEditTargetId('')}}>×</button></div>
            <form onSubmit={addTarget}>{targetError?<p role="alert" className="formError">{targetError}</p>:null}<label className="field">Target name<input type="text" maxLength="100" placeholder="Production app" value={targetLabel} onChange={e=>setTargetLabel(e.target.value)}/></label><label className="field">Target URL<input type="url" required placeholder="https://app.example.com" value={targetUrl} onChange={e=>setTargetUrl(e.target.value)}/></label><div className="modalFoot"><button type="button" className="secondaryBtn" onClick={()=>{setAddTargetOpen(false);setEditTargetId('')}}>Cancel</button><button className="primaryBtn" disabled={targetBusy}>{targetBusy?'Saving…':editTargetId?'Save Target':scanAfterTarget?'Save target & choose scan':'Add Target'}</button></div></form>
          </section>
        </div>
      ):null}

      {selectedRisk?(
        <div className="modalBackdrop riskBackdrop" onMouseDown={e=>{if(e.target===e.currentTarget)setSelectedRisk(null)}}>
          <aside className="riskDrawer" role="dialog" aria-modal="true" aria-label="Risk details">
            <div className="drawerTop"><div><Sev value={selectedRisk.severity}/><Badge tone="blue">{selectedRisk.engine||selectedRisk.category}</Badge></div><button onClick={()=>setSelectedRisk(null)}>×</button></div>
            <h2>{selectedRisk.title}</h2>
            {selectedRisk.coverageUnverified?<p className="muted">Retained from an earlier scan: the latest scan had incomplete coverage and could not verify this risk.</p>:null}
            <p className="lead">{selectedRisk.summary}</p>
            <section><h3>Detection details</h3><p>First seen: {fmt(selectedRisk.firstSeen||selectedRisk._scan?.completedAt||selectedRisk._scan?.scannedAt)} · Last seen: {fmt(selectedRisk.lastSeen||selectedRisk._scan?.completedAt||selectedRisk._scan?.scannedAt)}</p>{selectedRisk.cve?<p>CVE: {String(selectedRisk.cve)}</p>:null}{selectedRisk.cwe?<p>CWE: {String(selectedRisk.cwe)}</p>:null}{selectedRisk.cvss!=null?<p>CVSS: {typeof selectedRisk.cvss==='object'?JSON.stringify(selectedRisk.cvss):String(selectedRisk.cvss)}</p>:null}</section>
            <section><h3>Why it matters</h3><p>{selectedRisk.impact||'Review the evidence and affected location to understand the potential security impact.'}</p></section>
            <section><h3>Evidence</h3><pre>{typeof selectedRisk.evidence==='object'?JSON.stringify(selectedRisk.evidence,null,2):selectedRisk.evidence||selectedRisk.location||'No additional evidence was supplied by this check.'}</pre></section>
            <section><h3>Recommended fix</h3><p>{selectedRisk.remediation||'Review the upstream advisory or application control and remove the underlying exposure.'}</p></section>
            {selectedRisk._scan?.remediationPlan?.findingGuidance?.[selectedRisk.fingerprint]?<section><h3>Implementation guidance</h3><ol>{(selectedRisk._scan.remediationPlan.findingGuidance[selectedRisk.fingerprint].steps||[]).map((s,i)=><li key={i}>{s}</li>)}</ol></section>:null}
            <section><h3>Engineering owner and notes</h3><form onSubmit={e=>{e.preventDefault();saveRisk(selectedRisk,undefined,riskDraft);}}><label className="field">Owner or team<input maxLength={120} value={riskDraft.owner} onChange={e=>setRiskDraft({...riskDraft,owner:e.target.value})} placeholder="e.g. Platform Engineering"/></label><label className="field">Remediation notes<textarea rows={4} maxLength={4000} value={riskDraft.notes} onChange={e=>setRiskDraft({...riskDraft,notes:e.target.value})} placeholder="Fix plan, ticket reference, or acceptance rationale"/></label><p className="muted">Ownership is a saved label. No notification is sent.</p><button className="primaryBtn" disabled={riskSaving}>Save remediation details</button></form>{riskError?<p role="alert">{riskError}</p>:null}</section>
            <section><h3>Verify the fix</h3><p>{selectedRisk._scanId?'Retest repeats the original authorized scan profile. A risk is verified resolved only when the finding is absent and required coverage completed.':'Run the same scan profile again. Authenticated and private repository scans require a fresh authorized credential.'}</p><p className="muted">Marking a risk Resolved is a manual decision, not proof of a verified fix.</p>{(selectedRisk.retests||[]).map((r,i)=><p key={i}>{fmt(r.at)} · {r.status.replaceAll('_',' ')}</p>)}</section>
            <section><h3>Workflow</h3><div className="workflowButtons">
              {<><button onClick={()=>updateRiskStatus(selectedRisk,'open')}>Open</button><button onClick={()=>updateRiskStatus(selectedRisk,'in_progress')}>In progress</button><button onClick={()=>updateRiskStatus(selectedRisk,'resolved')}>Resolved</button><button onClick={()=>updateRiskStatus(selectedRisk,'accepted')}>Accept risk</button><button onClick={()=>updateRiskStatus(selectedRisk,'false_positive')}>False positive</button></>}
              {selectedRisk._scanId?<button className="primaryBtn" disabled={retesting} onClick={retestRisk}>{retesting?'Retesting…':'Retest finding'}</button>:null}
            </div></section><section><h3>Activity</h3>{(selectedRisk.workflowHistory||[]).slice().reverse().map((h,i)=><p key={i}>{fmt(h.at)} · {h.action||((h.from||'open')+' → '+h.to)}</p>)}{!selectedRisk.workflowHistory?.length?<p>No workflow changes yet.</p>:null}</section>
          </aside>
        </div>
      ):null}

      {selectedTarget?<div className="modalBackdrop riskBackdrop"><aside className="riskDrawer" role="dialog" aria-modal="true" aria-label="Target details"><div className="drawerTop"><Badge tone="blue">Web target</Badge><button aria-label="Close target details" onClick={()=>setSelectedTarget(null)}>×</button></div><h2>{selectedTarget.label}</h2><p className="lead">{selectedTarget.url}</p><p>Added {fmt(selectedTarget.createdAt)}</p><button className="primaryBtn" onClick={()=>{openNewScan(selectedTarget.id);setSelectedTarget(null);}}>Scan this target</button><button className="secondaryBtn" onClick={()=>{setPerformanceTarget(selectedTarget.id);setSelectedTarget(null);}}>Mobile & desktop speed</button><section><h3>Scan history</h3>{scanRows.filter(s=>s.assetId===selectedTarget.id).map(s=><button className="historyItem" key={s.id} onClick={()=>{setSelectedTarget(null);openScanDetails(s);}}><strong>{scanLabel(s)}</strong><span>{fmt(s.completedAt||s.scannedAt)} · {coverageState(s).label}</span><span>{s.findings?.length||0} findings →</span></button>)}{!scanRows.some(s=>s.assetId===selectedTarget.id)?<p>No scan has assessed this target yet.</p>:null}</section><section><h3>Discovered relationships</h3><p className="muted">Observed during Attack Surface scans of this target. Discovery does not add a target or schedule scanning automatically.</p>{(scans.find(s=>s.assetId===selectedTarget.id&&s.mode==='deep')?.evidence?.deep?.liveHosts||[]).map((h,i)=><div className="historyItem" key={i}><strong>{h.hostname}</strong><span>{h.url} · HTTP {h.status}</span></div>)}{!scans.some(s=>s.assetId===selectedTarget.id&&s.evidence?.deep?.liveHosts?.length)?<p>No discovered hosts recorded yet.</p>:null}</section><section><h3>Current risks</h3>{currentRisks.filter(r=>r._scan?.assetId===selectedTarget.id).map(r=><button className="historyItem" key={r._riskKey} onClick={()=>{setSelectedTarget(null);setSelectedRisk(r);}}><Sev value={r.severity}/><strong>{r.title}</strong><span>{r.workflowStatus||'open'}</span></button>)}</section></aside></div>:null}
      {selectedScan?<div className="modalBackdrop riskBackdrop"><aside className="riskDrawer" role="dialog" aria-modal="true" aria-label="Scan details"><div className="drawerTop"><Badge tone={coverageState(selectedScan).complete?'success':'warning'}>{coverageState(selectedScan).label} coverage</Badge><button aria-label="Close scan details" onClick={()=>setSelectedScan(null)}>×</button></div><h2>{scanLabel(selectedScan)}</h2><p className="lead">{selectedScan.finalUrl||selectedScan.url||selectedScan.target||selectedScan.repository?.url}</p><p>Started: {fmt(selectedScan.startedAt||selectedScan.scannedAt)}</p><p>Completed: {fmt(selectedScan.completedAt||selectedScan.scannedAt)}</p><section><h3>What ran</h3>{(selectedScan.engineRuns||[]).map((r,i)=><div className="historyItem" key={i}><strong>{r.name||r.engine}</strong><span>{r.status}</span>{r.error?<p>{r.error}</p>:null}</div>)}{!selectedScan.engineRuns?.length?<p>Engine-level telemetry was not recorded for this scan.</p>:null}</section><section><h3>Coverage and limitations</h3>{coverageState(selectedScan).gaps.length?coverageState(selectedScan).gaps.map((g,i)=><p className="formError" key={i}>{g}</p>):<p>{coverageState(selectedScan).complete?'Requested checks completed. Results apply only to this scope at the time of scanning.':'This scan did not complete. No clean assessment can be made.'}</p>}</section><section><h3>Findings ({selectedScan.findings?.length||0})</h3>{(selectedScan.findings||[]).map((f,i)=><div className="historyItem" key={i}><Sev value={f.severity}/><strong>{f.title}</strong><p>{f.summary}</p></div>)}</section><div className="workflowButtons"><button className="primaryBtn" onClick={()=>{setSelectedScan(null);setView('risks');}}>Manage risks</button><a className="secondaryBtn" href={'/api/report?'+new URLSearchParams({projectId:project.id,scanId:selectedScan.id,format:'pdf',section:'technical'})}>Download scan report</a></div></aside></div>:null}

      {onboardingOpen?(
        <div className="modalBackdrop onboardingBackdrop">
          <section className="modal onboardingModal">
            <div className="modalHead"><div><h2>Get started with Inspector</h2><p>Your workspace keeps your targets, scans, risks, and reports together.</p></div></div>
            <ol><li><strong>Add a target.</strong> Enter a website or app you own or have permission to test.</li><li><strong>Start a scan.</strong> Choose the scan type and confirm authorization. Watch progress in Scans.</li><li><strong>Review the result.</strong> Open Risks for evidence and remediation, then use Reports to export findings.</li></ol>
            <div className="modalFoot"><button className="secondaryBtn" onClick={finishOnboarding}>Close</button><button className="primaryBtn" onClick={()=>{finishOnboarding();project?openNewScan():setAddTargetOpen(true);}}>{project?'Choose a scan':'Add your first target'}</button></div>
          </section>
        </div>
      ):null}
    </main>
  );
}

