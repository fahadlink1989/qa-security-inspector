import { database } from '../../../lib/backend/db';
import { withWorkspace } from '../../../lib/backend/auth';
import { scannerWorkerHealth } from '../../../lib/workerClient';

export const runtime='nodejs';
export const dynamic='force-dynamic';

async function handleGET(){
  const worker=await scannerWorkerHealth();
  const heartbeat=await database().query("SELECT last_seen, last_seen>now()-interval '90 seconds' AS healthy FROM inspector_worker_heartbeats WHERE id='consumer'");
  return Response.json({
    orchestration:{storage:'postgres',durableQueue:true,consumerHealthy:Boolean(heartbeat.rows[0]?.healthy),lastHeartbeat:heartbeat.rows[0]?.last_seen||null},
    builtIn:[
      {id:'playwright',name:'Playwright',purpose:'Rendered browser QA',status:'available'},
      {id:'axe',name:'axe-core',purpose:'Accessibility analysis',status:'available'},
      {id:'nvd',name:'NVD / OSV enrichment',purpose:'Version and dependency vulnerability intelligence',status:'available'}
    ],
    worker:{
      ...worker,
      engines:[
        {id:'zap',name:'OWASP ZAP',profile:'safe baseline'},
        {id:'nuclei',name:'Nuclei',profile:'safe templates'},
        {id:'naabu',name:'Naabu',profile:'safe port discovery'},
        {id:'openvas',name:'Greenbone / OpenVAS',profile:'network assessment'},
        {id:'trivy',name:'Trivy',profile:'code / image / IaC'},
        {id:'gitleaks',name:'Gitleaks',profile:'repository secrets'}
      ].map(engine=>({...engine,available:Boolean(worker.connected&&worker.health?.engines?.[engine.id]),status:worker.connected&&worker.health?.engines?.[engine.id]?'available':'unavailable'}))
    }
  },{headers:{'cache-control':'no-store'}});
}


export const GET=withWorkspace(handleGET);
