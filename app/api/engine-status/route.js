import { withWorkspace } from '../../../lib/backend/auth';
import { scannerWorkerHealth } from '../../../lib/workerClient';

export const runtime='nodejs';
export const dynamic='force-dynamic';

async function handleGET(){
  const worker=await scannerWorkerHealth();
  return Response.json({
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
