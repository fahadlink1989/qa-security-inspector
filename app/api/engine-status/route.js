import { scannerWorkerHealth } from '../../../lib/workerClient';

export const runtime='nodejs';
export const dynamic='force-dynamic';

export async function GET(){
  const worker=await scannerWorkerHealth();
  return Response.json({
    builtIn:[
      {id:'playwright',name:'Playwright',purpose:'Rendered browser QA',status:'built-in'},
      {id:'axe',name:'axe-core',purpose:'Accessibility analysis',status:'built-in'},
      {id:'nvd',name:'NVD / OSV enrichment',purpose:'Version and dependency vulnerability intelligence',status:'built-in'}
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
      ].map(engine=>({...engine,status:worker.reachable&&worker.capabilities[engine.id]===true?'available':worker.configured?'unavailable':'not configured'}))
    }
  },{headers:{'cache-control':'no-store'}});
}
