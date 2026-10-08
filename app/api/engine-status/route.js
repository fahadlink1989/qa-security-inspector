import { scannerWorkerStatus } from '../../../lib/workerClient';

export const runtime='nodejs';
export const dynamic='force-dynamic';

export async function GET(){
  const worker=scannerWorkerStatus();
  return Response.json({
    builtIn:[
      {id:'playwright',name:'Playwright',purpose:'Rendered browser QA',status:'connected'},
      {id:'axe',name:'axe-core',purpose:'Accessibility analysis',status:'connected'},
      {id:'nvd',name:'NVD / OSV enrichment',purpose:'Version and dependency vulnerability intelligence',status:'connected'}
    ],
    worker:{
      ...worker,
      engines:[
        {id:'zap',name:'OWASP ZAP',profile:'safe baseline'},
        {id:'nuclei',name:'Nuclei',profile:'safe templates'},
        {id:'openvas',name:'Greenbone / OpenVAS',profile:'network assessment'},
        {id:'trivy',name:'Trivy',profile:'code / image / IaC'},
        {id:'gitleaks',name:'Gitleaks',profile:'repository secrets'}
      ]
    }
  },{headers:{'cache-control':'no-store'}});
}
