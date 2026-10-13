import crypto from 'node:crypto';
import {spawn} from 'node:child_process';
const url=process.env.TEST_DATABASE_URL;
if(!url||!new URL(url).pathname.startsWith('/inspector_qa'))throw new Error('Use isolated TEST_DATABASE_URL.');
const env={...process.env,DATABASE_URL:url,APP_ORIGINS:'http://localhost:3100',INSPECTOR_BACKEND:'1',JOB_ENCRYPTION_KEY:crypto.randomBytes(32).toString('base64')};
// No worker consumer and no provider credentials: journeys cannot trigger external work.
for(const key of ['RESEND_API_KEY','STRIPE_SECRET_KEY','PAGESPEED_API_KEY'])delete env[key];
const server=spawn(process.execPath,['node_modules/next/dist/bin/next','start','-p','3100','-H','127.0.0.1'],{env,stdio:'inherit'});
try{
 let ready=false;for(let i=0;i<60;i++){try{if((await fetch('http://localhost:3100/api/health')).ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,500));}
 if(!ready)throw new Error('QA server did not start');
 for(const file of ['tests/account-journey.mjs','tests/browser-journey.mjs']){
  const child=spawn(process.execPath,[file],{env:{...env,QA_BASE_URL:'http://localhost:3100'},stdio:'inherit'});
  const code=await new Promise(r=>child.on('exit',r));if(code)throw new Error(file+' failed');
 }
}finally{server.kill('SIGTERM');await new Promise(r=>server.on('exit',r));}
