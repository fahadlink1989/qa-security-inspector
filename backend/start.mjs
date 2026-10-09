import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import pg from 'pg';
const db=new pg.Client({connectionString:process.env.DATABASE_URL});
await db.connect();
try {
  await db.query('BEGIN');await db.query('SELECT pg_advisory_xact_lock(7463821)');
  await db.query(await readFile(new URL('../migrations/001_backend.sql',import.meta.url),'utf8'));
  await db.query('COMMIT');
}catch(error){await db.query('ROLLBACK');throw error;}finally{await db.end();}
const port=process.env.PORT||'3000';
const child=spawn(process.execPath,['node_modules/next/dist/bin/next','start','-p',port,'-H','::'],{stdio:'inherit',env:process.env});
let stopping=false;
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function tick(schedule=false){
  return fetch(`http://127.0.0.1:${port}/api/internal/tick${schedule?'?schedule=1':''}`,{
    method:'POST',headers:{authorization:'Bearer '+process.env.INTERNAL_WORKER_SECRET},signal:AbortSignal.timeout(1800000)});
}
async function consume(){
  while(!stopping){try{const response=await tick();if(!response.ok)console.error('Consumer request failed:',response.status);}catch{if(!stopping)console.error('Consumer reconnecting');}await sleep(2000);}
}
async function schedule(){while(!stopping){try{await tick(true);}catch{}await sleep(60000);}}
child.on('exit',code=>{stopping=true;process.exit(code||1);});
for(const signal of ['SIGTERM','SIGINT'])process.on(signal,()=>{stopping=true;child.kill(signal);});
if(process.env.VERIFY_BACKEND==='1') {
  for(let i=0;i<60;i++){try{if((await fetch(`http://127.0.0.1:${port}/api/health`)).ok)break;}catch{}await sleep(1000);}
  try{await (await import('./verify.mjs')).verifyBackend(`http://127.0.0.1:${port}`);}
  catch(error){console.error('BACKEND_VERIFICATION_FAILED',error.message);}
}
consume();schedule();
