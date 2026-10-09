import crypto from 'node:crypto';
import { consumeOne,scheduleDueJobs } from '../../../../lib/backend/consumer';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export async function POST(request) {
  const expected=process.env.INTERNAL_WORKER_SECRET||'';
  const supplied=request.headers.get('authorization')||'';
  const a=Buffer.from(supplied),b=Buffer.from('Bearer '+expected);
  if(!expected||a.length!==b.length||!crypto.timingSafeEqual(a,b))return new Response('Unauthorized',{status:401});
  try {
    if(new URL(request.url).searchParams.has('schedule')){await scheduleDueJobs();return Response.json({ok:true});}
    return Response.json(await consumeOne());
  }catch{return Response.json({error:'Consumer operation failed'},{status:503});}
}
