import { database } from '../../../lib/backend/db';
export const dynamic='force-dynamic';
export async function GET(){
  try{await database().query('SELECT 1 FROM inspector_workspaces LIMIT 1');return Response.json({ok:true,storage:'postgres'});}
  catch{return Response.json({ok:false},{status:503});}
}
