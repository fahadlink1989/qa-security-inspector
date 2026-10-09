import pg from 'pg';
let pool;
export function database() {
  if (!process.env.DATABASE_URL) throw new Error('Transactional database is not configured.');
  return pool ||= new pg.Pool({ connectionString:process.env.DATABASE_URL, max:5,
    connectionTimeoutMillis:10000, idleTimeoutMillis:30000 });
}
export async function transaction(fn) {
  const client=await database().connect();
  try { await client.query('BEGIN'); const result=await fn(client); await client.query('COMMIT'); return result; }
  catch(error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}
