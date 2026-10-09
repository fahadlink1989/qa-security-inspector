import crypto from 'node:crypto';
import { promisify } from 'node:util';
const scrypt=promisify(crypto.scrypt);
export const hashToken=value=>crypto.createHash('sha256').update(value).digest('hex');
export async function passwordHash(password) {
  const salt=crypto.randomBytes(16).toString('hex');
  const key=await scrypt(password,salt,64);
  return salt+':'+key.toString('hex');
}
export async function passwordMatches(password,stored) {
  const [salt,hex]=stored.split(':');
  const expected=Buffer.from(hex,'hex');
  const key=await scrypt(password,salt,64);
  return expected.length===key.length&&crypto.timingSafeEqual(expected,key);
}
function encryptionKey() {
  const key=Buffer.from(process.env.JOB_ENCRYPTION_KEY||'','base64');
  if(key.length!==32) throw new Error('Job encryption key is not configured.');
  return key;
}
export function encryptPayload(value,aad) {
  const iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',encryptionKey(),iv);
  cipher.setAAD(Buffer.from(aad));
  const bytes=Buffer.concat([cipher.update(JSON.stringify(value)),cipher.final()]);
  return [iv,cipher.getAuthTag(),bytes].map(b=>b.toString('base64')).join('.');
}
export function decryptPayload(value,aad) {
  const [iv,tag,bytes]=value.split('.').map(b=>Buffer.from(b,'base64'));
  const cipher=crypto.createDecipheriv('aes-256-gcm',encryptionKey(),iv);
  cipher.setAAD(Buffer.from(aad)); cipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([cipher.update(bytes),cipher.final()]).toString());
}
