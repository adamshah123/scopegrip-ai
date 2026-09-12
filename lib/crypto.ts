import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
export function seal(value: string, secret: string, tenant: string) {
 const key=Buffer.from(secret,'base64'); if(key.length!==32) throw new Error('Encryption key must be 32 bytes');
 const iv=randomBytes(12); const cipher=createCipheriv('aes-256-gcm',key,iv); cipher.setAAD(Buffer.from(tenant));
 const encrypted=Buffer.concat([cipher.update(value,'utf8'),cipher.final()]);
 return Buffer.concat([iv,cipher.getAuthTag(),encrypted]).toString('base64');
}
export function unseal(value: string, secret: string, tenant: string) {
 const data=Buffer.from(value,'base64'); const decipher=createDecipheriv('aes-256-gcm',Buffer.from(secret,'base64'),data.subarray(0,12));
 decipher.setAAD(Buffer.from(tenant)); decipher.setAuthTag(data.subarray(12,28));
 return Buffer.concat([decipher.update(data.subarray(28)),decipher.final()]).toString('utf8');
}
