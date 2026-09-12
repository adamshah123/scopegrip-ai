import 'server-only';
import { randomUUID } from 'node:crypto';
import { adminDb } from '@/lib/supabase/admin';
import { checked, HttpError } from '@/lib/http';
export async function withOperation<T>(workspaceId:string,scanning:boolean,fn:(token:string)=>Promise<T>):Promise<T> {
 const db=adminDb(), token=randomUUID();
 if(!checked(await db.rpc('acquire_operation',{w:workspaceId,t:token,scanning}))) throw new HttpError(409,'An operation is running, or the five-minute scan cooldown has not elapsed.');
 try { return await fn(token); }
 finally { const {error}=await db.from('operation_locks').update({expires_at:new Date(0).toISOString()}).eq('workspace_id',workspaceId).eq('token',token); if(error) console.error('Could not release operation lease'); }
}
export async function requireSubscription(w:string) {
 const data=checked(await adminDb().from('billing_accounts').select('status,period_end').eq('workspace_id',w).single());
 if(!data || !['active','trialing'].includes(data.status) || !data.period_end || Date.parse(data.period_end)<=Date.now()) throw new HttpError(402,'An active workspace subscription is required to scan.');
}
