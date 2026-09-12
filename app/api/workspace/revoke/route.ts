import { NextResponse } from 'next/server';
import { z } from 'zod';
import { authorize, body, checked, failure, HttpError, sameOrigin } from '@/lib/http';
import { directory, googleOptions } from '@/lib/google';
import { adminDb } from '@/lib/supabase/admin';
import { withOperation } from '@/lib/operations';
import { env } from '@/lib/env';
export const runtime='nodejs';
export async function POST(req:Request) {
 try {
 sameOrigin(req); const {workspaceId,grantId}=await body(req,z.object({workspaceId:z.string().uuid(),grantId:z.string().uuid()}).strict());
 const {user}=await authorize(workspaceId,true);
 return await withOperation(workspaceId,false,async token=>{
 const db=adminDb(); const grant=checked(await db.from('oauth_grants').select('*').eq('id',grantId).eq('workspace_id',workspaceId).maybeSingle());
 if(!grant) throw new HttpError(404,'Grant not found.');
 if(grant.client_id===env('GOOGLE_CLIENT_ID')) throw new HttpError(409,'Manage ScopeGrip’s own connection in Google Admin to avoid locking out this audit session.');
 const {api,customerId}=await directory(workspaceId);
 const {data:target}=await api.users.get({userKey:grant.google_user_id},googleOptions);
 if(target.customerId!==customerId) throw new HttpError(403,'User is outside this Google Workspace.');
 const event=checked(await db.from('revocation_events').insert({workspace_id:workspaceId,actor_id:user.id,google_user_id:grant.google_user_id,client_id:grant.client_id,status:'pending'}).select('id').single());
 if(!event) throw new Error('Audit event failed');
 try { await api.tokens.delete({userKey:grant.google_user_id,clientId:grant.client_id},googleOptions); }
 catch(e) { if((e as {response?:{status?:number}}).response?.status!==404) {
 checked(await db.from('revocation_events').update({status:'failed'}).eq('id',event.id)); throw e;
 } }
 try {checked(await db.rpc('finish_revoke',{w:workspaceId,t:token,e:event.id,u:grant.google_user_id,c:grant.client_id,actor:user.id}));}
 catch {throw new HttpError(502,'Google revocation succeeded, but local confirmation failed. Retry this grant to reconcile it.');}
 return NextResponse.json({revoked:true});
 });
 } catch(e) {return failure(e);}
}
