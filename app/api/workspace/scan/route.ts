import { NextResponse } from 'next/server';
import { authorize, body, checked, failure, HttpError, sameOrigin, workspaceBody } from '@/lib/http';
import { directory, googleOptions } from '@/lib/google';
import { adminDb } from '@/lib/supabase/admin';
import { assess } from '@/lib/risk';
import { requireSubscription, withOperation } from '@/lib/operations';
export const runtime='nodejs';
export const maxDuration=300;
export async function POST(req:Request) {
 try {
 sameOrigin(req); const {workspaceId}=await body(req,workspaceBody); const {user}=await authorize(workspaceId,true); await requireSubscription(workspaceId);
 return await withOperation(workspaceId,true,async token=>{
 const db=adminDb(); const scan=checked(await db.from('scans').insert({workspace_id:workspaceId,started_by:user.id}).select('id').single());
 if(!scan) throw new Error('Scan creation failed');
 try {
 const started=Date.now(); const budget=()=>{if(Date.now()-started>240000) throw new HttpError(422,'Scan exceeded the MVP time budget. Use a durable scan worker for this tenant.');};
 const {api,customerId}=await directory(workspaceId);
 const users: {id:string;email:string}[]=[]; let pageToken:string|undefined;
 do {
 budget(); const {data}=await api.users.list({customer:customerId,maxResults:100,pageToken,projection:'basic'},googleOptions);
 for(const u of data.users || []) {if(!u.id || !u.primaryEmail) throw new Error('Incomplete directory user'); users.push({id:u.id,email:u.primaryEmail});}
 if(users.length>50) throw new HttpError(422,'This MVP supports at most 50 users per workspace.'); pageToken=data.nextPageToken || undefined;
 } while(pageToken);
 const grants=[]; const cache=new Map<string,Awaited<ReturnType<typeof assess>>>();
 for(const u of users) {
 budget(); const {data}=await api.tokens.list({userKey:u.id},googleOptions);
 for(const item of data.items || []) {
 if(!item.clientId) throw new Error('Incomplete OAuth grant');
 const scopes=[...new Set(item.scopes || [])].sort(), displayName=(item.displayText || item.clientId).slice(0,300);
 if(scopes.length>200 || scopes.some(s=>s.length>1000)) throw new Error('Scope payload too large');
 const key=JSON.stringify([item.clientId,scopes]); let risk=cache.get(key);
 if(!risk) { budget(); risk=await assess(displayName,scopes); cache.set(key,risk); }
 grants.push({google_user_id:u.id,user_email:u.email,client_id:item.clientId,display_name:displayName,scopes,...risk});
 if(grants.length>500) throw new HttpError(422,'This MVP supports at most 500 user/app grants per scan.');
 }
 }
 budget(); checked(await db.rpc('finish_scan',{w:workspaceId,t:token,s:scan.id,users_count:users.length,grants}));
 return NextResponse.json({scanId:scan.id,users:users.length,grants:grants.length});
 } catch(e) {
 const {error}=await db.from('scans').update({status:'failed',completed_at:new Date().toISOString(),error:e instanceof HttpError?e.message:'Provider or database failure. Reconnect Google and retry.'}).eq('id',scan.id).eq('workspace_id',workspaceId);
 if(error) console.error('Could not record failed scan'); throw e;
 }
 });
 } catch(e) { return failure(e); }
}
