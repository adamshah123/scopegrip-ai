import { randomBytes, createHash } from 'node:crypto';
import { NextResponse } from 'next/server';
import { authorize, body, checked, failure, sameOrigin, workspaceBody } from '@/lib/http';
import { oauthClient, scopes } from '@/lib/google';
import { adminDb } from '@/lib/supabase/admin';
export async function POST(req:Request) {
 try { sameOrigin(req); const {workspaceId}=await body(req,workspaceBody); const {user}=await authorize(workspaceId,true);
 const state=randomBytes(32).toString('hex'); const db=adminDb();
 checked(await db.from('oauth_states').delete().eq('user_id',user.id));
 checked(await db.from('oauth_states').insert({state_hash:createHash('sha256').update(state).digest('hex'),workspace_id:workspaceId,user_id:user.id,expires_at:new Date(Date.now()+600000).toISOString()}));
 return NextResponse.json({url:oauthClient().generateAuthUrl({scope:scopes,access_type:'offline',prompt:'consent',state})});
 } catch(e) {return failure(e);}
}
