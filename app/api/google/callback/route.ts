import { createHash } from 'node:crypto';
import { google } from 'googleapis';
import { NextResponse } from 'next/server';
import { authorize, checked, identity } from '@/lib/http';
import { adminDb } from '@/lib/supabase/admin';
import { oauthClient, googleOptions, scopes } from '@/lib/google';
import { seal } from '@/lib/crypto';
import { appUrl, env } from '@/lib/env';
import { withOperation } from '@/lib/operations';
export async function GET(req:Request) {
 try {
 const {user}=await identity(); const params=new URL(req.url).searchParams;
 const state=params.get('state'),code=params.get('code'); if(!state || !code || state.length!==64) throw new Error('Invalid callback');
 const db=adminDb(); const saved=checked(await db.from('oauth_states').delete().eq('state_hash',createHash('sha256').update(state).digest('hex')).eq('user_id',user.id).gt('expires_at',new Date().toISOString()).select().single());
 if(!saved) throw new Error('Expired OAuth state'); await authorize(saved.workspace_id,true);
 await withOperation(saved.workspace_id,false,async()=>{
 const auth=oauthClient(); const {tokens}=await auth.getToken(code); if(!tokens.refresh_token || !tokens.id_token) throw new Error('Offline consent required');
 const payload=(await auth.verifyIdToken({idToken:tokens.id_token,audience:env('GOOGLE_CLIENT_ID')})).getPayload();
 if(!payload?.email_verified || !payload.email) throw new Error('Verified email required');
 const granted=new Set((tokens.scope || '').split(' ')); if(scopes.filter(s=>s.startsWith('https:')).some(s=>!granted.has(s))) throw new Error('Missing consent');
 auth.setCredentials(tokens); const api=google.admin({version:'directory_v1',auth});
 const {data:admin}=await api.users.get({userKey:payload.email},googleOptions);
 if(!admin.isAdmin || !admin.customerId) throw new Error('Super administrator required');
 const old=checked(await db.from('google_connections').select('customer_id').eq('workspace_id',saved.workspace_id).maybeSingle());
 if(old && old.customer_id!==admin.customerId) throw new Error('Workspace customer cannot be changed');
 checked(await db.from('google_connections').upsert({workspace_id:saved.workspace_id,customer_id:admin.customerId,admin_email:payload.email,refresh_token_encrypted:seal(tokens.refresh_token,env('TOKEN_ENCRYPTION_KEY'),saved.workspace_id),connected_at:new Date().toISOString()}));
 });
 return NextResponse.redirect(`${appUrl()}/?google=connected`);
 } catch { return NextResponse.redirect(`${appUrl()}/?google=failed`); }
}
