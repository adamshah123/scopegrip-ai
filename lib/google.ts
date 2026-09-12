import 'server-only';
import { google } from 'googleapis';
import { env, appUrl } from '@/lib/env';
import { adminDb } from '@/lib/supabase/admin';
import { unseal } from '@/lib/crypto';
import { HttpError } from '@/lib/http';
export const scopes=['openid','email','https://www.googleapis.com/auth/admin.directory.user.readonly','https://www.googleapis.com/auth/admin.directory.user.security'];
export function oauthClient() { return new google.auth.OAuth2(env('GOOGLE_CLIENT_ID'),env('GOOGLE_CLIENT_SECRET'),`${appUrl()}/api/google/callback`); }
export async function directory(workspaceId:string) {
 const {data,error}=await adminDb().from('google_connections').select('*').eq('workspace_id',workspaceId).single();
 if(error || !data) throw new HttpError(409,'Connect a Google Workspace super administrator first.');
 const auth=oauthClient(); auth.setCredentials({refresh_token:unseal(data.refresh_token_encrypted,env('TOKEN_ENCRYPTION_KEY'),workspaceId)});
 return {api:google.admin({version:'directory_v1',auth}),customerId:data.customer_id};
}
export const googleOptions={timeout:15000,retry:false};
