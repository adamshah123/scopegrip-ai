import { NextResponse } from 'next/server';
import type { EmailOtpType } from '@supabase/supabase-js';
import { createClient } from '@/lib/supabase/server';
import { appUrl } from '@/lib/env';
export async function GET(req:Request) {
 const p=new URL(req.url).searchParams,tokenHash=p.get('token_hash'),type=p.get('type');
 if(tokenHash && (type==='signup'||type==='recovery'||type==='email')) {
 const db=await createClient();const {error}=await db.auth.verifyOtp({token_hash:tokenHash,type:type as EmailOtpType});
 if(!error)return NextResponse.redirect(`${appUrl()}${type==='recovery'?'/account/password':'/'}`);
 }
 return NextResponse.redirect(`${appUrl()}/login?auth=expired`);
}
