import { NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase/server';
import { appUrl } from '@/lib/env';
export async function GET(req:Request) {
 const params=new URL(req.url).searchParams,code=params.get('code');
 if(code){const db=await createClient();const {error}=await db.auth.exchangeCodeForSession(code);if(!error)return NextResponse.redirect(`${appUrl()}/account/password`);}
 return NextResponse.redirect(`${appUrl()}/login?auth=expired`);
}
