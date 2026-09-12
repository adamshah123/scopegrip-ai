import { createServerClient } from '@supabase/ssr';
import { NextResponse, type NextRequest } from 'next/server';
export async function proxy(request: NextRequest) {
 const url=process.env.NEXT_PUBLIC_SUPABASE_URL, key=process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
 if(!url || !key) return new NextResponse('ScopeGrip is not configured. Complete the environment setup in README.md.',{status:503});
 const nonce=Buffer.from(crypto.randomUUID()).toString('base64');
 const csp=["default-src 'self'",`script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${process.env.NODE_ENV==='development'?" 'unsafe-eval'":''}`,"style-src 'self' 'unsafe-inline'",`connect-src 'self' ${new URL(url).origin}`,"img-src 'self' data:","font-src 'self'", "object-src 'none'", "base-uri 'self'", "frame-ancestors 'none'", "form-action 'self'"].join('; ');
 const headers=new Headers(request.headers);headers.set('x-nonce',nonce);headers.set('Content-Security-Policy',csp);
 let response=NextResponse.next({request:{headers}});
 const supabase=createServerClient(url,key,{cookies:{getAll:()=>request.cookies.getAll(),setAll:values=>{
 values.forEach(({name,value})=>request.cookies.set(name,value));
 headers.set('cookie',request.cookies.toString());response=NextResponse.next({request:{headers}});
 values.forEach(({name,value,options})=>response.cookies.set(name,value,options));
 }}});
 try {await supabase.auth.getUser();} catch {return new NextResponse('Authentication service temporarily unavailable.',{status:503});}
 response.headers.set('Content-Security-Policy',csp);response.headers.set('Cache-Control','private, no-store');
 return response;
}
export const config={matcher:['/((?!_next/static|_next/image|favicon.ico|api/stripe/webhook|api/health).*)']};
