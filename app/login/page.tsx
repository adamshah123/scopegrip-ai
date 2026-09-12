'use client';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { createClient } from '@/lib/supabase/client';
export default function Login() {
 const router=useRouter(); const [mode,setMode]=useState<'login'|'signup'|'reset'>('login');
 const [email,setEmail]=useState(''),[password,setPassword]=useState(''),[message,setMessage]=useState(''),[busy,setBusy]=useState(false);
 useEffect(()=>{const p=new URLSearchParams(window.location.search);if(p.get('auth')==='expired')setMessage('This email link is invalid or expired. Request a new one.');if(p.get('password')==='updated')setMessage('Password updated. Sign in with your new password.');},[]);
 async function submit(e:React.FormEvent) {
 e.preventDefault();setBusy(true);setMessage('');
 try {const auth=createClient().auth;if(mode==='reset'){const {error}=await auth.resetPasswordForEmail(email,{redirectTo:`${window.location.origin}/auth/callback`});if(error)throw error;setMessage('If an account exists, a recovery email is on its way.');return;}const {data,error}=mode==='login'?await auth.signInWithPassword({email,password}):await auth.signUp({email,password});
 if(error) throw error;
 if(data.session) {router.replace('/');router.refresh();} else setMessage('Check your email to confirm your account, then sign in.');
 } catch(e) {setMessage(e instanceof Error?e.message:'Sign-in failed.');} finally {setBusy(false);}
 }
 return <main className="mx-auto flex min-h-screen max-w-md flex-col justify-center px-6 py-12">
 <div className="mb-8"><p className="mb-4 text-sm font-semibold uppercase tracking-widest text-emerald-400">ScopeGrip AI</p><h1 className="text-3xl font-semibold">Take control of app access.</h1><p className="mt-3 text-slate-400">Audit Google Workspace permissions in one place.</p></div>
 <form onSubmit={submit} className="panel space-y-5 p-6"><h2 className="text-xl">{mode==='login'?'Welcome back':mode==='reset'?'Reset your password':'Create your account'}</h2>
 <label className="block text-sm">Email<input className="input mt-2" type="email" autoComplete="email" required value={email} onChange={e=>setEmail(e.target.value)}/></label>
 {mode!=='reset'&&<label className="block text-sm">Password<input className="input mt-2" type="password" autoComplete={mode==='login'?'current-password':'new-password'} minLength={12} required value={password} onChange={e=>setPassword(e.target.value)}/></label>}
 <button className="btn w-full" disabled={busy}>{busy?'Please wait…':mode==='login'?'Sign in':mode==='reset'?'Send recovery email':'Create account'}</button><p aria-live="polite" className="text-sm text-amber-300">{message}</p>
 <button type="button" className="text-sm text-slate-400 underline" onClick={()=>setMode(mode==='login'?'signup':'login')}>{mode==='login'?'New here? Create an account':'Already registered? Sign in'}</button>
 <button type="button" className="block text-sm text-slate-400 underline" onClick={()=>{setMode(mode==='reset'?'login':'reset');setMessage('');}}>{mode==='reset'?'Back to sign in':'Forgot your password?'}</button>
 </form></main>;
}
