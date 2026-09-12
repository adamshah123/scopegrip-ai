'use client';
import { useState } from 'react';
import { createClient } from '@/lib/supabase/client';
export default function PasswordPage(){
 const [password,setPassword]=useState(''),[message,setMessage]=useState(''),[busy,setBusy]=useState(false);
 async function submit(e:React.FormEvent){e.preventDefault();setBusy(true);setMessage('');try{
 const db=createClient();const {data:{user}}=await db.auth.getUser();if(!user)throw new Error('Open a fresh password recovery link first.');
 const {error}=await db.auth.updateUser({password});if(error)throw error;await db.auth.signOut({scope:'global'});window.location.assign('/login?password=updated');
 }catch(e){setMessage(e instanceof Error?e.message:'Password update failed.');}finally{setBusy(false);}}
 return <main className="mx-auto flex min-h-screen max-w-md flex-col justify-center px-6"><form className="panel space-y-5 p-6" onSubmit={submit}><h1 className="text-2xl font-semibold">Set a new password</h1><label className="block text-sm">New password<input autoComplete="new-password" className="input mt-2" type="password" minLength={12} required value={password} onChange={e=>setPassword(e.target.value)}/></label><button className="btn w-full" disabled={busy}>{busy?'Updating…':'Update password'}</button><p aria-live="polite" className="text-sm text-amber-300">{message}</p><a href="/login" className="block text-sm underline">Back to sign in</a></form></main>;
}
