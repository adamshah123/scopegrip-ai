import { redirect } from 'next/navigation';
import { createClient } from '@/lib/supabase/server';
import Dashboard from './dashboard';
export const dynamic='force-dynamic';
export default async function Page() {
 const db=await createClient(); const {data:{user}}=await db.auth.getUser(); if(!user) redirect('/login');
 return <Dashboard email={user.email || 'Signed in'} userId={user.id}/>;
}
