import { NextResponse } from 'next/server';
import { z } from 'zod';
import { body, checked, failure, identity, sameOrigin } from '@/lib/http';
export async function POST(req:Request) {
 try { sameOrigin(req); const {name}=await body(req,z.object({name:z.string().trim().min(1).max(80)}).strict());
 const {db}=await identity(); const id=checked(await db.rpc('create_workspace',{workspace_name:name})); return NextResponse.json({id});
 } catch(e) {return failure(e);}
}
