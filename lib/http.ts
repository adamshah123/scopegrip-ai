import 'server-only';
import { NextResponse } from 'next/server';
import { ZodError, z } from 'zod';
import { createClient } from '@/lib/supabase/server';
import { boundedText, BodyTooLarge } from '@/lib/request-body';
import { appUrl } from '@/lib/env';
export class HttpError extends Error { constructor(public status: number, message: string) { super(message); } }
export function sameOrigin(req: Request) { if (req.headers.get('origin') !== appUrl()) throw new HttpError(403,'Invalid request origin.'); }
export async function body<T>(req: Request, schema: z.ZodType<T>): Promise<T> {
 try { return schema.parse(JSON.parse(await boundedText(req,8192))); } catch(e) { if(e instanceof BodyTooLarge)throw new HttpError(413,'Request too large.');throw new HttpError(400,'Invalid request.'); }
}
export async function identity() {
 const db = await createClient(); const {data:{user},error} = await db.auth.getUser();
 if (error || !user) throw new HttpError(401,'Sign in to continue.'); return {db,user};
}
export async function authorize(workspaceId: string, owner = false) {
 const {db,user} = await identity();
 const {data,error} = await db.from('workspace_members').select('role').eq('workspace_id',workspaceId).eq('user_id',user.id).single();
 if (error || !data || (owner && data.role !== 'owner')) throw new HttpError(403,'Workspace access denied.');
 return {db,user};
}
export function failure(error: unknown) {
 if (error instanceof HttpError) return NextResponse.json({error:error.message},{status:error.status});
 if (error instanceof ZodError) return NextResponse.json({error:'Invalid data.'},{status:400});
 console.error('ScopeGrip operation failed', {type: error instanceof Error ? error.name : 'Unknown'});
 return NextResponse.json({error:'Operation failed. Check provider configuration and try again.'},{status:500});
}
export function checked<T>(result: {data:T;error:unknown}): T { if(result.error) throw new Error('Database operation failed'); return result.data; }
export const workspaceBody = z.object({workspaceId:z.string().uuid()}).strict();
