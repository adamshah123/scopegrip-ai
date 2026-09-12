import { NextResponse } from 'next/server';
import { authorize, body, checked, failure, HttpError, sameOrigin, workspaceBody } from '@/lib/http';
import { stripeClient } from '@/lib/stripe';
import { adminDb } from '@/lib/supabase/admin';
import { appUrl } from '@/lib/env';
export async function POST(req:Request) {
 try { sameOrigin(req); const {workspaceId}=await body(req,workspaceBody); await authorize(workspaceId,true);
 const account=checked(await adminDb().from('billing_accounts').select('customer_id').eq('workspace_id',workspaceId).single());
 if(!account?.customer_id) throw new HttpError(409,'Subscribe before opening the billing portal.');
 const session=await stripeClient().billingPortal.sessions.create({customer:account.customer_id,return_url:appUrl()});
 return NextResponse.json({url:session.url});
 } catch(e) {return failure(e);}
}
