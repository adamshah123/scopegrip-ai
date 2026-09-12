import { NextResponse } from 'next/server';
import { authorize, body, checked, failure, HttpError, sameOrigin, workspaceBody } from '@/lib/http';
import { stripeClient } from '@/lib/stripe';
import { adminDb } from '@/lib/supabase/admin';
import { appUrl, env } from '@/lib/env';
import { withOperation } from '@/lib/operations';
export async function POST(req:Request) {
 try {
 sameOrigin(req); const {workspaceId}=await body(req,workspaceBody); await authorize(workspaceId,true);
 return await withOperation(workspaceId,false,async()=>{
 const stripe=stripeClient(),db=adminDb(); const price=await stripe.prices.retrieve(env('STRIPE_PRICE_ID'));
 if(!price.active || price.currency!=='usd' || price.unit_amount!==4900 || price.recurring?.interval!=='month' || price.recurring.interval_count!==1 || price.recurring.usage_type!=='licensed') throw new HttpError(503,'Configure an active USD $49/month recurring Stripe price.');
 const account=checked(await db.from('billing_accounts').select('*').eq('workspace_id',workspaceId).single());
 if(!account) throw new Error('Billing account missing'); let customerId:string=account.customer_id;
 if(!customerId) {
 const customer=await stripe.customers.create({metadata:{workspace_id:workspaceId}},{idempotencyKey:`workspace-customer-${workspaceId}`}); customerId=customer.id;
 checked(await db.from('billing_accounts').update({customer_id:customerId}).eq('workspace_id',workspaceId));
 }
 const subscriptions=await stripe.subscriptions.list({customer:customerId,status:'all',limit:100});
 if(subscriptions.data.some(s=>!['canceled','incomplete_expired'].includes(s.status))) throw new HttpError(409,'This workspace already has a subscription. Use Manage billing.');
 const open=await stripe.checkout.sessions.list({customer:customerId,status:'open',limit:100});
 const reusable=open.data.find(s=>s.mode==='subscription' && s.metadata?.workspace_id===workspaceId);
 if(reusable?.url) return NextResponse.json({url:reusable.url});
 const session=await stripe.checkout.sessions.create({mode:'subscription',customer:customerId,client_reference_id:workspaceId,
 line_items:[{price:price.id,quantity:1}],metadata:{workspace_id:workspaceId},subscription_data:{metadata:{workspace_id:workspaceId}},
 success_url:`${appUrl()}/?billing=success`,cancel_url:`${appUrl()}/?billing=cancelled`}, {idempotencyKey:`checkout-${workspaceId}-${subscriptions.data[0]?.id || 'initial'}-${Math.floor(Date.now()/1800000)}`});
 if(!session.url) throw new Error('Checkout URL missing'); return NextResponse.json({url:session.url});
 });
 } catch(e) {return failure(e);}
}
