import { NextResponse } from 'next/server';
import Stripe from 'stripe';
import { boundedText } from '@/lib/request-body';
import { stripeClient } from '@/lib/stripe';
import { env } from '@/lib/env';
import { adminDb } from '@/lib/supabase/admin';
import { checked, failure } from '@/lib/http';
export const runtime='nodejs';
export async function POST(req:Request) {
 const stripe=stripeClient(); let event:Stripe.Event;
 try { event=stripe.webhooks.constructEvent(await boundedText(req,1048576),req.headers.get('stripe-signature') || '',env('STRIPE_WEBHOOK_SECRET')); }
 catch {return NextResponse.json({error:'Invalid webhook signature.'},{status:400});}
 try {
 if(['customer.subscription.created','customer.subscription.updated','customer.subscription.deleted'].includes(event.type)) {
 const incoming=event.data.object as Stripe.Subscription;
 const sub=await stripe.subscriptions.retrieve(incoming.id);
 const w=sub.metadata.workspace_id;
 if(w) {
 const customer=typeof sub.customer==='string'?sub.customer:sub.customer.id;
 const db=adminDb(); const account=checked(await db.from('billing_accounts').select('workspace_id,subscription_id').eq('workspace_id',w).eq('customer_id',customer).maybeSingle());
 if(!account) throw new Error('Unrecognized billing mapping');
 const item=sub.items.data[0]; const valid=sub.items.data.length===1 && item?.price.id===env('STRIPE_PRICE_ID') && item.quantity===1 && item.price.currency==='usd' && item.price.unit_amount===4900 && item.price.recurring?.interval==='month' && item.price.recurring.interval_count===1;
 if(!account.subscription_id || account.subscription_id===sub.id || !['canceled','incomplete_expired'].includes(sub.status)) {
 checked(await db.rpc('apply_billing',{w,customer,subscription:sub.id,new_status:valid?sub.status:'invalid_price',ends_at:new Date(sub.current_period_end*1000).toISOString(),event_time:event.created}));
 }
 }
 }
 return NextResponse.json({received:true});
 } catch(e) {return failure(e);}
}
