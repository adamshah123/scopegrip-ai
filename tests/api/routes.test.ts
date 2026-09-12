import { beforeEach, describe, expect, it, vi } from 'vitest';
import Stripe from 'stripe';
const mocks=vi.hoisted(()=>({getUser:vi.fn(),member:vi.fn(),from:vi.fn(),rpc:vi.fn(),deleteToken:vi.fn(),getGoogleUser:vi.fn(),directory:vi.fn(),stripe:vi.fn(),requireSubscription:vi.fn()}));
vi.mock('server-only',()=>({}));
vi.mock('@/lib/supabase/server',()=>({createClient:async()=>({auth:{getUser:mocks.getUser},from:()=>({select:()=>({eq:()=>({eq:()=>({single:mocks.member})})})})})}));
vi.mock('@/lib/supabase/admin',()=>({adminDb:()=>({from:mocks.from,rpc:mocks.rpc})}));
vi.mock('@/lib/google',()=>({directory:mocks.directory,googleOptions:{timeout:15000,retry:false}}));
vi.mock('@/lib/operations',()=>({withOperation:async(_w:string,_s:boolean,fn:(t:string)=>Promise<unknown>)=>fn('lease'),requireSubscription:mocks.requireSubscription}));
vi.mock('@/lib/stripe',()=>({stripeClient:mocks.stripe}));
vi.mock('@/lib/risk',()=>({assess:vi.fn()}));
import { POST as revoke } from '@/app/api/workspace/revoke/route';
import { POST as scan } from '@/app/api/workspace/scan/route';
import { POST as webhook } from '@/app/api/stripe/webhook/route';
import { HttpError, authorize } from '@/lib/http';
const workspaceId='00000000-0000-4000-8000-000000000001',grantId='00000000-0000-4000-8000-000000000002';
function req(payload:unknown,origin='https://scopegrip.test'){return new Request(`${origin}/api/workspace/revoke`,{method:'POST',headers:{origin,'content-type':'application/json'},body:JSON.stringify(payload)});}
function result(data:unknown){const chain:any={};for(const k of ['select','eq','update','insert'])chain[k]=()=>chain;chain.maybeSingle=async()=>({data,error:null});chain.single=async()=>({data,error:null});chain.then=(resolve:Function)=>resolve({data,error:null});return chain;}
beforeEach(()=>{
 vi.resetAllMocks();process.env.APP_URL='https://scopegrip.test';process.env.GOOGLE_CLIENT_ID='scopegrip-client';process.env.STRIPE_PRICE_ID='price_expected';process.env.STRIPE_WEBHOOK_SECRET='whsec_test';
 mocks.getUser.mockResolvedValue({data:{user:{id:'owner'}},error:null});mocks.member.mockResolvedValue({data:{role:'owner'},error:null});
 mocks.rpc.mockResolvedValue({data:null,error:null});mocks.deleteToken.mockResolvedValue({});mocks.getGoogleUser.mockResolvedValue({data:{customerId:'google-customer'}});
 mocks.directory.mockResolvedValue({customerId:'google-customer',api:{users:{get:mocks.getGoogleUser},tokens:{delete:mocks.deleteToken}}});
 mocks.from.mockImplementation((table:string)=>result(table==='oauth_grants'?{id:grantId,google_user_id:'google-user',client_id:'third-party',workspace_id:workspaceId}:{id:'audit-event'}));
});
describe('authorization and revocation',()=>{
 it('rejects cross-origin requests before Google access',async()=>{expect((await revoke(req({workspaceId,grantId},'https://evil.test'))).status).toBe(403);expect(mocks.directory).not.toHaveBeenCalled();});
 it('rejects unauthenticated users',async()=>{mocks.getUser.mockResolvedValue({data:{user:null},error:null});expect((await revoke(req({workspaceId,grantId}))).status).toBe(401);});
 it('rejects viewers for writes but permits workspace reads',async()=>{mocks.member.mockResolvedValue({data:{role:'viewer'},error:null});await expect(authorize(workspaceId)).resolves.toBeDefined();expect((await revoke(req({workspaceId,grantId}))).status).toBe(403);expect(mocks.directory).not.toHaveBeenCalled();});
 it('rejects users without tenant membership',async()=>{mocks.member.mockResolvedValue({data:null,error:{code:'missing'}});expect((await revoke(req({workspaceId,grantId}))).status).toBe(403);});
 it('rejects malformed IDs',async()=>{expect((await revoke(req({workspaceId:'bad',grantId}))).status).toBe(400);});
 it('bounds the body before parsing',async()=>{expect((await revoke(req({workspaceId,grantId,padding:'x'.repeat(9000)}))).status).toBe(413);});
 it('refuses users outside the connected Google customer',async()=>{mocks.getGoogleUser.mockResolvedValue({data:{customerId:'other-customer'}});expect((await revoke(req({workspaceId,grantId}))).status).toBe(403);expect(mocks.deleteToken).not.toHaveBeenCalled();});
 it('treats an absent Google token as already revoked and reconciles local data',async()=>{mocks.deleteToken.mockRejectedValue({response:{status:404}});expect((await revoke(req({workspaceId,grantId}))).status).toBe(200);expect(mocks.rpc).toHaveBeenCalledWith('finish_revoke',expect.objectContaining({w:workspaceId,u:'google-user',c:'third-party'}));});
 it('reports successful Google deletion followed by local persistence failure',async()=>{mocks.rpc.mockResolvedValue({data:null,error:{message:'offline'}});const response=await revoke(req({workspaceId,grantId}));expect(response.status).toBe(502);expect((await response.json()).error).toMatch(/Google revocation succeeded/);});
 it('prevents unpaid scans before provider calls',async()=>{mocks.requireSubscription.mockRejectedValue(new HttpError(402,'Subscription required'));expect((await scan(req({workspaceId}))).status).toBe(402);expect(mocks.directory).not.toHaveBeenCalled();});
});
describe('Stripe webhook signature and entitlement',()=>{
 const real=new Stripe('sk_test_not_a_real_key');
 function setup(price='price_expected'){
 mocks.stripe.mockReturnValue({webhooks:real.webhooks,subscriptions:{retrieve:async()=>({id:'sub_1',customer:'cus_1',metadata:{workspace_id:workspaceId},status:'active',current_period_end:2000000000,items:{data:[{quantity:1,price:{id:price,currency:'usd',unit_amount:4900,recurring:{interval:'month',interval_count:1}}}]}})}});
 mocks.from.mockReturnValue(result({workspace_id:workspaceId,subscription_id:'sub_1'}));
 }
 function signed(){const payload=JSON.stringify({id:'evt_1',type:'customer.subscription.updated',created:1900000000,data:{object:{id:'sub_1'}}});return new Request('https://scopegrip.test/api/stripe/webhook',{method:'POST',body:payload,headers:{'stripe-signature':real.webhooks.generateTestHeaderString({payload,secret:'whsec_test'})}});}
 it('rejects forged signatures without touching billing',async()=>{setup();expect((await webhook(req({}))).status).toBe(400);expect(mocks.rpc).not.toHaveBeenCalled();});
 it('applies a verified matching-price subscription',async()=>{setup();expect((await webhook(signed())).status).toBe(200);expect(mocks.rpc).toHaveBeenCalledWith('apply_billing',expect.objectContaining({new_status:'active',w:workspaceId,customer:'cus_1'}));});
 it('does not grant access for another Stripe price',async()=>{setup('price_wrong');expect((await webhook(signed())).status).toBe(200);expect(mocks.rpc).toHaveBeenCalledWith('apply_billing',expect.objectContaining({new_status:'invalid_price'}));});
});
