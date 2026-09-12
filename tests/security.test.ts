import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { PGlite } from '@electric-sql/pglite';
import { randomBytes } from 'node:crypto';
import { seal, unseal } from '../lib/crypto';
import { riskFloor, maxRisk } from '../lib/risk-policy';
test('encrypted refresh tokens reject wrong tenants and tampering',()=>{
 const key=randomBytes(32).toString('base64');const cipher=seal('refresh-token',key,'tenant-a');
 assert.equal(unseal(cipher,key,'tenant-a'),'refresh-token');assert.throws(()=>unseal(cipher,key,'tenant-b'));
 const bytes=Buffer.from(cipher,'base64');bytes[30]^=1;assert.throws(()=>unseal(bytes.toString('base64'),key,'tenant-a'));
});
test('sensitive scopes cannot be downgraded by model output',()=>{
 assert.equal(riskFloor(['https://www.googleapis.com/auth/drive']),'HIGH');
 assert.equal(riskFloor(['https://www.googleapis.com/auth/admin.directory.user.security']),'HIGH');
 assert.equal(riskFloor(['https://www.googleapis.com/auth/drive.readonly']),'MEDIUM');
 assert.equal(riskFloor(['unknown-scope']),'MEDIUM');assert.equal(riskFloor([]),'MEDIUM');
 assert.equal(riskFloor(['openid','email']),'LOW');assert.equal(maxRisk('HIGH','LOW'),'HIGH');
});
test('Postgres tenant boundaries, write restrictions, leases, atomic snapshots, and billing ordering',async()=>{
 const db=new PGlite();
 try {
 await db.exec(`create role anon; create role authenticated; create role service_role bypassrls;
 create schema auth; create table auth.users(id uuid primary key);
 create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('request.jwt.claim.sub',true),'')::uuid $$;
 grant usage on schema auth to authenticated,service_role; grant execute on function auth.uid() to authenticated,service_role;
 insert into auth.users values ('00000000-0000-0000-0000-000000000001'),('00000000-0000-0000-0000-000000000002'),('00000000-0000-0000-0000-000000000003');`);
 await db.exec(await readFile(new URL('../schema.sql',import.meta.url),'utf8'));
 const a='00000000-0000-0000-0000-000000000001',b='00000000-0000-0000-0000-000000000002',viewer='00000000-0000-0000-0000-000000000003';
 async function asUser(id:string) {await db.exec('reset role; set role authenticated;');await db.query("select set_config('request.jwt.claim.sub',$1,false)",[id]);}
 await asUser(a);const wa=(await db.query<{id:string}>("select public.create_workspace('Alpha') as id")).rows[0].id;
 await asUser(b);const wb=(await db.query<{id:string}>("select public.create_workspace('Beta') as id")).rows[0].id;
 assert.deepEqual((await db.query<{id:string}>('select id from public.workspaces')).rows.map(r=>r.id),[wb]);
 assert.equal((await db.query('select * from public.workspace_members where workspace_id=$1',[wa])).rows.length,0);
 await assert.rejects(db.query("insert into public.workspace_members values($1,$2,'owner')",[wa,b]));
 await assert.rejects(db.query("update public.billing_accounts set status='active' where workspace_id=$1",[wb]));
 await assert.rejects(db.query('select * from public.google_connections'));
 await assert.rejects(db.query('select public.acquire_operation($1,gen_random_uuid(),false)',[wb]));
 await db.exec('reset role;');
 await db.query("insert into public.workspace_members values($1,$2,'viewer')",[wa,viewer]);
 const scanId=(await db.query<{id:string}>("insert into public.scans(workspace_id,started_by) values($1,$2) returning id",[wa,a])).rows[0].id;
 const token='10000000-0000-0000-0000-000000000001',other='10000000-0000-0000-0000-000000000002';
 await db.exec('set role service_role;');
 assert.equal((await db.query<{ok:boolean}>('select public.acquire_operation($1,$2,true) as ok',[wa,token])).rows[0].ok,true);
 assert.equal((await db.query<{ok:boolean}>('select public.acquire_operation($1,$2,false) as ok',[wa,other])).rows[0].ok,false);
 const grant={google_user_id:'google-user',user_email:'user@example.com',client_id:'client-1',display_name:'Example',scopes:['openid'],risk:'LOW',summary:'Identity only',possible_ai:false,assessment_source:'rules'};
 await assert.rejects(db.query('select public.finish_scan($1,$2,$3,1,$4::jsonb)',[wa,other,scanId,JSON.stringify([grant])]));
 await assert.rejects(db.query('select public.finish_scan($1,$2,$3,1,$4::jsonb)',[wa,token,scanId,JSON.stringify([grant,grant])]));
 assert.equal((await db.query('select * from public.oauth_grants')).rows.length,0);
 await db.query('select public.finish_scan($1,$2,$3,1,$4::jsonb)',[wa,token,scanId,JSON.stringify([grant])]);
 await asUser(b);assert.equal((await db.query('select * from public.oauth_grants')).rows.length,0);assert.equal((await db.query('select * from public.scans')).rows.length,0);
 await asUser(viewer);assert.equal((await db.query('select * from public.oauth_grants')).rows.length,1);
 await assert.rejects(db.query("update public.oauth_grants set revoked_at=now()"));
 await db.exec('reset role; set role service_role;');
 await assert.rejects(db.query(`insert into public.oauth_grants(workspace_id,scan_id,google_user_id,user_email,client_id,display_name,scopes,risk,summary,assessment_source) values($1,$2,'x','x','x','x','{}','LOW','x','rules')`,[wb,scanId]));
 const event=(await db.query<{id:string}>("insert into public.revocation_events(workspace_id,actor_id,google_user_id,client_id,status) values($1,$2,'google-user','client-1','pending') returning id",[wa,a])).rows[0].id;
 await db.query("select public.finish_revoke($1,$2,$3,'google-user','client-1',$4)",[wa,token,event,a]);
 assert.ok((await db.query<{revoked_at:string}>('select revoked_at from public.oauth_grants')).rows[0].revoked_at);
 await db.query("update public.operation_locks set expires_at=now()-interval '1 minute' where workspace_id=$1",[wa]);
 assert.equal((await db.query<{ok:boolean}>('select public.acquire_operation($1,$2,true) as ok',[wa,other])).rows[0].ok,false);
 assert.equal((await db.query<{ok:boolean}>('select public.acquire_operation($1,$2,false) as ok',[wa,other])).rows[0].ok,true);
 await db.query("update public.billing_accounts set customer_id='cus_a' where workspace_id=$1",[wa]);
 await db.query("select public.apply_billing($1,'cus_a','sub_a','canceled',now(),20)",[wa]);
 await db.query("select public.apply_billing($1,'cus_a','sub_a','active',now(),10)",[wa]);
 await db.query("select public.apply_billing($1,'cus_wrong','sub_a','active',now(),30)",[wa]);
 assert.equal((await db.query<{status:string}>('select status from public.billing_accounts where workspace_id=$1',[wa])).rows[0].status,'canceled');
 await db.exec('reset role; set role anon;');await assert.rejects(db.query('select * from public.workspaces'));
 } finally {await db.close();}
});
