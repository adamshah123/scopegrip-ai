begin;
create table public.workspaces (
 id uuid primary key default gen_random_uuid(), name text not null check(length(name) between 1 and 80),
 created_by uuid not null references auth.users(id), created_at timestamptz not null default now()
);
create table public.workspace_members (
 workspace_id uuid not null references public.workspaces(id) on delete cascade,
 user_id uuid not null references auth.users(id) on delete cascade,
 role text not null check(role in ('owner','viewer')), primary key(workspace_id,user_id)
);
create index workspace_members_user on public.workspace_members(user_id);
create table public.scans (
 id uuid primary key default gen_random_uuid(), workspace_id uuid not null references public.workspaces(id) on delete cascade,
 started_by uuid not null references auth.users(id), status text not null default 'running' check(status in ('running','complete','failed')),
 users_scanned integer not null default 0, grant_count integer not null default 0,
 created_at timestamptz not null default now(), completed_at timestamptz, error text, unique(workspace_id,id)
);
create index scans_workspace_date on public.scans(workspace_id,created_at desc);
create table public.oauth_grants (
 id uuid primary key default gen_random_uuid(), workspace_id uuid not null references public.workspaces(id) on delete cascade,
 scan_id uuid not null, google_user_id text not null, user_email text not null, client_id text not null, display_name text not null,
 scopes text[] not null, risk text not null check(risk in ('HIGH','MEDIUM','LOW')), summary text not null,
 possible_ai boolean not null default false, assessment_source text not null check(assessment_source in ('openai','rules')),
 revoked_at timestamptz, revoked_by uuid references auth.users(id),
 foreign key(workspace_id,scan_id) references public.scans(workspace_id,id) on delete cascade,
 unique(scan_id,google_user_id,client_id)
);
create index grants_workspace_scan on public.oauth_grants(workspace_id,scan_id);
create table public.google_connections (
 workspace_id uuid primary key references public.workspaces(id) on delete cascade,
 customer_id text not null unique, admin_email text not null, refresh_token_encrypted text not null,
 connected_at timestamptz not null default now()
);
create table public.billing_accounts (
 workspace_id uuid primary key references public.workspaces(id) on delete cascade,
 customer_id text unique, subscription_id text unique, status text not null default 'inactive',
 period_end timestamptz, event_created bigint not null default 0
);
create table public.operation_locks (
 workspace_id uuid primary key references public.workspaces(id) on delete cascade,
 token uuid not null, expires_at timestamptz not null, last_scan_at timestamptz
);
create table public.oauth_states (
 state_hash text primary key, workspace_id uuid not null references public.workspaces(id) on delete cascade,
 user_id uuid not null references auth.users(id) on delete cascade, expires_at timestamptz not null
);
create table public.revocation_events (
 id uuid primary key default gen_random_uuid(), workspace_id uuid not null references public.workspaces(id) on delete cascade,
 actor_id uuid not null references auth.users(id), google_user_id text not null, client_id text not null,
 status text not null check(status in ('pending','complete','failed')), created_at timestamptz not null default now()
);
create function public.is_member(w uuid) returns boolean language sql stable security definer set search_path = '' as $$
 select exists(select 1 from public.workspace_members where workspace_id=w and user_id=auth.uid());
$$;
revoke all on function public.is_member(uuid) from public;
grant execute on function public.is_member(uuid) to authenticated;
alter table public.workspaces enable row level security;
alter table public.workspace_members enable row level security;
alter table public.scans enable row level security;
alter table public.oauth_grants enable row level security;
alter table public.google_connections enable row level security;
alter table public.billing_accounts enable row level security;
alter table public.operation_locks enable row level security;
alter table public.oauth_states enable row level security;
alter table public.revocation_events enable row level security;
create policy workspace_read on public.workspaces for select to authenticated using(public.is_member(id));
create policy members_read on public.workspace_members for select to authenticated using(public.is_member(workspace_id));
create policy scans_read on public.scans for select to authenticated using(public.is_member(workspace_id));
create policy grants_read on public.oauth_grants for select to authenticated using(public.is_member(workspace_id));
create policy billing_read on public.billing_accounts for select to authenticated using(public.is_member(workspace_id));
create policy revocations_read on public.revocation_events for select to authenticated using(public.is_member(workspace_id));
revoke all on public.workspaces,public.workspace_members,public.scans,public.oauth_grants,public.google_connections,public.billing_accounts,public.operation_locks,public.oauth_states,public.revocation_events from anon,authenticated;
grant select on public.workspaces,public.workspace_members,public.scans,public.oauth_grants,public.billing_accounts,public.revocation_events to authenticated;
grant all on public.workspaces,public.workspace_members,public.scans,public.oauth_grants,public.google_connections,public.billing_accounts,public.operation_locks,public.oauth_states,public.revocation_events to service_role;
create function public.create_workspace(workspace_name text) returns uuid language plpgsql security definer set search_path='' as $$
declare w uuid; u uuid := auth.uid();
begin
 if u is null then raise exception 'Authentication required'; end if;
 perform pg_advisory_xact_lock(hashtextextended(u::text,0));
 if (select count(*) from public.workspaces where created_by=u)>=5 then raise exception 'Workspace limit reached'; end if;
 insert into public.workspaces(name,created_by) values(trim(workspace_name),u) returning id into w;
 insert into public.workspace_members values(w,u,'owner');
 insert into public.billing_accounts(workspace_id) values(w);
 return w;
end $$;
revoke all on function public.create_workspace(text) from public;
grant execute on function public.create_workspace(text) to authenticated;
create function public.acquire_operation(w uuid, t uuid, scanning boolean) returns boolean language plpgsql security definer set search_path='' as $$
declare acquired uuid;
begin
 insert into public.operation_locks(workspace_id,token,expires_at,last_scan_at)
 values(w,t,now()+interval '10 minutes',case when scanning then now() end)
 on conflict(workspace_id) do update set token=t,expires_at=now()+interval '10 minutes',
 last_scan_at=case when scanning then now() else public.operation_locks.last_scan_at end
 where public.operation_locks.expires_at<now() and (not scanning or public.operation_locks.last_scan_at is null or public.operation_locks.last_scan_at<now()-interval '5 minutes')
 returning token into acquired;
 return acquired is not null;
end $$;
create function public.finish_scan(w uuid,t uuid,s uuid, users_count integer, grants jsonb) returns void language plpgsql security definer set search_path='' as $$
begin
 perform 1 from public.operation_locks where workspace_id=w and token=t and expires_at>now() for update;
 if not found then raise exception 'Operation lease expired'; end if;
 perform 1 from public.scans where id=s and workspace_id=w and status='running' for update;
 if not found then raise exception 'Invalid scan'; end if;
 insert into public.oauth_grants(workspace_id,scan_id,google_user_id,user_email,client_id,display_name,scopes,risk,summary,possible_ai,assessment_source)
 select w,s,x.google_user_id,x.user_email,x.client_id,x.display_name,x.scopes,x.risk,x.summary,x.possible_ai,x.assessment_source
 from jsonb_to_recordset(grants) as x(google_user_id text,user_email text,client_id text,display_name text,scopes text[],risk text,summary text,possible_ai boolean,assessment_source text);
 update public.scans set status='complete',completed_at=now(),users_scanned=users_count,grant_count=jsonb_array_length(grants) where id=s;
end $$;
create function public.finish_revoke(w uuid,t uuid,e uuid,u text,c text,actor uuid) returns void language plpgsql security definer set search_path='' as $$
begin
 perform 1 from public.operation_locks where workspace_id=w and token=t and expires_at>now() for update;
 if not found then raise exception 'Operation lease expired'; end if;
 update public.oauth_grants set revoked_at=now(),revoked_by=actor where workspace_id=w and google_user_id=u and client_id=c and revoked_at is null;
 update public.revocation_events set status='complete' where id=e and workspace_id=w;
end $$;
create function public.apply_billing(w uuid,customer text,subscription text,new_status text,ends_at timestamptz,event_time bigint) returns void language plpgsql security definer set search_path='' as $$
begin
 update public.billing_accounts set subscription_id=subscription,status=new_status,period_end=ends_at,event_created=event_time
 where workspace_id=w and customer_id=customer and event_created<=event_time;
end $$;
revoke all on function public.acquire_operation(uuid,uuid,boolean),public.finish_scan(uuid,uuid,uuid,integer,jsonb),public.finish_revoke(uuid,uuid,uuid,text,text,uuid),public.apply_billing(uuid,text,text,text,timestamptz,bigint) from public;
grant execute on function public.acquire_operation(uuid,uuid,boolean),public.finish_scan(uuid,uuid,uuid,integer,jsonb),public.finish_revoke(uuid,uuid,uuid,text,text,uuid),public.apply_billing(uuid,text,text,text,timestamptz,bigint) to service_role;
commit;
