-- ============================================================
-- TREZO v2.5 — Migration multi-utilisateurs & droits d'accès
-- À exécuter UNE FOIS dans Supabase → SQL Editor → Run
-- (sans danger pour les données existantes)
-- ============================================================

alter table public.memberships add column if not exists perms jsonb not null default '{}'::jsonb;

create table if not exists public.invitations (
  code       text primary key,
  company_id uuid not null references public.companies(id) on delete cascade,
  perms      jsonb not null default '{}'::jsonb,
  created_by uuid not null,
  created_at timestamptz not null default now(),
  used_by    uuid,
  used_at    timestamptz
);
alter table public.invitations enable row level security;
revoke all on public.invitations from anon, authenticated;

create or replace function public.is_owner(cid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.memberships
                 where company_id = cid and user_id = auth.uid() and role = 'owner');
$$;

create or replace function public.create_invitation(p_company uuid, p_perms jsonb) returns text
language plpgsql security definer set search_path = public as $$
declare c text;
begin
  if not public.is_owner(p_company) then raise exception 'not_owner'; end if;
  c := 'TRZ-' || upper(substr(md5(random()::text || clock_timestamp()::text), 1, 8));
  insert into public.invitations(code, company_id, perms, created_by)
    values (c, p_company, coalesce(p_perms, '{}'::jsonb), auth.uid());
  return c;
end $$;

create or replace function public.join_with_code(p_code text) returns json
language plpgsql security definer set search_path = public as $$
declare inv public.invitations; c public.companies;
begin
  if auth.uid() is null then raise exception 'auth_required'; end if;
  if exists (select 1 from public.memberships where user_id = auth.uid()) then
    raise exception 'already_has_company';
  end if;
  select * into inv from public.invitations
   where code = upper(trim(p_code)) and used_by is null
     and created_at > now() - interval '30 days';
  if inv.code is null then raise exception 'invalid_code'; end if;
  insert into public.memberships(user_id, company_id, role, perms)
    values (auth.uid(), inv.company_id, 'user', inv.perms);
  update public.invitations set used_by = auth.uid(), used_at = now() where code = inv.code;
  select * into c from public.companies where id = inv.company_id;
  return row_to_json(c);
end $$;

create or replace function public.list_members(p_company uuid) returns json
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_owner(p_company) then raise exception 'not_owner'; end if;
  return coalesce((
    select json_agg(json_build_object(
      'user_id', m.user_id, 'role', m.role, 'perms', m.perms, 'email', u.email)
      order by (m.role = 'owner') desc, u.email)
    from public.memberships m join auth.users u on u.id = m.user_id
    where m.company_id = p_company), '[]'::json);
end $$;

create or replace function public.update_member_perms(p_company uuid, p_user uuid, p_perms jsonb) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_owner(p_company) then raise exception 'not_owner'; end if;
  if exists (select 1 from public.memberships where company_id = p_company and user_id = p_user and role = 'owner') then
    raise exception 'cannot_edit_owner';
  end if;
  update public.memberships set perms = coalesce(p_perms, '{}'::jsonb)
   where company_id = p_company and user_id = p_user;
end $$;

create or replace function public.remove_member(p_company uuid, p_user uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_owner(p_company) then raise exception 'not_owner'; end if;
  if exists (select 1 from public.memberships where company_id = p_company and user_id = p_user and role = 'owner') then
    raise exception 'cannot_edit_owner';
  end if;
  delete from public.memberships where company_id = p_company and user_id = p_user;
end $$;

-- Les profils 100 % lecture sont aussi bloqués CÔTÉ SERVEUR
create or replace function public.save_data(p_company uuid, p_data jsonb, p_version bigint) returns bigint
language plpgsql security definer set search_path = public as $$
declare e timestamptz; v bigint; pm jsonb;
begin
  if not public.is_member(p_company) then raise exception 'not_member'; end if;
  select perms into pm from public.memberships where company_id = p_company and user_id = auth.uid();
  if coalesce(pm->>'w', '1') = '0' then raise exception 'read_only_profile'; end if;
  select license_expiry into e from public.companies where id = p_company;
  if e is null or e < now() then raise exception 'license_expired'; end if;
  update public.company_data set data = p_data, version = version + 1, updated_at = now()
   where company_id = p_company and version = p_version
   returning version into v;
  if v is null then raise exception 'version_conflict'; end if;
  return v;
end $$;

revoke all on function public.is_owner(uuid) from public, anon;
revoke all on function public.create_invitation(uuid, jsonb) from public, anon;
revoke all on function public.join_with_code(text) from public, anon;
revoke all on function public.list_members(uuid) from public, anon;
revoke all on function public.update_member_perms(uuid, uuid, jsonb) from public, anon;
revoke all on function public.remove_member(uuid, uuid) from public, anon;
grant execute on function public.is_owner(uuid) to authenticated;
grant execute on function public.create_invitation(uuid, jsonb) to authenticated;
grant execute on function public.join_with_code(text) to authenticated;
grant execute on function public.list_members(uuid) to authenticated;
grant execute on function public.update_member_perms(uuid, uuid, jsonb) to authenticated;
grant execute on function public.remove_member(uuid, uuid) to authenticated;
-- Fin de la migration v2.5
