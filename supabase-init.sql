-- ============================================================
-- TREZO CLOUD — Script d'initialisation Supabase (v1)
-- À exécuter UNE FOIS dans : Supabase → SQL Editor → Run
-- ============================================================

create extension if not exists pgcrypto with schema extensions;
create extension if not exists unaccent with schema extensions;

-- Schéma privé : le secret des licences vit ici, inaccessible aux clients
create schema if not exists private;
revoke usage on schema private from public, anon, authenticated;

-- ------------------------------------------------------------
-- Tables
-- ------------------------------------------------------------
create table public.companies (
  id             uuid primary key default gen_random_uuid(),
  name           text not null,
  currency       text not null default 'XOF',
  symbol         text not null default 'FCFA',
  license_key    text,
  license_expiry timestamptz,
  is_trial       boolean not null default false,
  created_at     timestamptz not null default now()
);

create table public.memberships (
  user_id    uuid not null references auth.users(id) on delete cascade,
  company_id uuid not null references public.companies(id) on delete cascade,
  role       text not null default 'owner',
  primary key (user_id, company_id)
);

create table public.company_data (
  company_id uuid primary key references public.companies(id) on delete cascade,
  data       jsonb not null default '{}'::jsonb,
  version    bigint not null default 1,
  updated_at timestamptz not null default now()
);

-- ------------------------------------------------------------
-- Sécurité : RLS + droits
-- ------------------------------------------------------------
alter table public.companies    enable row level security;
alter table public.memberships  enable row level security;
alter table public.company_data enable row level security;

create or replace function public.is_member(cid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.memberships
                 where company_id = cid and user_id = auth.uid());
$$;

create policy mem_select on public.memberships
  for select using (user_id = auth.uid());
create policy co_select on public.companies
  for select using (public.is_member(id));
create policy co_update on public.companies
  for update using (public.is_member(id)) with check (public.is_member(id));
create policy cd_select on public.company_data
  for select using (public.is_member(company_id));
-- (aucune policy d'insertion/suppression : tout passe par les fonctions RPC)

revoke all on public.companies, public.memberships, public.company_data
  from anon, authenticated;
grant select on public.companies, public.memberships, public.company_data
  to authenticated;
grant update (name, currency, symbol) on public.companies to authenticated;

-- Verrou supplémentaire : les colonnes de licence ne sont modifiables
-- que par les fonctions serveur (double protection avec le grant ci-dessus)
create or replace function public.protect_license() returns trigger
language plpgsql as $$
begin
  if coalesce(current_setting('app.lic', true), '') = '1' then return new; end if;
  if new.license_key    is distinct from old.license_key
  or new.license_expiry is distinct from old.license_expiry
  or new.is_trial       is distinct from old.is_trial then
    raise exception 'license_protected';
  end if;
  return new;
end $$;
create trigger trg_protect_license
  before update on public.companies
  for each row execute function public.protect_license();

-- ------------------------------------------------------------
-- Vérification des clés TRZO (côté serveur — le secret est ICI)
-- ------------------------------------------------------------
create or replace function private.b36(t text) returns bigint
language plpgsql immutable as $$
declare r bigint := 0; d int; i int;
begin
  t := upper(t);
  for i in 1..length(t) loop
    d := position(substr(t, i, 1) in '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ') - 1;
    if d < 0 then return null; end if;
    r := r * 36 + d;
  end loop;
  return r;
end $$;

create or replace function private.check_key(p_name text, p_key text) returns timestamptz
language plpgsql stable security definer
set search_path = public, private, extensions as $$
declare
  secret text := 'TREZO-K7#2026';
  k text; m text[]; ymd text; d date;
  n1 text; n2 text; h1 text; h2 text;
begin
  k := upper(trim(coalesce(p_key, '')));
  m := regexp_match(k, '^TRZO-([0-9A-Z]{1,8})-([0-9A-F]{4})-([0-9A-F]{4})$');
  if m is null then return null; end if;
  ymd := lpad(private.b36(m[1])::text, 8, '0');
  if length(ymd) <> 8 then return null; end if;
  -- deux normalisations tolérées (accents translittérés ou supprimés)
  n1 := regexp_replace(upper(unaccent(p_name)), '[^A-Z0-9]', '', 'g');
  n2 := regexp_replace(upper(p_name), '[^A-Z0-9]', '', 'g');
  h1 := upper(encode(digest(secret || '|' || n1 || '|' || ymd, 'sha256'), 'hex'));
  h2 := upper(encode(digest(secret || '|' || n2 || '|' || ymd, 'sha256'), 'hex'));
  if not ((substr(h1,1,4) = m[2] and substr(h1,5,4) = m[3])
       or (substr(h2,1,4) = m[2] and substr(h2,5,4) = m[3])) then
    return null;
  end if;
  begin d := to_date(ymd, 'YYYYMMDD'); exception when others then return null; end;
  return (d::timestamp + interval '23 hours 59 minutes 59 seconds')::timestamptz;
end $$;

revoke all on function private.b36(text) from public, anon, authenticated;
revoke all on function private.check_key(text, text) from public, anon, authenticated;

-- ------------------------------------------------------------
-- Fonctions applicatives (RPC)
-- ------------------------------------------------------------
create or replace function public.create_company_with_license(
  p_name text, p_currency text, p_symbol text, p_key text) returns json
language plpgsql security definer set search_path = public, private, extensions as $$
declare exp timestamptz; c public.companies;
begin
  if auth.uid() is null then raise exception 'auth_required'; end if;
  if exists (select 1 from public.memberships where user_id = auth.uid()) then
    raise exception 'already_has_company';
  end if;
  exp := private.check_key(p_name, p_key);
  if exp is null then raise exception 'invalid_key'; end if;
  if exp < now() then raise exception 'expired_key'; end if;
  insert into public.companies (name, currency, symbol, license_key, license_expiry, is_trial)
    values (trim(p_name), p_currency, p_symbol, upper(trim(p_key)), exp, false)
    returning * into c;
  insert into public.memberships (user_id, company_id, role) values (auth.uid(), c.id, 'owner');
  insert into public.company_data (company_id) values (c.id);
  return row_to_json(c);
end $$;

create or replace function public.start_trial(
  p_name text, p_currency text, p_symbol text) returns json
language plpgsql security definer set search_path = public, private, extensions as $$
declare c public.companies;
begin
  if auth.uid() is null then raise exception 'auth_required'; end if;
  if exists (select 1 from public.memberships where user_id = auth.uid()) then
    raise exception 'already_has_company';
  end if;
  insert into public.companies (name, currency, symbol, license_key, license_expiry, is_trial)
    values (trim(p_name), p_currency, p_symbol, 'ESSAI', now() + interval '14 days', true)
    returning * into c;
  insert into public.memberships (user_id, company_id, role) values (auth.uid(), c.id, 'owner');
  insert into public.company_data (company_id) values (c.id);
  return row_to_json(c);
end $$;

create or replace function public.renew_license(p_company uuid, p_key text) returns timestamptz
language plpgsql security definer set search_path = public, private, extensions as $$
declare exp timestamptz; n text;
begin
  if not public.is_member(p_company) then raise exception 'not_member'; end if;
  select name into n from public.companies where id = p_company;
  exp := private.check_key(n, p_key);
  if exp is null then raise exception 'invalid_key'; end if;
  if exp < now() then raise exception 'expired_key'; end if;
  perform set_config('app.lic', '1', true);
  update public.companies
     set license_key = upper(trim(p_key)), license_expiry = exp, is_trial = false
   where id = p_company;
  return exp;
end $$;

create or replace function public.save_data(
  p_company uuid, p_data jsonb, p_version bigint) returns bigint
language plpgsql security definer set search_path = public as $$
declare e timestamptz; v bigint;
begin
  if not public.is_member(p_company) then raise exception 'not_member'; end if;
  select license_expiry into e from public.companies where id = p_company;
  if e is null or e < now() then raise exception 'license_expired'; end if;
  update public.company_data
     set data = p_data, version = version + 1, updated_at = now()
   where company_id = p_company and version = p_version
   returning version into v;
  if v is null then raise exception 'version_conflict'; end if;
  return v;
end $$;

revoke all on function public.create_company_with_license(text,text,text,text) from public, anon;
revoke all on function public.start_trial(text,text,text) from public, anon;
revoke all on function public.renew_license(uuid,text) from public, anon;
revoke all on function public.save_data(uuid,jsonb,bigint) from public, anon;
grant execute on function public.create_company_with_license(text,text,text,text) to authenticated;
grant execute on function public.start_trial(text,text,text) to authenticated;
grant execute on function public.renew_license(uuid,text) to authenticated;
grant execute on function public.save_data(uuid,jsonb,bigint) to authenticated;
grant execute on function public.is_member(uuid) to authenticated;

-- Fin. Vérifiez qu'aucune erreur n'apparaît ci-dessus.
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
-- ============================================================
-- TREZO v2.8 — Création directe des comptes collaborateurs
-- À exécuter UNE FOIS dans Supabase → SQL Editor → Run
-- (après migration-multi-utilisateurs.sql ; sans danger)
-- ============================================================

alter table public.memberships add column if not exists display_name text not null default '';

-- L'admin crée le compte depuis l'application, puis cette fonction
-- rattache le collaborateur à l'entreprise avec ses droits.
create or replace function public.admin_add_member(p_company uuid, p_email text, p_name text, p_perms jsonb) returns void
language plpgsql security definer set search_path = public as $$
declare v_uid uuid;
begin
  if not public.is_owner(p_company) then raise exception 'not_owner'; end if;
  select id into v_uid from auth.users where lower(email) = lower(trim(p_email)) limit 1;
  if v_uid is null then raise exception 'user_not_found'; end if;
  if exists (select 1 from public.memberships where user_id = v_uid) then
    raise exception 'already_has_company';
  end if;
  insert into public.memberships(user_id, company_id, role, perms, display_name)
    values (v_uid, p_company, 'user', coalesce(p_perms,'{}'::jsonb), coalesce(trim(p_name),''));
end $$;
revoke all on function public.admin_add_member(uuid, text, text, jsonb) from public, anon;
grant execute on function public.admin_add_member(uuid, text, text, jsonb) to authenticated;

-- list_members renvoie désormais aussi le nom du collaborateur
create or replace function public.list_members(p_company uuid) returns json
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_owner(p_company) then raise exception 'not_owner'; end if;
  return coalesce((
    select json_agg(json_build_object(
      'user_id', m.user_id, 'role', m.role, 'perms', m.perms,
      'email', u.email, 'display_name', m.display_name)
      order by (m.role = 'owner') desc, u.email)
    from public.memberships m join auth.users u on u.id = m.user_id
    where m.company_id = p_company), '[]'::json);
end $$;
-- Fin de la migration v2.8
-- ============================================================
-- TREZO — Système central de gestion des licences (registre partagé)
-- À exécuter UNE FOIS dans Supabase → SQL Editor → Run
-- Puis : renseignez vos e-mails dans le bloc "GESTIONNAIRES" tout en bas.
-- ============================================================

create table if not exists public.licenses (
  id           uuid primary key default gen_random_uuid(),
  key          text unique not null,
  company_name text not null,
  client_name  text not null default '',
  phone        text not null default '',
  type         text not null default 'cloud' check (type in ('cloud','classique')),
  months       int  not null default 12,
  expiry       timestamptz not null,
  suspended    boolean not null default false,
  activated_at timestamptz,
  created_by   text not null default '',
  created_at   timestamptz not null default now()
);
create table if not exists public.license_events (
  id         bigserial primary key,
  license_id uuid not null references public.licenses(id) on delete cascade,
  action     text not null,
  detail     text not null default '',
  by_email   text not null default '',
  at         timestamptz not null default now()
);
create table if not exists public.license_admins (
  user_id uuid primary key,
  email   text not null default ''
);
alter table public.licenses       enable row level security;
alter table public.license_events enable row level security;
alter table public.license_admins enable row level security;

create or replace function public.is_licenser() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.license_admins where user_id = auth.uid());
$$;
revoke all on function public.is_licenser() from public, anon;
grant execute on function public.is_licenser() to authenticated;

drop policy if exists lic_all on public.licenses;
create policy lic_all on public.licenses for all to authenticated
  using (public.is_licenser()) with check (public.is_licenser());
drop policy if exists lev_all on public.license_events;
create policy lev_all on public.license_events for all to authenticated
  using (public.is_licenser()) with check (public.is_licenser());
drop policy if exists la_sel on public.license_admins;
create policy la_sel on public.license_admins for select to authenticated
  using (user_id = auth.uid());
grant select, insert, update on public.licenses to authenticated;
grant select, insert on public.license_events to authenticated;
grant select on public.license_admins to authenticated;
grant usage on sequence public.license_events_id_seq to authenticated;

-- Drapeau de suspension sur les entreprises Cloud
alter table public.companies add column if not exists suspended boolean not null default false;

-- Le gestionnaire agit sur une entreprise Cloud par son nom (suspension / échéance)
create or replace function public.licenser_set_cloud(p_name text, p_susp boolean, p_expiry timestamptz) returns int
language plpgsql security definer set search_path = public, extensions as $$
declare n int;
begin
  if not public.is_licenser() then raise exception 'not_licenser'; end if;
  update public.companies
     set suspended = coalesce(p_susp, suspended),
         license_expiry = coalesce(p_expiry, license_expiry)
   where regexp_replace(upper(unaccent(name)), '[^A-Z0-9]', '', 'g')
       = regexp_replace(upper(unaccent(coalesce(p_name,''))), '[^A-Z0-9]', '', 'g');
  get diagnostics n = row_count;
  return n;
end $$;
revoke all on function public.licenser_set_cloud(text, boolean, timestamptz) from public, anon;
grant execute on function public.licenser_set_cloud(text, boolean, timestamptz) to authenticated;

-- Vérification en ligne pour Trezo Classique (anonyme : statut uniquement)
create or replace function public.license_check(p_name text) returns text
language plpgsql stable security definer set search_path = public, extensions as $$
declare susp boolean;
begin
  select bool_or(suspended) into susp from public.licenses
   where type = 'classique'
     and regexp_replace(upper(unaccent(company_name)), '[^A-Z0-9]', '', 'g')
       = regexp_replace(upper(unaccent(coalesce(p_name,''))), '[^A-Z0-9]', '', 'g');
  if susp is null then return 'unknown'; end if;
  return case when susp then 'suspended' else 'ok' end;
end $$;
grant execute on function public.license_check(text) to anon, authenticated;

-- save_data : bloque expiration, lecture seule ET suspension
create or replace function public.save_data(p_company uuid, p_data jsonb, p_version bigint) returns bigint
language plpgsql security definer set search_path = public as $$
declare e timestamptz; v bigint; pm jsonb; sp boolean;
begin
  if not public.is_member(p_company) then raise exception 'not_member'; end if;
  select perms into pm from public.memberships where company_id = p_company and user_id = auth.uid();
  if coalesce(pm->>'w','1') = '0' then raise exception 'read_only_profile'; end if;
  select license_expiry, suspended into e, sp from public.companies where id = p_company;
  if coalesce(sp, false) then raise exception 'suspended'; end if;
  if e is null or e < now() then raise exception 'license_expired'; end if;
  update public.company_data set data = p_data, version = version + 1, updated_at = now()
   where company_id = p_company and version = p_version
   returning version into v;
  if v is null then raise exception 'version_conflict'; end if;
  return v;
end $$;

-- Activation automatique du registre quand une clé Cloud est utilisée
create or replace function public.create_company_with_license(
  p_name text, p_currency text, p_symbol text, p_key text) returns json
language plpgsql security definer set search_path = public, private, extensions as $$
declare exp timestamptz; c public.companies;
begin
  if auth.uid() is null then raise exception 'auth_required'; end if;
  if exists (select 1 from public.memberships where user_id = auth.uid()) then
    raise exception 'already_has_company';
  end if;
  if exists (select 1 from public.licenses where key = upper(trim(p_key)) and suspended) then
    raise exception 'suspended';
  end if;
  exp := private.check_key(p_name, p_key);
  if exp is null then raise exception 'invalid_key'; end if;
  if exp < now() then raise exception 'expired_key'; end if;
  insert into public.companies (name, currency, symbol, license_key, license_expiry, is_trial)
    values (trim(p_name), p_currency, p_symbol, upper(trim(p_key)), exp, false)
    returning * into c;
  insert into public.memberships (user_id, company_id, role) values (auth.uid(), c.id, 'owner');
  insert into public.company_data (company_id) values (c.id);
  update public.licenses set activated_at = coalesce(activated_at, now()) where key = upper(trim(p_key));
  return row_to_json(c);
end $$;

create or replace function public.renew_license(p_company uuid, p_key text) returns timestamptz
language plpgsql security definer set search_path = public, private, extensions as $$
declare exp timestamptz; n text;
begin
  if not public.is_member(p_company) then raise exception 'not_member'; end if;
  if exists (select 1 from public.licenses where key = upper(trim(p_key)) and suspended) then
    raise exception 'suspended';
  end if;
  select name into n from public.companies where id = p_company;
  exp := private.check_key(n, p_key);
  if exp is null then raise exception 'invalid_key'; end if;
  if exp < now() then raise exception 'expired_key'; end if;
  perform set_config('app.lic', '1', true);
  update public.companies
     set license_key = upper(trim(p_key)), license_expiry = exp, is_trial = false
   where id = p_company;
  update public.licenses set activated_at = coalesce(activated_at, now()) where key = upper(trim(p_key));
  return exp;
end $$;

-- ============================================================
-- GESTIONNAIRES DE LICENCES (vous + votre partenaire)
-- 1) Créez d'abord vos deux comptes (page de connexion du générateur).
-- 2) Remplacez les e-mails ci-dessous par les vôtres, puis exécutez :
-- ============================================================
insert into public.license_admins (user_id, email)
select id, email from auth.users
 where lower(email) in (lower('VOTRE-EMAIL@exemple.com'), lower('EMAIL-PARTENAIRE@exemple.com'))
on conflict (user_id) do nothing;
-- Fin de la migration licences
-- ============================================================
-- TREZO — Un même compte peut appartenir à PLUSIEURS entreprises
-- (comptable multi-sociétés). À exécuter UNE FOIS dans Supabase.
-- ============================================================

create or replace function public.admin_add_member(p_company uuid, p_email text, p_name text, p_perms jsonb) returns void
language plpgsql security definer set search_path = public as $$
declare v_uid uuid;
begin
  if not public.is_owner(p_company) then raise exception 'not_owner'; end if;
  select id into v_uid from auth.users where lower(email) = lower(trim(p_email)) limit 1;
  if v_uid is null then raise exception 'user_not_found'; end if;
  if exists (select 1 from public.memberships where user_id = v_uid and company_id = p_company) then
    raise exception 'already_member';
  end if;
  insert into public.memberships(user_id, company_id, role, perms, display_name)
    values (v_uid, p_company, 'user', coalesce(p_perms,'{}'::jsonb), coalesce(trim(p_name),''));
end $$;

create or replace function public.join_with_code(p_code text) returns json
language plpgsql security definer set search_path = public as $$
declare inv public.invitations; c public.companies;
begin
  if auth.uid() is null then raise exception 'auth_required'; end if;
  select * into inv from public.invitations
   where code = upper(trim(p_code)) and used_by is null
     and created_at > now() - interval '30 days';
  if inv.code is null then raise exception 'invalid_code'; end if;
  if exists (select 1 from public.memberships where user_id = auth.uid() and company_id = inv.company_id) then
    raise exception 'already_member';
  end if;
  insert into public.memberships(user_id, company_id, role, perms)
    values (auth.uid(), inv.company_id, 'user', inv.perms);
  update public.invitations set used_by = auth.uid(), used_at = now() where code = inv.code;
  select * into c from public.companies where id = inv.company_id;
  return row_to_json(c);
end $$;
-- Fin de la migration multi-entreprises
-- ============================================================
-- TREZO — Suppression définitive des licences (liste noire)
-- À exécuter UNE FOIS dans Supabase → SQL Editor → Run
-- ============================================================
alter table public.licenses add column if not exists deleted boolean not null default false;
alter table public.licenses add column if not exists deleted_at timestamptz;
alter table public.licenses add column if not exists deleted_by text not null default '';

-- Une clé supprimée ne peut plus JAMAIS activer ni renouveler
create or replace function public.create_company_with_license(
  p_name text, p_currency text, p_symbol text, p_key text) returns json
language plpgsql security definer set search_path = public, private, extensions as $$
declare exp timestamptz; c public.companies;
begin
  if auth.uid() is null then raise exception 'auth_required'; end if;
  if exists (select 1 from public.memberships where user_id = auth.uid()) then
    raise exception 'already_has_company';
  end if;
  if exists (select 1 from public.licenses where key = upper(trim(p_key)) and deleted) then
    raise exception 'revoked_key';
  end if;
  if exists (select 1 from public.licenses where key = upper(trim(p_key)) and suspended) then
    raise exception 'suspended';
  end if;
  exp := private.check_key(p_name, p_key);
  if exp is null then raise exception 'invalid_key'; end if;
  if exp < now() then raise exception 'expired_key'; end if;
  insert into public.companies (name, currency, symbol, license_key, license_expiry, is_trial)
    values (trim(p_name), p_currency, p_symbol, upper(trim(p_key)), exp, false)
    returning * into c;
  insert into public.memberships (user_id, company_id, role) values (auth.uid(), c.id, 'owner');
  insert into public.company_data (company_id) values (c.id);
  update public.licenses set activated_at = coalesce(activated_at, now()) where key = upper(trim(p_key));
  return row_to_json(c);
end $$;

create or replace function public.renew_license(p_company uuid, p_key text) returns timestamptz
language plpgsql security definer set search_path = public, private, extensions as $$
declare exp timestamptz; n text;
begin
  if not public.is_member(p_company) then raise exception 'not_member'; end if;
  if exists (select 1 from public.licenses where key = upper(trim(p_key)) and deleted) then
    raise exception 'revoked_key';
  end if;
  if exists (select 1 from public.licenses where key = upper(trim(p_key)) and suspended) then
    raise exception 'suspended';
  end if;
  select name into n from public.companies where id = p_company;
  exp := private.check_key(n, p_key);
  if exp is null then raise exception 'invalid_key'; end if;
  if exp < now() then raise exception 'expired_key'; end if;
  perform set_config('app.lic', '1', true);
  update public.companies
     set license_key = upper(trim(p_key)), license_expiry = exp, is_trial = false
   where id = p_company;
  update public.licenses set activated_at = coalesce(activated_at, now()) where key = upper(trim(p_key));
  return exp;
end $$;

-- La vérification en ligne de Classique bloque aussi les licences supprimées
create or replace function public.license_check(p_name text) returns text
language plpgsql stable security definer set search_path = public, extensions as $$
declare susp boolean;
begin
  select bool_or(suspended or deleted) into susp from public.licenses
   where type = 'classique'
     and regexp_replace(upper(unaccent(company_name)), '[^A-Z0-9]', '', 'g')
       = regexp_replace(upper(unaccent(coalesce(p_name,''))), '[^A-Z0-9]', '', 'g');
  if susp is null then return 'unknown'; end if;
  return case when susp then 'suspended' else 'ok' end;
end $$;
-- Fin de la migration suppression
