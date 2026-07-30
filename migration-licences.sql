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
