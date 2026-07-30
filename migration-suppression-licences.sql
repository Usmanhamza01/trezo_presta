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
