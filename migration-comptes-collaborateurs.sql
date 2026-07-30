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
