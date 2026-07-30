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
