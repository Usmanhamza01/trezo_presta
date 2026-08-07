-- ============================================================
-- TREZO BUSINESS — Édition par entreprise + navigation inter-espaces
-- À exécuter UNE FOIS dans Supabase (SQL Editor).
-- Prérequis : migration-multi-entreprises.sql déjà appliquée.
-- ============================================================

-- 1) Chaque entreprise appartient à une édition : 'commerce' ou 'services'
alter table public.companies
  add column if not exists edition text not null default 'commerce'
  check (edition in ('commerce','services'));

-- 2) (Optionnel) marquer les entreprises existantes.
--    Par défaut tout est 'commerce'. Pour passer une entreprise en Services :
--    update public.companies set edition='services' where id='...';

-- 3) Fonction : lister les espaces (entreprises) du compte connecté,
--    avec leur édition, pour alimenter le sélecteur BUSINESS.
create or replace function public.my_spaces() returns json
language sql security definer set search_path = public as $$
  select coalesce(json_agg(json_build_object(
      'company_id', c.id,
      'name',       c.name,
      'edition',    c.edition,
      'role',       m.role
    ) order by c.edition, c.name), '[]'::json)
  from public.memberships m
  join public.companies c on c.id = m.company_id
  where m.user_id = auth.uid();
$$;

grant execute on function public.my_spaces() to authenticated;

-- ============================================================
-- Le compte BUSINESS = un utilisateur membre d'au moins une
-- entreprise 'commerce' ET une entreprise 'services'.
-- L'authentification Supabase est partagée entre les deux apps
-- (même projet), donc la bascule se fait sans reconnexion (SSO).
-- ============================================================
