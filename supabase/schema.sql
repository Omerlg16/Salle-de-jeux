-- Salle de jeux : structure de la base Supabase
-- À coller une seule fois dans Supabase > SQL Editor > New query, puis "Run".

-- ===== Comptes et rôles =====
create table public.profils (
  id uuid primary key references auth.users(id) on delete cascade,
  nom text not null,
  role text not null check (role in ('admin','patron','gerant')),
  actif boolean not null default true
);

create or replace function public.mon_role() returns text
language sql stable security definer set search_path = public as $$
  select role from public.profils where id = auth.uid() and actif
$$;

-- ===== Référentiel =====
create table public.salles (id uuid primary key default gen_random_uuid(), nom text not null);
create table public.postes (
  id uuid primary key default gen_random_uuid(),
  salle_id uuid not null references public.salles(id),
  nom text not null,
  console text not null,
  etat text not null default 'ok' check (etat in ('ok','panne'))
);
create table public.forfaits (
  id uuid primary key default gen_random_uuid(),
  console text not null, jeu text not null, libelle text not null,
  minutes int not null check (minutes > 0),
  prix int not null check (prix >= 0),
  actif boolean not null default true
);
create table public.charges (
  id uuid primary key default gen_random_uuid(),
  libelle text not null, montant numeric not null, devise text not null check (devise in ('FC','USD'))
);
create table public.reglages (id int primary key default 1 check (id = 1), taux_usd numeric not null default 2800);

-- ===== Mouvements (jamais effacés) =====
create table public.parties (
  id uuid primary key default gen_random_uuid(),
  poste_id uuid not null references public.postes(id),
  forfait_id uuid not null references public.forfaits(id),
  prix int not null,
  debut timestamptz not null default now(),
  fin timestamptz,
  par uuid not null default auth.uid() references public.profils(id),
  demande_annulation text,
  annulee boolean not null default false,
  refusee boolean not null default false,
  cree_le timestamptz not null default now()
);
create table public.depenses (
  id uuid primary key default gen_random_uuid(),
  libelle text not null, montant numeric not null check (montant > 0),
  devise text not null default 'FC' check (devise in ('FC','USD')),
  de_la_caisse boolean not null default true,
  le timestamptz not null default now(),
  par uuid not null default auth.uid() references public.profils(id),
  annulee boolean not null default false
);
create table public.caisses (
  id uuid primary key default gen_random_uuid(),
  jour date not null unique,
  declare int not null check (declare >= 0),
  le timestamptz not null default now(),
  par uuid not null default auth.uid() references public.profils(id)
);
create table public.dettes (
  id uuid primary key default gen_random_uuid(),
  proprietaire uuid not null references public.profils(id),
  type text not null check (type in ('emprunt','remboursement','depart')),
  montant int not null check (montant > 0),
  de_la_caisse boolean not null default false,
  le timestamptz not null default now(),
  par uuid not null default auth.uid() references public.profils(id)
);

-- Le prix d'une partie vient toujours du forfait, jamais de la saisie
create or replace function public.prix_du_forfait() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    select prix into new.prix from public.forfaits where id = new.forfait_id;
    new.debut := now(); new.cree_le := now(); new.par := auth.uid();
  elsif public.mon_role() = 'gerant' then
    -- le gérant ne peut que terminer une partie ou demander son annulation
    if new.prix <> old.prix or new.debut <> old.debut or new.poste_id <> old.poste_id
       or new.forfait_id <> old.forfait_id or new.annulee <> old.annulee or new.refusee <> old.refusee then
      raise exception 'Modification non autorisée';
    end if;
    if old.fin is not null and new.fin is distinct from old.fin then raise exception 'Partie déjà terminée'; end if;
    if new.fin is not null and old.fin is null then new.fin := now(); end if;
  end if;
  return new;
end $$;
create trigger parties_prix before insert or update on public.parties
  for each row execute function public.prix_du_forfait();

-- ===== Sécurité : qui voit et fait quoi =====
alter table public.profils enable row level security;
alter table public.salles enable row level security;
alter table public.postes enable row level security;
alter table public.forfaits enable row level security;
alter table public.charges enable row level security;
alter table public.reglages enable row level security;
alter table public.parties enable row level security;
alter table public.depenses enable row level security;
alter table public.caisses enable row level security;
alter table public.dettes enable row level security;

-- Lecture du référentiel : tous les comptes actifs
create policy lire on public.profils  for select using (public.mon_role() is not null);
create policy lire on public.salles   for select using (public.mon_role() is not null);
create policy lire on public.postes   for select using (public.mon_role() is not null);
create policy lire on public.forfaits for select using (public.mon_role() is not null);
create policy lire on public.charges  for select using (public.mon_role() is not null);
create policy lire on public.reglages for select using (public.mon_role() is not null);

-- Réglages : super utilisateur seulement
create policy admin on public.profils  for all using (public.mon_role() = 'admin') with check (public.mon_role() = 'admin');
create policy admin on public.salles   for all using (public.mon_role() = 'admin') with check (public.mon_role() = 'admin');
create policy admin on public.postes   for all using (public.mon_role() = 'admin') with check (public.mon_role() = 'admin');
create policy admin on public.forfaits for all using (public.mon_role() = 'admin') with check (public.mon_role() = 'admin');
create policy admin on public.charges  for all using (public.mon_role() = 'admin') with check (public.mon_role() = 'admin');
create policy admin on public.reglages for all using (public.mon_role() = 'admin') with check (public.mon_role() = 'admin');

-- Parties : le gérant voit celles du jour, patrons et admin voient tout
create policy lire on public.parties for select using (
  public.mon_role() in ('admin','patron') or (public.mon_role() = 'gerant' and debut >= current_date));
create policy creer on public.parties for insert with check (public.mon_role() in ('admin','gerant'));
create policy modifier on public.parties for update using (
  public.mon_role() = 'admin' or (public.mon_role() = 'gerant' and debut >= current_date));

-- Dépenses : tout le monde saisit, le gérant ne voit que les siennes
create policy lire on public.depenses for select using (public.mon_role() in ('admin','patron') or par = auth.uid());
create policy creer on public.depenses for insert with check (public.mon_role() is not null);
create policy admin on public.depenses for update using (public.mon_role() = 'admin');

-- Caisse : le gérant déclare une fois par jour, sans voir l'attendu
create policy lire on public.caisses for select using (public.mon_role() in ('admin','patron') or par = auth.uid());
create policy creer on public.caisses for insert with check (public.mon_role() in ('admin','gerant'));
create policy admin on public.caisses for update using (public.mon_role() = 'admin');

-- Dettes : patrons et admin
create policy lire on public.dettes for select using (public.mon_role() in ('admin','patron'));
create policy creer on public.dettes for insert with check (public.mon_role() in ('admin','patron'));
create policy admin on public.dettes for update using (public.mon_role() = 'admin');

-- Personne ne supprime un mouvement : aucune policy "delete" sur parties, depenses, caisses, dettes.

-- Temps réel pour l'écran "En direct"
alter publication supabase_realtime add table public.parties, public.depenses, public.caisses, public.postes;

-- ===== Données de départ =====
insert into public.reglages (id, taux_usd) values (1, 2800);
insert into public.charges (libelle, montant, devise) values ('Loyer', 90, 'USD'), ('Électricité', 7000, 'FC');
with s as (insert into public.salles (nom) values ('Salle 1') returning id)
insert into public.postes (salle_id, nom, console, etat)
select s.id, p.nom, p.console, p.etat from s, (values
  ('PS4 n°1','PS4','ok'),('PS4 n°2','PS4','ok'),('PS3 n°1','PS3','ok'),('PS3 n°2','PS3','panne')) as p(nom,console,etat);
insert into public.forfaits (console, jeu, libelle, minutes, prix) values
  ('PS4','Foot (FC)','1 match',3,500),('PS4','Foot (FC)','2 matchs',6,1000),('PS4','Foot (FC)','3 matchs',9,1500),
  ('PS4','GTA 5','20 minutes',20,1000),('PS4','GTA 5','1 heure',60,3000),
  ('PS3','Foot (PES)','2 matchs',16,500),('PS3','Foot (PES)','4 matchs',32,1000),
  ('PS3','GTA 5','15 minutes',15,500),('PS3','GTA 5','30 minutes',30,1000);
