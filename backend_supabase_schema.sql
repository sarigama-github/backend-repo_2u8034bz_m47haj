-- Supabase schema for Dr. Bur Dental Clinic
-- Enable necessary extensions
create extension if not exists pgcrypto;

-- Profiles table mirrors auth.users with role and attributes
create table if not exists public.user_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  avatar_url text,
  role text not null default 'patient' check (role in ('patient','doctor','admin')),
  phone text,
  gender text,
  theme text not null default 'light',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.emergency_contacts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  name text,
  phone text,
  relation text,
  created_at timestamptz not null default now()
);

create table if not exists public.medical_history (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  allergies text,
  medications text,
  previous_treatments text,
  pain_level text,
  chronic_illnesses text,
  smoking_alcohol text,
  emergency_contact text,
  notes text,
  created_at timestamptz not null default now()
);

create table if not exists public.doctor_patient_links (
  id uuid primary key default gen_random_uuid(),
  doctor_id uuid not null references auth.users(id) on delete cascade,
  patient_id uuid not null references auth.users(id) on delete cascade,
  approved boolean not null default false,
  created_at timestamptz not null default now(),
  unique(doctor_id, patient_id)
);

create table if not exists public.appointments (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid not null references auth.users(id) on delete cascade,
  doctor_id uuid not null references auth.users(id) on delete cascade,
  purpose text,
  starts_at timestamptz not null,
  status text not null default 'pending' check (status in ('pending','approved','declined','cancelled')),
  is_new_patient boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.products (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text,
  price numeric(10,2) not null default 0,
  featured boolean not null default false,
  image_url text,
  stock integer not null default 0,
  category text,
  created_at timestamptz not null default now()
);

create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  items jsonb not null,
  total numeric(10,2) not null,
  status text not null default 'pending' check (status in ('pending','paid','failed','cancelled')),
  created_at timestamptz not null default now()
);

create table if not exists public.chat_messages (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid not null references auth.users(id) on delete cascade,
  recipient_id uuid not null references auth.users(id) on delete cascade,
  appointment_id uuid references public.appointments(id) on delete set null,
  content text not null,
  seen_at timestamptz,
  created_at timestamptz not null default now()
);

-- Enable RLS
alter table public.user_profiles enable row level security;
alter table public.emergency_contacts enable row level security;
alter table public.medical_history enable row level security;
alter table public.doctor_patient_links enable row level security;
alter table public.appointments enable row level security;
alter table public.products enable row level security;
alter table public.orders enable row level security;
alter table public.chat_messages enable row level security;

-- Helper: check if current user is admin/doctor
create or replace view public.current_user_role as
  select p.id, p.role from public.user_profiles p where p.id = auth.uid();

-- user_profiles policies
create policy "profiles_insert_own" on public.user_profiles
  for insert with check (id = auth.uid());
create policy "profiles_select_self" on public.user_profiles
  for select using (id = auth.uid());
create policy "profiles_update_self" on public.user_profiles
  for update using (id = auth.uid());
create policy "profiles_admin_all" on public.user_profiles
  for all using (exists(select 1 from public.user_profiles p where p.id = auth.uid() and p.role = 'admin'));

-- emergency_contacts: owner or admin
create policy "ec_owner_rw" on public.emergency_contacts
  for all using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "ec_admin_all" on public.emergency_contacts
  for all using (exists(select 1 from public.user_profiles p where p.id = auth.uid() and p.role='admin'));

-- medical_history: owner rw, doctor/admin read
create policy "mh_owner_rw" on public.medical_history
  for all using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "mh_doctor_read" on public.medical_history
  for select using (
    exists(select 1 from public.user_profiles p where p.id = auth.uid() and p.role in ('doctor','admin'))
  );

-- doctor_patient_links: doctors/admin manage, patients can read their approvals
create policy "dpl_doctor_admin_all" on public.doctor_patient_links
  for all using (
    exists(select 1 from public.user_profiles p where p.id = auth.uid() and p.role in ('doctor','admin'))
  );
create policy "dpl_patient_read" on public.doctor_patient_links
  for select using (patient_id = auth.uid());

-- appointments: patient owns, doctor involved, admin all
create policy "appt_patient_rw" on public.appointments
  for all using (patient_id = auth.uid()) with check (patient_id = auth.uid());
create policy "appt_doctor_read_write" on public.appointments
  for all using (doctor_id = auth.uid()) with check (doctor_id = auth.uid());
create policy "appt_admin_all" on public.appointments
  for all using (exists(select 1 from public.user_profiles p where p.id = auth.uid() and p.role='admin'));

-- products: readable to all authenticated, writable by admin
create policy "products_read_all" on public.products for select using (true);
create policy "products_admin_all" on public.products for all using (
  exists(select 1 from public.user_profiles p where p.id = auth.uid() and p.role='admin')
) with check (
  exists(select 1 from public.user_profiles p where p.id = auth.uid() and p.role='admin')
);

-- orders: owner rw, admin all
create policy "orders_owner_rw" on public.orders for all using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "orders_admin_all" on public.orders for all using (exists(select 1 from public.user_profiles p where p.id = auth.uid() and p.role='admin'));

-- chat_messages: sender or recipient read; sender can insert; admin all
create policy "chat_select_participants" on public.chat_messages for select using (
  sender_id = auth.uid() or recipient_id = auth.uid() or exists(select 1 from public.user_profiles p where p.id = auth.uid() and p.role='admin')
);
create policy "chat_insert_sender" on public.chat_messages for insert with check (sender_id = auth.uid());
create policy "chat_update_participants" on public.chat_messages for update using (
  sender_id = auth.uid() or recipient_id = auth.uid() or exists(select 1 from public.user_profiles p where p.id = auth.uid() and p.role='admin')
);
