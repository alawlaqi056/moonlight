-- ============================================================
-- Moonlight Assistance — قاعدة البيانات والصلاحيات
-- الصق هذا الملف كاملًا في Supabase > SQL Editor ثم اضغط Run.
-- آمن للتشغيل أكثر من مرة: لا يكرّر البيانات ولا يمسح شيئًا.
-- ============================================================

-- ---------- الجداول ----------

create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  email       text,
  full_name   text,
  role        text not null default 'staff' check (role in ('admin', 'staff')),
  active      boolean not null default true,
  created_at  timestamptz not null default now()
);

create table if not exists public.partners (
  id          bigint generated always as identity primary key,
  kind        text not null check (kind in ('uni', 'lang')),
  short       text not null default '' check (char_length(short) <= 24),
  name        text not null check (char_length(name) between 2 and 160),
  image_url   text check (image_url is null or char_length(image_url) <= 1000),
  sort        integer not null default 0,
  visible     boolean not null default true,
  created_at  timestamptz not null default now()
);

create table if not exists public.settings (
  key         text primary key check (char_length(key) <= 60),
  value_ar    text check (char_length(value_ar) <= 2000),
  value_en    text check (char_length(value_en) <= 2000),
  updated_at  timestamptz not null default now()
);

create table if not exists public.inquiries (
  id          bigint generated always as identity primary key,
  created_at  timestamptz not null default now(),
  name        text not null check (char_length(name) between 1 and 120),
  country     text check (char_length(country) <= 80),
  goal        text check (char_length(goal) <= 200),
  level       text check (char_length(level) <= 20),
  phone       text check (char_length(phone) <= 30),
  lang        text check (lang in ('ar', 'en')),
  status      text not null default 'new' check (status in ('new', 'contacted', 'done', 'spam')),
  note        text check (char_length(note) <= 1000),
  handled_by  uuid references auth.users(id) on delete set null
);

create index if not exists partners_sort_idx on public.partners (sort, id);
create index if not exists inquiries_created_idx on public.inquiries (created_at desc);

-- ---------- دوال الصلاحيات ----------

create or replace function public.is_staff()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles p where p.id = auth.uid() and p.active)
$$;

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles p where p.id = auth.uid() and p.active and p.role = 'admin')
$$;

-- تُعيد false للزائر غير المسجّل، ومسموحة له كي لا تفشل سياسات القراءة العامة
revoke all on function public.is_staff() from public;
revoke all on function public.is_admin() from public;
grant execute on function public.is_staff() to anon, authenticated;
grant execute on function public.is_admin() to anon, authenticated;

-- المدير فقط: يمنح مستخدمًا موجودًا صلاحية مدير أو موظف (تستدعيها اللوحة)
create or replace function public.grant_staff(p_email text, p_role text, p_name text default null)
returns void language plpgsql security definer set search_path = public, auth as $$
declare v_id uuid;
begin
  if not public.is_admin() then raise exception 'غير مسموح'; end if;
  if p_role not in ('admin', 'staff') then raise exception 'صلاحية غير صحيحة'; end if;
  select id into v_id from auth.users where lower(email) = lower(p_email) limit 1;
  if v_id is null then raise exception 'المستخدم غير موجود'; end if;
  insert into public.profiles (id, email, full_name, role, active)
  values (v_id, lower(p_email), nullif(trim(coalesce(p_name, '')), ''), p_role, true)
  on conflict (id) do update
    set role = excluded.role,
        active = true,
        email = excluded.email,
        full_name = coalesce(excluded.full_name, public.profiles.full_name);
end $$;

revoke all on function public.grant_staff(text, text, text) from public, anon;
grant execute on function public.grant_staff(text, text, text) to authenticated;

-- لا تُستدعى إلا من SQL Editor وتعمل مرة واحدة فقط، لإنشاء أول مدير
create or replace function public.bootstrap_first_admin(p_email text)
returns void language plpgsql security definer set search_path = public, auth as $$
declare v_id uuid;
begin
  if exists (select 1 from public.profiles where role = 'admin') then
    raise exception 'يوجد مدير بالفعل';
  end if;
  select id into v_id from auth.users where lower(email) = lower(p_email) limit 1;
  if v_id is null then raise exception 'أنشئ المستخدم أولًا من Authentication > Users'; end if;
  insert into public.profiles (id, email, full_name, role, active)
  values (v_id, lower(p_email), 'المدير', 'admin', true);
end $$;

revoke all on function public.bootstrap_first_admin(text) from public, anon, authenticated;

-- يمنع حذف أو تعطيل آخر مدير
create or replace function public.protect_last_admin()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if (tg_op = 'DELETE' and old.role = 'admin' and old.active)
     or (tg_op = 'UPDATE' and old.role = 'admin' and old.active and (new.role <> 'admin' or not new.active)) then
    if not exists (select 1 from public.profiles where role = 'admin' and active and id <> old.id) then
      raise exception 'لا يمكن حذف أو تعطيل آخر مدير';
    end if;
  end if;
  if tg_op = 'DELETE' then return old; end if;
  return new;
end $$;

drop trigger if exists trg_protect_last_admin on public.profiles;
create trigger trg_protect_last_admin
  before update or delete on public.profiles
  for each row execute function public.protect_last_admin();

-- ---------- الأمان (RLS) ----------

alter table public.profiles  enable row level security;
alter table public.partners  enable row level security;
alter table public.settings  enable row level security;
alter table public.inquiries enable row level security;

revoke all on public.profiles, public.partners, public.settings, public.inquiries from anon, authenticated;

grant select on public.partners, public.settings to anon, authenticated;
grant insert, update, delete on public.partners, public.settings to authenticated;

grant select, insert, update, delete on public.profiles to authenticated;

grant insert on public.inquiries to anon, authenticated;
grant select, delete on public.inquiries to authenticated;
grant update (status, note, handled_by) on public.inquiries to authenticated;

-- الشركاء: الزائر يرى الظاهر فقط، والموظفون يرون الكل، والمدير يعدّل
drop policy if exists partners_read on public.partners;
create policy partners_read on public.partners for select to anon, authenticated
  using (visible or public.is_staff());
drop policy if exists partners_admin_write on public.partners;
create policy partners_admin_write on public.partners for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- النصوص ومعلومات التواصل: قراءة للجميع، تعديل للمدير
drop policy if exists settings_read on public.settings;
create policy settings_read on public.settings for select to anon, authenticated
  using (true);
drop policy if exists settings_admin_write on public.settings;
create policy settings_admin_write on public.settings for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- الاستفسارات: أي زائر يرسل، الموظفون يقرؤون ويحدّثون الحالة، المدير يحذف
drop policy if exists inquiries_insert on public.inquiries;
create policy inquiries_insert on public.inquiries for insert to anon, authenticated
  with check (status = 'new' and note is null and handled_by is null);
drop policy if exists inquiries_staff_read on public.inquiries;
create policy inquiries_staff_read on public.inquiries for select to authenticated
  using (public.is_staff());
drop policy if exists inquiries_staff_update on public.inquiries;
create policy inquiries_staff_update on public.inquiries for update to authenticated
  using (public.is_staff()) with check (public.is_staff());
drop policy if exists inquiries_admin_delete on public.inquiries;
create policy inquiries_admin_delete on public.inquiries for delete to authenticated
  using (public.is_admin());

-- الموظفون: كل مستخدم يرى سجله، والمدير يرى ويدير الجميع
drop policy if exists profiles_self_read on public.profiles;
create policy profiles_self_read on public.profiles for select to authenticated
  using (id = auth.uid() or public.is_admin());
drop policy if exists profiles_admin_write on public.profiles;
create policy profiles_admin_write on public.profiles for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- ---------- مخزن الصور ----------

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('partner-images', 'partner-images', true, 1048576, array['image/jpeg', 'image/png', 'image/webp'])
on conflict (id) do update
  set public = excluded.public,
      file_size_limit = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

-- القراءة للمدير مطلوبة كي ينجح حذف الصور القديمة (الحذف يقرأ الصف أولًا)
drop policy if exists "partner images admin select" on storage.objects;
create policy "partner images admin select" on storage.objects for select to authenticated
  using (bucket_id = 'partner-images' and public.is_admin());
drop policy if exists "partner images admin insert" on storage.objects;
create policy "partner images admin insert" on storage.objects for insert to authenticated
  with check (bucket_id = 'partner-images' and public.is_admin());
drop policy if exists "partner images admin update" on storage.objects;
create policy "partner images admin update" on storage.objects for update to authenticated
  using (bucket_id = 'partner-images' and public.is_admin());
drop policy if exists "partner images admin delete" on storage.objects;
create policy "partner images admin delete" on storage.objects for delete to authenticated
  using (bucket_id = 'partner-images' and public.is_admin());

-- ---------- بيانات أولية (تُضاف مرة واحدة فقط إذا كان الجدول فارغًا) ----------

insert into public.partners (kind, short, name, sort)
select v.kind, v.short, v.name, v.sort
from (values
  ('uni', 'UNITEN', 'Universiti Tenaga Nasional', 10),
  ('uni', 'UPM', 'Universiti Putra Malaysia', 20),
  ('uni', 'APU', 'Asia Pacific University', 30),
  ('uni', 'KLUST', 'Kuala Lumpur University of Science and Technology', 40),
  ('uni', 'UNITAR', 'UNITAR International University', 50),
  ('uni', 'MONASH', 'Monash University Malaysia', 60),
  ('uni', 'TAYLOR''S', 'Taylor''s University', 70),
  ('uni', 'UniKL', 'Universiti Kuala Lumpur', 80),
  ('uni', 'UTP', 'Universiti Teknologi PETRONAS', 90),
  ('uni', 'MMU', 'Multimedia University', 100),
  ('uni', 'MSU', 'Management and Science University', 110),
  ('uni', 'UTM', 'Universiti Teknologi Malaysia', 120),
  ('uni', 'USM', 'Universiti Sains Malaysia', 130),
  ('uni', 'UTHM', 'Universiti Tun Hussein Onn Malaysia', 140),
  ('uni', 'IIUM', 'International Islamic University Malaysia', 150),
  ('uni', 'SUNWAY', 'Sunway University', 160),
  ('uni', 'UniMAP', 'Universiti Malaysia Perlis', 170),
  ('uni', 'UCSI', 'UCSI University', 180),
  ('uni', 'LINCOLN', 'Lincoln University College', 190),
  ('uni', 'CITY', 'City University Malaysia', 200),
  ('uni', 'MAHSA', 'MAHSA University', 210),
  ('uni', 'UKM', 'Universiti Kebangsaan Malaysia', 220),
  ('uni', 'UNIMY', 'University Malaysia of Computer Science and Engineering', 230),
  ('uni', 'UoC', 'University of Cyberjaya', 240),
  ('uni', 'IMU', 'International Medical University', 250),
  ('uni', 'ALFA', 'ALFA University College', 260),
  ('uni', 'SEGi', 'SEGi University', 270),
  ('uni', 'NILAI', 'Nilai University', 280),
  ('uni', 'INTI', 'INTI International University', 290),
  ('uni', 'OUM', 'Open University Malaysia', 300),
  ('lang', '', 'Big Ben', 310),
  ('lang', '', 'Wall Street English', 320),
  ('lang', '', 'Awesome Academy', 330),
  ('lang', '', 'Britannia Language Centre', 340),
  ('lang', '', 'ELS Language Centres', 350),
  ('lang', '', 'Erican Language Centre', 360),
  ('lang', '', 'EMS Language Centre', 370),
  ('lang', '', 'Sheffield Academy', 380),
  ('lang', '', 'Stratford International Language Centre', 390),
  ('lang', '', 'Bright Language Center', 400),
  ('lang', '', 'ELIT Language Centre', 410),
  ('lang', '', 'ELEC Language Centre', 420),
  ('lang', '', 'California KL Language Academy', 430),
  ('lang', '', 'Excel Language Center', 440)
) as v(kind, short, name, sort)
where not exists (select 1 from public.partners);

insert into public.settings (key, value_ar)
values
  ('whatsapp', '+60 11-2835 6676'),
  ('email', 'Moonlight.assistance142@gmail.com')
on conflict (key) do nothing;

-- ============================================================
-- الخطوة الأخيرة (بعد إنشاء مستخدمك من Authentication > Users):
-- عدّل البريد ثم شغّل السطر التالي مرة واحدة لتصبح مديرًا:
--
--   select public.bootstrap_first_admin('بريدك@example.com');
--
-- ============================================================
