-- =====================================================================
--  รังมด · Delish Foods — ฐานข้อมูล Supabase (Postgres + Row Level Security)
--  วิธีใช้: Supabase Dashboard > SQL Editor > วางทั้งไฟล์ > Run (รันซ้ำได้ปลอดภัยใน DB ใหม่เท่านั้น)
-- =====================================================================
create extension if not exists pgcrypto;

-- ---------- ตาราง ----------
create table public.profiles(
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null, pos text, dept text, line text,
  role text not null default 'worker' check (role in ('queen','leader','worker')),
  status text not null default 'pending' check (status in ('pending','ok','no')),
  av int not null default 0,
  created_at timestamptz not null default now());

create table public.tasks(
  id uuid primary key default gen_random_uuid(),
  title text not null, descr text not null default '',
  from_id uuid not null references public.profiles(id),
  to_id uuid not null references public.profiles(id),
  due date,
  pri text not null default 'normal' check (pri in ('normal','urgent')),
  st text not null default 'doing' check (st in ('doing','review','redo','done')),
  prog int not null default 0 check (prog between 0 and 100),
  bites int not null default 0,
  sweet int check (sweet between 1 and 5),
  verdict text check (verdict in ('fix','fail')),
  sub jsonb, rid uuid, gid text,
  created_at timestamptz not null default now());
create index on public.tasks(to_id);
create index on public.tasks(from_id);
create unique index tasks_recurring_uq on public.tasks(rid,due,to_id) where rid is not null;

create table public.task_comments(
  id uuid primary key default gen_random_uuid(),
  task_id uuid not null references public.tasks(id) on delete cascade,
  by_id uuid not null references public.profiles(id),
  tx text not null, at timestamptz not null default now());
create index on public.task_comments(task_id);

create table public.notifs(
  id uuid primary key default gen_random_uuid(),
  to_id uuid not null references public.profiles(id) on delete cascade,
  tx text not null, ref uuid, at timestamptz not null default now(),
  read boolean not null default false);
create index on public.notifs(to_id, at desc);

create table public.recurs(
  id uuid primary key default gen_random_uuid(),
  title text not null, descr text not null default '',
  from_id uuid not null references public.profiles(id) on delete cascade,
  to_ids uuid[] not null,
  pri text not null default 'normal' check (pri in ('normal','urgent')),
  freq text not null check (freq in ('week','month')),
  dow int check (dow between 0 and 6),
  dom int check (dom between 0 and 28),
  start date not null, gen date,
  active boolean not null default true,
  created_at timestamptz not null default now());

create table public.notes(
  id uuid primary key default gen_random_uuid(),
  uid uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  tx text not null, tm text,
  date date not null default ((now() at time zone 'Asia/Bangkok')::date),
  ok boolean not null default false, al boolean not null default false);

-- ---------- ฟังก์ชันช่วย (security definer เพื่อเลี่ยง policy วนซ้ำ) ----------
create function public.my_role() returns text language sql stable security definer set search_path=public as
$$ select role from public.profiles where id=auth.uid() and status='ok' $$;

create function public.is_queen() returns boolean language sql stable security definer set search_path=public as
$$ select coalesce(public.my_role()='queen',false) $$;

-- ราชินีมอบได้: หัวหน้า+มดงาน | หัวหน้ามอบได้: มดงาน
create function public.can_assign(target uuid) returns boolean language sql stable security definer set search_path=public as
$$ select exists(select 1 from public.profiles t where t.id=target and t.status='ok' and (
     (public.my_role()='queen'  and t.role in ('leader','worker')) or
     (public.my_role()='leader' and t.role='worker'))) $$;

create function public.nf(to_ uuid, tx_ text, ref_ uuid default null) returns void language sql security definer set search_path=public as
$$ insert into public.notifs(to_id,tx,ref) values(to_,tx_,ref_) $$;
revoke all on function public.nf(uuid,text,uuid) from public, anon, authenticated;

-- ---------- สมัครสมาชิก: สร้างโปรไฟล์อัตโนมัติ (คนแรกของระบบ = ราชินี) ----------
create function public.handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$
declare first_user boolean; m jsonb:=coalesce(new.raw_user_meta_data,'{}'::jsonb);
begin
  select not exists(select 1 from public.profiles where role='queen') into first_user;
  insert into public.profiles(id,name,pos,dept,line,role,status)
  values(new.id, coalesce(nullif(m->>'name',''),split_part(new.email,'@',1)), m->>'pos', m->>'dept', m->>'line',
         case when first_user then 'queen' else 'worker' end, case when first_user then 'ok' else 'pending' end);
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();

-- ---------- Guard: ห้ามแก้ role/status เอง, ห้ามแก้รายละเอียดงาน ----------
create function public.profiles_guard() returns trigger language plpgsql security definer set search_path=public as $$
begin
  if auth.uid() is not null and not public.is_queen() and (new.role<>old.role or new.status<>old.status) then
    raise exception 'เฉพาะราชินีเท่านั้นที่เปลี่ยนตำแหน่งหรืออนุมัติได้'; end if;
  return new; end $$;
create trigger profiles_guard before update on public.profiles for each row execute function public.profiles_guard();

create function public.tasks_guard() returns trigger language plpgsql security definer set search_path=public as $$
begin
  if auth.uid() is null then return new; end if;
  if new.title<>old.title or new.descr<>old.descr or new.from_id<>old.from_id or new.to_id<>old.to_id
     or new.due is distinct from old.due or new.pri<>old.pri or new.rid is distinct from old.rid then
    raise exception 'ห้ามแก้ไขรายละเอียดงานหลังมอบหมาย'; end if;
  if auth.uid()=old.from_id then return new; end if;              -- ผู้มอบหมาย: ตรวจรับ/ให้คะแนน/กัด
  if old.st='done' then raise exception 'งานที่ผ่านแล้วแก้ไขไม่ได้'; end if;   -- ผู้รับงาน:
  if new.bites<>old.bites or new.sweet is distinct from old.sweet or new.verdict is distinct from old.verdict then
    raise exception 'ผู้รับงานให้คะแนนหรือกัดเองไม่ได้'; end if;
  if new.st<>old.st and new.st not in ('doing','review') then
    raise exception 'ผู้รับงานเปลี่ยนสถานะได้เฉพาะ กำลังทำ/ส่งตรวจ'; end if;
  return new; end $$;
create trigger tasks_guard before update on public.tasks for each row execute function public.tasks_guard();

-- ---------- แจ้งเตือนอัตโนมัติ (ทำที่ฐานข้อมูล ปลอมไม่ได้) ----------
create function public.trg_profile_notify() returns trigger language plpgsql security definer set search_path=public as $$
declare q record; rn text;
begin
  rn:=case new.role when 'queen' then 'ราชินีมด' when 'leader' then 'หัวหน้ามด' else 'มดงาน' end;
  if tg_op='INSERT' then
    if new.status='pending' then
      for q in select id from public.profiles where role='queen' and status='ok' loop
        perform public.nf(q.id, new.name||' ขอเข้ารัง ('||coalesce(new.pos,'-')||')'); end loop; end if;
  elsif old.status='pending' and new.status='ok' then perform public.nf(new.id,'ราชินีอนุมัติแล้ว ยินดีต้อนรับเข้ารัง ('||rn||')');
  elsif old.status='pending' and new.status='no' then perform public.nf(new.id,'คำขอเข้ารังยังไม่ได้รับการอนุมัติ');
  elsif new.status='ok' and old.role<>new.role then perform public.nf(new.id,'ตำแหน่งของคุณถูกเปลี่ยนเป็น '||rn); end if;
  return new; end $$;
create trigger profile_notify after insert or update on public.profiles for each row execute function public.trg_profile_notify();

create function public.trg_task_notify() returns trigger language plpgsql security definer set search_path=public as $$
declare fn text; tn text;
begin
  select name into fn from public.profiles where id=new.from_id;
  select name into tn from public.profiles where id=new.to_id;
  if tg_op='INSERT' then
    if new.rid is not null then perform public.nf(new.to_id,'งานประจำรอบใหม่: '||new.title||' (ครบกำหนด '||coalesce(new.due::text,'-')||')',new.id);
    else perform public.nf(new.to_id, fn||' มอบหมายงานใหม่'||case when new.pri='urgent' then ' (ด่วน)' else '' end||': '||new.title,new.id); end if;
    return new; end if;
  if new.st<>old.st then
    if new.st='review' then perform public.nf(new.from_id, tn||' ส่งงาน “'||new.title||'” รอตรวจรับ (ทาง '||case when new.sub->>'via'='email' then 'อีเมล' else 'LINE' end||')',new.id);
    elsif new.st='done' then perform public.nf(new.to_id,'งาน “'||new.title||'” ผ่านแล้ว'||case when new.sweet>0 then ' และได้รับน้ำหวาน '||new.sweet||' หยด 🍯' else '' end,new.id);
    elsif new.st='redo' then perform public.nf(new.to_id,'งาน “'||new.title||'” '||case when new.verdict='fail' then 'ยังไม่ผ่าน' else 'ขอให้แก้ไขเล็กน้อย' end||' ดูคอมเมนต์ได้เลย',new.id); end if; end if;
  if new.bites>old.bites then perform public.nf(new.to_id,'🐜 '||fn||' กัดเบา ๆ เรื่อง “'||new.title||'” (ครั้งที่ '||new.bites||')',new.id); end if;
  return new; end $$;
create trigger task_notify after insert or update on public.tasks for each row execute function public.trg_task_notify();

create function public.trg_comment_notify() returns trigger language plpgsql security definer set search_path=public as $$
declare t record; bn text;
begin
  select * into t from public.tasks where id=new.task_id;
  select name into bn from public.profiles where id=new.by_id;
  perform public.nf(case when new.by_id=t.from_id then t.to_id else t.from_id end, bn||' คอมเมนต์ในงาน “'||t.title||'”: '||left(new.tx,60), t.id);
  return new; end $$;
create trigger comment_notify after insert on public.task_comments for each row execute function public.trg_comment_notify();

-- ---------- สถิติรายคน (ไม่เปิดเผยตัวงานของคนอื่น) ----------
create function public.member_stats() returns table(id uuid, open_n int, n_rated int, avg_sweet numeric)
language sql stable security definer set search_path=public as $$
  select p.id,
    (select count(*)::int from public.tasks t where t.to_id=p.id and t.st<>'done'),
    (select count(*)::int from public.tasks t where t.to_id=p.id and t.sweet>0),
    (select avg(t.sweet)::numeric from public.tasks t where t.to_id=p.id and t.sweet>0)
  from public.profiles p where p.status='ok' and public.my_role() is not null $$;

-- ---------- สร้างงานประจำรอบใหม่ (รายสัปดาห์ล่วงหน้า 6 วัน / รายเดือน 14 วัน) ----------
create function public.generate_recurring() returns int language plpgsql security definer set search_path=public as $$
declare r record; d date; tgt uuid; n int:=0; today date:=(now() at time zone 'Asia/Bangkok')::date;
        lead int; a date; last_d date; eom int;
begin
  for r in select * from public.recurs where active loop
    lead:=case when r.freq='week' then 6 else 14 end;
    a:=greatest(r.start, coalesce(r.gen+1,r.start)); last_d:=null;
    for d in select g::date from generate_series(a::timestamp, (today+lead)::timestamp, interval '1 day') g loop
      eom:=extract(day from (date_trunc('month',d)+interval '1 month - 1 day'))::int;
      if (r.freq='week' and extract(dow from d)::int=r.dow)
      or (r.freq='month' and extract(day from d)::int = case when r.dom=0 then eom else least(r.dom,eom) end) then
        foreach tgt in array r.to_ids loop
          insert into public.tasks(title,descr,from_id,to_id,due,pri,rid,gid)
          select r.title,r.descr,r.from_id,tgt,d,r.pri,r.id,'r'||r.id
          from public.profiles t, public.profiles f
          where t.id=tgt and t.status='ok' and f.id=r.from_id and f.status='ok'
            and ((f.role='queen' and t.role in ('leader','worker')) or (f.role='leader' and t.role='worker'))
          on conflict (rid,due,to_id) where rid is not null do nothing;
          if found then n:=n+1; end if;
        end loop;
        last_d:=d;
      end if;
    end loop;
    if last_d is not null then update public.recurs set gen=last_d where id=r.id; end if;
  end loop;
  return n; end $$;
grant execute on function public.generate_recurring() to authenticated;
grant execute on function public.member_stats() to authenticated;
grant execute on function public.my_role(), public.is_queen(), public.can_assign(uuid) to authenticated;

-- ---------- Row Level Security ----------
alter table public.profiles enable row level security;
alter table public.tasks enable row level security;
alter table public.task_comments enable row level security;
alter table public.notifs enable row level security;
alter table public.recurs enable row level security;
alter table public.notes enable row level security;

create policy profiles_read on public.profiles for select to authenticated
  using (id=auth.uid() or public.my_role() is not null and status='ok' or public.is_queen());
create policy profiles_self_update on public.profiles for update to authenticated using (id=auth.uid()) with check (id=auth.uid());
create policy profiles_queen_update on public.profiles for update to authenticated using (public.is_queen()) with check (public.is_queen());

create policy tasks_read on public.tasks for select to authenticated using (from_id=auth.uid() or to_id=auth.uid() or public.is_queen());
create policy tasks_insert on public.tasks for insert to authenticated with check (from_id=auth.uid() and public.can_assign(to_id));
create policy tasks_update on public.tasks for update to authenticated using (from_id=auth.uid() or to_id=auth.uid()) with check (from_id=auth.uid() or to_id=auth.uid());
create policy tasks_delete on public.tasks for delete to authenticated using (from_id=auth.uid() or public.is_queen());

create policy comments_read on public.task_comments for select to authenticated using (exists(select 1 from public.tasks t where t.id=task_id));
create policy comments_insert on public.task_comments for insert to authenticated
  with check (by_id=auth.uid() and exists(select 1 from public.tasks t where t.id=task_id and auth.uid() in (t.from_id,t.to_id)));

create policy notifs_read on public.notifs for select to authenticated using (to_id=auth.uid());
create policy notifs_update on public.notifs for update to authenticated using (to_id=auth.uid()) with check (to_id=auth.uid());
create policy notifs_delete on public.notifs for delete to authenticated using (to_id=auth.uid());

create policy recurs_read on public.recurs for select to authenticated using (from_id=auth.uid());
create policy recurs_insert on public.recurs for insert to authenticated with check (from_id=auth.uid() and public.my_role() in ('queen','leader'));
create policy recurs_update on public.recurs for update to authenticated using (from_id=auth.uid()) with check (from_id=auth.uid());
create policy recurs_delete on public.recurs for delete to authenticated using (from_id=auth.uid());

create policy notes_all on public.notes for all to authenticated using (uid=auth.uid()) with check (uid=auth.uid());

-- ---------- Realtime (แจ้งเตือน/งานอัปเดตสดข้ามเครื่อง) ----------
do $$ begin
  if exists(select 1 from pg_publication where pubname='supabase_realtime') then
    alter publication supabase_realtime add table public.tasks, public.notifs, public.task_comments, public.profiles, public.recurs;
  end if; end $$;

-- ---------- (ทางเลือก) ตั้งเวลาให้สร้างงานประจำทุกวัน 00:05 น. เวลาไทย ----------
-- เปิด Database > Extensions > pg_cron ก่อน แล้วรันบรรทัดล่างนี้แยกต่างหาก:
-- select cron.schedule('antnest-recurring','5 17 * * *','select public.generate_recurring()');
