-- Users table for Trello Manager
create table if not exists public.users (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  email text not null unique,
  password_hash text not null,
  role text not null default 'user' check (role in ('admin', 'user')),
  trello_api_key text,
  trello_token text,
  created_at timestamptz not null default now()
);

-- Index for login queries
create index if not exists users_email_idx on public.users (email);
