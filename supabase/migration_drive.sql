-- Adiciona colunas de Google Drive na tabela users
alter table public.users
  add column if not exists google_refresh_token text,
  add column if not exists google_email text;
