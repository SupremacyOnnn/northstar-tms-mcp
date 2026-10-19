CREATE TABLE IF NOT EXISTS public.oidc_adapter_store (
  model text NOT NULL,
  id text NOT NULL,
  payload jsonb NOT NULL,
  expires_at timestamptz,
  uid text,
  user_code text,
  grant_id text,
  PRIMARY KEY (model, id)
);
CREATE INDEX IF NOT EXISTS oidc_adapter_uid_idx ON public.oidc_adapter_store (model, uid);
CREATE INDEX IF NOT EXISTS oidc_adapter_user_code_idx ON public.oidc_adapter_store (model, user_code);
CREATE INDEX IF NOT EXISTS oidc_adapter_grant_idx ON public.oidc_adapter_store (grant_id);
