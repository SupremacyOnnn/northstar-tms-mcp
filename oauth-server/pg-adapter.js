import { Pool } from "pg";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Durable oidc-provider adapter. The table must be created by a migration.
export function createPgAdapter(databaseUrl) {
  const caPath = path.join(path.dirname(fileURLToPath(import.meta.url)), "certs", "supabase-ca.crt");
  const pool = new Pool({ connectionString: databaseUrl, ssl: { rejectUnauthorized: true, ca: fs.readFileSync(caPath, "utf8") } });
  return class PgAdapter {
    constructor(model) { this.model = model; }
    async upsert(id, payload, expiresIn) {
      const expiresAt = typeof expiresIn === "number" ? new Date(Date.now() + expiresIn * 1000) : null;
      await pool.query(`INSERT INTO public.oidc_adapter_store (model, id, payload, expires_at, uid, user_code, grant_id)
        VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (model,id) DO UPDATE SET payload=EXCLUDED.payload, expires_at=EXCLUDED.expires_at, uid=EXCLUDED.uid, user_code=EXCLUDED.user_code, grant_id=EXCLUDED.grant_id`,
        [this.model, id, payload, expiresAt, payload.uid ?? null, payload.userCode ?? null, payload.grantId ?? null]);
    }
    async find(id) { const r = await pool.query("SELECT payload FROM public.oidc_adapter_store WHERE model=$1 AND id=$2 AND (expires_at IS NULL OR expires_at > now())", [this.model,id]); return r.rows[0]?.payload; }
    async findByUid(uid) { const r = await pool.query("SELECT payload FROM public.oidc_adapter_store WHERE model=$1 AND uid=$2 AND (expires_at IS NULL OR expires_at > now())", [this.model,uid]); return r.rows[0]?.payload; }
    async findByUserCode(userCode) { const r = await pool.query("SELECT payload FROM public.oidc_adapter_store WHERE model=$1 AND user_code=$2 AND (expires_at IS NULL OR expires_at > now())", [this.model,userCode]); return r.rows[0]?.payload; }
    async consume(id) { await pool.query("UPDATE public.oidc_adapter_store SET payload=jsonb_set(payload, '{consumed}', to_jsonb(floor(extract(epoch from now()))) ) WHERE model=$1 AND id=$2", [this.model,id]); }
    async destroy(id) { await pool.query("DELETE FROM public.oidc_adapter_store WHERE model=$1 AND id=$2", [this.model,id]); }
    async revokeByGrantId(grantId) { await pool.query("DELETE FROM public.oidc_adapter_store WHERE grant_id=$1", [grantId]); }
  };
}
