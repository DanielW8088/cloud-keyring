export interface Env {
  DB: D1Database;
  ADMIN_PASSWORD: string;
  SESSION_SECRET: string;
  SITE_NAME?: string;
}

export interface IdentityRow {
  id: number;
  handle: string;
  name: string;
  description: string;
  is_public: number;
  created_at: string;
  updated_at: string;
}

export interface KeyRow {
  id: number;
  identity_id: number;
  public_key: string;
  key_type: string;
  fingerprint: string;
  label: string;
  key_comment: string;
  added_at: string;
  created_at: string;
  updated_at: string;
}

export interface IdentityWithKeys extends IdentityRow {
  keys: KeyRow[];
}
