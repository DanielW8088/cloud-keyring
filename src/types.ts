export interface Env {
  DB: D1Database;
  ADMIN_PASSWORD: string;
  SESSION_SECRET: string;
  SITE_NAME?: string;
  CANONICAL_ORIGIN?: string;
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

export interface InstallerSubject {
  /** Immutable identity uid; null for handles retired before uids existed. */
  uid: string | null;
  handle: string;
  /** Every handle this identity has used, for migrating legacy blocks. */
  legacyHandles: string[];
  /** False when the identity is hidden or deleted: the installer only revokes. */
  published: boolean;
  keys: KeyRow[];
}
