import type { Env, IdentityRow, IdentityWithKeys, KeyRow } from "./types";

const IDENTITY_COLUMNS = "id, handle, name, description, is_public, created_at, updated_at";
const KEY_COLUMNS = "id, identity_id, public_key, key_type, fingerprint, label, key_comment, added_at, created_at, updated_at";

export async function listPublicIdentities(env: Env): Promise<IdentityRow[]> {
  const result = await env.DB.prepare(
    `SELECT ${IDENTITY_COLUMNS}, (SELECT COUNT(*) FROM ssh_keys WHERE identity_id = identities.id) AS key_count
     FROM identities WHERE is_public = 1 ORDER BY handle`,
  ).all<IdentityRow>();
  return result.results;
}

export async function getPublicIdentity(env: Env, handle: string): Promise<IdentityWithKeys | null> {
  const identity = await env.DB.prepare(
    `SELECT ${IDENTITY_COLUMNS} FROM identities WHERE handle = ? AND is_public = 1`,
  )
    .bind(handle)
    .first<IdentityRow>();
  if (!identity) return null;
  const keys = await env.DB.prepare(
    `SELECT ${KEY_COLUMNS} FROM ssh_keys WHERE identity_id = ? ORDER BY added_at DESC, id DESC`,
  )
    .bind(identity.id)
    .all<KeyRow>();
  return { ...identity, keys: keys.results };
}

export async function listAllIdentities(env: Env): Promise<IdentityWithKeys[]> {
  const [identitiesResult, keysResult] = await env.DB.batch([
    env.DB.prepare(`SELECT ${IDENTITY_COLUMNS} FROM identities ORDER BY handle`),
    env.DB.prepare(`SELECT ${KEY_COLUMNS} FROM ssh_keys ORDER BY added_at DESC, id DESC`),
  ]);
  if (!identitiesResult || !keysResult) throw new Error("D1 returned an incomplete batch result");
  const identities = (identitiesResult.results ?? []) as unknown as IdentityRow[];
  const keys = (keysResult.results ?? []) as unknown as KeyRow[];
  return identities.map((identity) => ({
    ...identity,
    keys: keys.filter((key) => key.identity_id === identity.id),
  }));
}

export async function listAuditEvents(env: Env): Promise<Record<string, unknown>[]> {
  const result = await env.DB.prepare(
    "SELECT id, action, target, detail, actor_hash, created_at FROM audit_events ORDER BY id DESC LIMIT 50",
  ).all();
  return result.results;
}

export function auditStatement(
  env: Env,
  action: string,
  target: string,
  detail: string,
  actorHash: string,
): D1PreparedStatement {
  return env.DB.prepare(
    "INSERT INTO audit_events (action, target, detail, actor_hash) VALUES (?, ?, ?, ?)",
  ).bind(action, target, detail, actorHash);
}
