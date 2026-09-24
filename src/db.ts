import type { Env, IdentityRow, IdentityWithKeys, InstallerSubject, KeyRow } from "./types";

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

/**
 * Resolves an installer URL. Any handle an identity has ever used resolves to
 * that identity's current state; hidden and deleted identities yield a
 * revocation-only installer instead of a 404, so servers can still converge.
 */
export async function getInstallerSubject(env: Env, handle: string): Promise<InstallerSubject | null> {
  const entry = await env.DB.prepare("SELECT identity_uid FROM identity_handles WHERE handle = ?")
    .bind(handle)
    .first<{ identity_uid: string | null }>();
  if (!entry) return null;
  const uid = entry.identity_uid;
  if (!uid) return { uid: null, handle, legacyHandles: [handle], published: false, keys: [] };

  const [identityResult, handlesResult] = await env.DB.batch([
    env.DB.prepare("SELECT id, handle, is_public FROM identities WHERE uid = ?").bind(uid),
    env.DB.prepare("SELECT handle FROM identity_handles WHERE identity_uid = ? ORDER BY handle").bind(uid),
  ]);
  const identity = identityResult?.results?.[0] as Pick<IdentityRow, "id" | "handle" | "is_public"> | undefined;
  const legacyHandles = ((handlesResult?.results ?? []) as { handle: string }[]).map((row) => row.handle);
  if (!identity || identity.is_public !== 1) {
    return { uid, handle: identity?.handle ?? handle, legacyHandles, published: false, keys: [] };
  }
  const keys = await env.DB.prepare(
    `SELECT ${KEY_COLUMNS} FROM ssh_keys WHERE identity_id = ? ORDER BY added_at DESC, id DESC`,
  )
    .bind(identity.id)
    .all<KeyRow>();
  return { uid, handle: identity.handle, legacyHandles, published: true, keys: keys.results };
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

export async function listAuditEvents(env: Env): Promise<{
  events: Record<string, unknown>[];
  loginFailures24h: number;
}> {
  // Login events are kept out of the main list so unauthenticated floods of
  // failed logins cannot push management events out of view.
  const [events, failures] = await env.DB.batch([
    env.DB.prepare(
      `SELECT id, action, target, detail, actor_hash, created_at FROM audit_events
       WHERE substr(action, 1, 6) <> 'login.' ORDER BY id DESC LIMIT 50`,
    ),
    env.DB.prepare(
      `SELECT COUNT(*) AS count FROM audit_events
       WHERE action = 'login.failed' AND created_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 day')`,
    ),
  ]);
  return {
    events: (events?.results ?? []) as Record<string, unknown>[],
    loginFailures24h: Number((failures?.results?.[0] as { count?: number } | undefined)?.count ?? 0),
  };
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
