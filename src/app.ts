import { ADMIN_JS, APP_JS, CSS } from "./assets";
import { auditStatement, getPublicIdentity, listAllIdentities, listAuditEvents, listPublicIdentities } from "./db";
import {
  clearSessionCookie,
  createSessionCookie,
  hasValidSession,
  isSameOrigin,
  passwordsEqual,
  privacyHash,
} from "./security";
import { parsePublicKey } from "./ssh";
import type { Env, IdentityRow, KeyRow } from "./types";
import { renderAdmin, renderHome, renderIdentity, renderLogin } from "./views";

const SECURITY_HEADERS: Record<string, string> = {
  "content-security-policy":
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  "referrer-policy": "no-referrer",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
};

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

function response(body: BodyInit | null, status = 200, headers: HeadersInit = {}): Response {
  return new Response(body, { status, headers: { ...SECURITY_HEADERS, ...headers } });
}

function html(body: string, status = 200): Response {
  return response(body, status, {
    "cache-control": "no-store",
    "content-type": "text/html; charset=utf-8",
  });
}

function json(body: unknown, status = 200, headers: HeadersInit = {}): Response {
  return response(JSON.stringify(body), status, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    ...headers,
  });
}

function text(body: string, contentType = "text/plain; charset=utf-8"): Response {
  return response(body, 200, {
    "cache-control": "no-store",
    "content-type": contentType,
  });
}

function siteName(env: Env): string {
  return env.SITE_NAME?.trim().slice(0, 60) || "Cloud Keyring";
}

function validateConfiguration(env: Env): void {
  if (!env.ADMIN_PASSWORD || env.ADMIN_PASSWORD.length < 16) {
    throw new Error("ADMIN_PASSWORD must contain at least 16 characters");
  }
  if (!env.SESSION_SECRET || env.SESSION_SECRET.length < 32) {
    throw new Error("SESSION_SECRET must contain at least 32 characters");
  }
}

async function readJson(request: Request): Promise<Record<string, unknown>> {
  const length = Number(request.headers.get("content-length") ?? 0);
  if (length > 20_000) throw new HttpError(413, "请求内容过大");
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
    throw new HttpError(415, "请求必须使用 application/json");
  }
  try {
    const body = await request.text();
    if (new TextEncoder().encode(body).byteLength > 20_000) throw new HttpError(413, "请求内容过大");
    const value: unknown = JSON.parse(body);
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error();
    return value as Record<string, unknown>;
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(400, "JSON 请求无效");
  }
}

function stringField(
  data: Record<string, unknown>,
  field: string,
  maximum: number,
  required = true,
): string {
  const value = data[field];
  if (typeof value !== "string") throw new HttpError(400, `${field} 必须是字符串`);
  const normalized = value.trim();
  if ((required && !normalized) || normalized.length > maximum || /[\0\r]/.test(normalized)) {
    throw new HttpError(400, `${field} 的格式或长度无效`);
  }
  return normalized;
}

function identityFields(data: Record<string, unknown>): {
  handle: string;
  name: string;
  description: string;
  isPublic: number;
} {
  const handle = stringField(data, "handle", 32).toLowerCase();
  if (!/^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/.test(handle)) {
    throw new HttpError(400, "Handle 只能包含小写字母、数字和中划线，且不能以中划线结尾");
  }
  if (["admin", "api", "assets"].includes(handle)) {
    throw new HttpError(400, "该 Handle 是系统保留名称");
  }
  const name = stringField(data, "name", 80);
  const description = stringField(data, "description", 240, false);
  if (typeof data.isPublic !== "boolean") throw new HttpError(400, "isPublic 必须是布尔值");
  return { handle, name, description, isPublic: data.isPublic ? 1 : 0 };
}

function integerId(value: string | undefined): number {
  if (!value || !/^[1-9]\d{0,9}$/.test(value)) throw new HttpError(404, "资源不存在");
  return Number(value);
}

function validDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const [year, month, day] = value.split("-").map(Number);
  const date = new Date(Date.UTC(year ?? 0, (month ?? 0) - 1, day));
  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() + 1 === month &&
    date.getUTCDate() === day
  );
}

function actorIp(request: Request): string {
  return request.headers.get("cf-connecting-ip") ?? "local";
}

async function actorHash(request: Request, env: Env): Promise<string> {
  return privacyHash(env.SESSION_SECRET, actorIp(request));
}

async function requireAdmin(request: Request, env: Env): Promise<void> {
  if (!(await hasValidSession(request, env.SESSION_SECRET))) {
    throw new HttpError(401, "登录已失效");
  }
  if (request.method !== "GET" && !isSameOrigin(request)) {
    throw new HttpError(403, "拒绝跨站请求");
  }
}

async function login(request: Request, env: Env): Promise<Response> {
  if (!isSameOrigin(request)) throw new HttpError(403, "拒绝跨站请求");
  const data = await readJson(request);
  const password = stringField(data, "password", 1024);
  const bucket = await privacyHash(env.SESSION_SECRET, `login:${actorIp(request)}`);
  const now = Math.floor(Date.now() / 1000);
  const attempt = await env.DB.prepare(
    "SELECT failures, blocked_until FROM auth_attempts WHERE bucket = ?",
  )
    .bind(bucket)
    .first<{ failures: number; blocked_until: number }>();
  if (attempt && attempt.blocked_until > now) {
    throw new HttpError(429, "登录尝试过多，请稍后重试");
  }

  if (!(await passwordsEqual(password, env.ADMIN_PASSWORD))) {
    const failures = (attempt?.blocked_until && attempt.blocked_until <= now ? 0 : attempt?.failures ?? 0) + 1;
    const blockedUntil = failures >= 5 ? now + Math.min(15 * 60, 30 * 2 ** Math.min(failures - 5, 5)) : 0;
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO auth_attempts (bucket, failures, blocked_until, updated_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(bucket) DO UPDATE SET failures = excluded.failures, blocked_until = excluded.blocked_until, updated_at = excluded.updated_at`,
      ).bind(bucket, failures, blockedUntil, now),
      auditStatement(env, "login.failed", "admin", `failure ${failures}`, await actorHash(request, env)),
    ]);
    throw new HttpError(401, "口令错误");
  }

  await env.DB.batch([
    env.DB.prepare("DELETE FROM auth_attempts WHERE bucket = ?").bind(bucket),
    auditStatement(env, "login.succeeded", "admin", "", await actorHash(request, env)),
  ]);
  return json(
    { ok: true },
    200,
    { "set-cookie": await createSessionCookie(env.SESSION_SECRET) },
  );
}

async function adminApi(request: Request, env: Env, path: string): Promise<Response> {
  if (path === "/api/login" && request.method === "POST") return login(request, env);
  await requireAdmin(request, env);

  if (path === "/api/logout" && request.method === "POST") {
    return json({ ok: true }, 200, { "set-cookie": clearSessionCookie() });
  }
  if (path === "/api/admin/state" && request.method === "GET") {
    const [identities, audit] = await Promise.all([listAllIdentities(env), listAuditEvents(env)]);
    return json({ identities, audit });
  }
  if (path === "/api/identities" && request.method === "POST") {
    const fields = identityFields(await readJson(request));
    const actor = await actorHash(request, env);
    try {
      await env.DB.batch([
        env.DB.prepare(
          "INSERT INTO identities (handle, name, description, is_public) VALUES (?, ?, ?, ?)",
        ).bind(fields.handle, fields.name, fields.description, fields.isPublic),
        auditStatement(env, "identity.created", fields.handle, fields.name, actor),
      ]);
    } catch (error) {
      if (String(error).includes("UNIQUE")) throw new HttpError(409, "该 Handle 已存在");
      throw error;
    }
    return json({ ok: true }, 201);
  }

  const identityMatch = path.match(/^\/api\/identities\/(\d+)$/);
  if (identityMatch && request.method === "PUT") {
    const id = integerId(identityMatch[1]);
    const fields = identityFields(await readJson(request));
    const existing = await env.DB.prepare("SELECT handle FROM identities WHERE id = ?").bind(id).first<{ handle: string }>();
    if (!existing) throw new HttpError(404, "身份不存在");
    try {
      await env.DB.batch([
        env.DB.prepare(
          "UPDATE identities SET handle = ?, name = ?, description = ?, is_public = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
        ).bind(fields.handle, fields.name, fields.description, fields.isPublic, id),
        auditStatement(env, "identity.updated", fields.handle, `formerly ${existing.handle}`, await actorHash(request, env)),
      ]);
    } catch (error) {
      if (String(error).includes("UNIQUE")) throw new HttpError(409, "该 Handle 已存在");
      throw error;
    }
    return json({ ok: true });
  }
  if (identityMatch && request.method === "DELETE") {
    const id = integerId(identityMatch[1]);
    const existing = await env.DB.prepare("SELECT handle FROM identities WHERE id = ?").bind(id).first<{ handle: string }>();
    if (!existing) throw new HttpError(404, "身份不存在");
    await env.DB.batch([
      env.DB.prepare("DELETE FROM identities WHERE id = ?").bind(id),
      auditStatement(env, "identity.deleted", existing.handle, "including all keys", await actorHash(request, env)),
    ]);
    return json({ ok: true });
  }

  const addKeyMatch = path.match(/^\/api\/identities\/(\d+)\/keys$/);
  if (addKeyMatch && request.method === "POST") {
    const identityId = integerId(addKeyMatch[1]);
    const identity = await env.DB.prepare("SELECT handle FROM identities WHERE id = ?")
      .bind(identityId)
      .first<{ handle: string }>();
    if (!identity) throw new HttpError(404, "身份不存在");
    const data = await readJson(request);
    const publicKey = stringField(data, "publicKey", 16_384);
    const label = stringField(data, "label", 80, false);
    const addedAt = data.addedAt === "" ? new Date().toISOString().slice(0, 10) : stringField(data, "addedAt", 10);
    if (!validDate(addedAt)) {
      throw new HttpError(400, "添加日期无效");
    }
    let parsed: Awaited<ReturnType<typeof parsePublicKey>>;
    try {
      parsed = await parsePublicKey(publicKey);
    } catch (error) {
      throw new HttpError(400, error instanceof Error ? error.message : "公钥无效");
    }
    try {
      await env.DB.batch([
        env.DB.prepare(
          `INSERT INTO ssh_keys (identity_id, public_key, key_type, fingerprint, label, key_comment, added_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        ).bind(identityId, parsed.line, parsed.type, parsed.fingerprint, label, parsed.comment, addedAt),
        auditStatement(env, "key.created", identity.handle, parsed.fingerprint, await actorHash(request, env)),
      ]);
    } catch (error) {
      if (String(error).includes("UNIQUE")) throw new HttpError(409, "该身份已经拥有这把公钥");
      throw error;
    }
    return json({ ok: true, fingerprint: parsed.fingerprint }, 201);
  }

  const keyMatch = path.match(/^\/api\/keys\/(\d+)$/);
  if (keyMatch && request.method === "DELETE") {
    const id = integerId(keyMatch[1]);
    const key = await env.DB.prepare(
      "SELECT ssh_keys.fingerprint, identities.handle FROM ssh_keys JOIN identities ON identities.id = ssh_keys.identity_id WHERE ssh_keys.id = ?",
    )
      .bind(id)
      .first<{ fingerprint: string; handle: string }>();
    if (!key) throw new HttpError(404, "公钥不存在");
    await env.DB.batch([
      env.DB.prepare("DELETE FROM ssh_keys WHERE id = ?").bind(id),
      auditStatement(env, "key.deleted", key.handle, key.fingerprint, await actorHash(request, env)),
    ]);
    return json({ ok: true });
  }

  throw new HttpError(404, "API 路由不存在");
}

function rawKeys(keys: KeyRow[]): string {
  return keys.length ? `${keys.map((key) => key.public_key).join("\n")}\n` : "";
}

export function installer(identity: IdentityRow & { keys: KeyRow[] }, origin: string): string {
  const marker = `cloud-keyring/${identity.handle}`;
  const lines = rawKeys(identity.keys);
  const fingerprints = identity.keys.map((key) => `#   ${key.fingerprint}`).join("\n");
  return `#!/bin/sh
# Synchronize SSH public keys for @${identity.handle}.
# Source: ${origin}/${identity.handle}.keys
${fingerprints ? `# Expected fingerprints:\n${fingerprints}` : "# No public keys are currently published."}
set -eu
umask 077

SSH_DIR="$HOME/.ssh"
AUTHORIZED_KEYS="$SSH_DIR/authorized_keys"
BEGIN="# >>> ${marker} >>>"
END="# <<< ${marker} <<<"

mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"
touch "$AUTHORIZED_KEYS"
chmod 600 "$AUTHORIZED_KEYS"
cp "$AUTHORIZED_KEYS" "$AUTHORIZED_KEYS.keyring.bak"
chmod 600 "$AUTHORIZED_KEYS.keyring.bak"

KEYS_TMP=$(mktemp "$SSH_DIR/.keyring-keys.XXXXXX")
OUTPUT_TMP=$(mktemp "$SSH_DIR/.keyring-output.XXXXXX")
cleanup() { rm -f "$KEYS_TMP" "$OUTPUT_TMP"; }
trap cleanup EXIT HUP INT TERM

cat > "$KEYS_TMP" <<'CLOUD_KEYRING_KEYS'
${lines}CLOUD_KEYRING_KEYS

awk -v begin="$BEGIN" -v end="$END" '
  function key_id(line, fields, count, position) {
    count = split(line, fields, /[ \t]+/)
    for (position = 1; position < count; position++) {
      if (fields[position] ~ /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)$/) {
        return fields[position] " " fields[position + 1]
      }
    }
    return ""
  }
  reading_existing != 1 {
    id = key_id($0)
    if (id != "") managed[id] = 1
    next
  }
  $0 == begin { skip = 1; next }
  $0 == end { skip = 0; next }
  skip { next }
  {
    id = key_id($0)
    if (id == "" || !(id in managed)) print
  }
' "$KEYS_TMP" reading_existing=1 "$AUTHORIZED_KEYS" > "$OUTPUT_TMP"

{
  printf '%s\\n' "$BEGIN"
  cat "$KEYS_TMP"
  printf '%s\\n' "$END"
} >> "$OUTPUT_TMP"

mv "$OUTPUT_TMP" "$AUTHORIZED_KEYS"
chmod 600 "$AUTHORIZED_KEYS"
printf '%s\\n' '@${identity.handle}: synchronized ${identity.keys.length} SSH public key(s).'
`;
}

async function publicRoute(request: Request, env: Env, path: string): Promise<Response> {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return response("Method not allowed\n", 405, { allow: "GET, HEAD", "content-type": "text/plain; charset=utf-8" });
  }
  if (path === "/") return html(renderHome(siteName(env), await listPublicIdentities(env)));
  if (path === "/assets/app.css") {
    return response(CSS, 200, { "cache-control": "public, max-age=3600", "content-type": "text/css; charset=utf-8" });
  }
  if (path === "/assets/app.js") {
    return response(APP_JS, 200, { "cache-control": "public, max-age=3600", "content-type": "text/javascript; charset=utf-8" });
  }
  if (path === "/assets/admin.js") {
    return response(ADMIN_JS, 200, { "cache-control": "no-store", "content-type": "text/javascript; charset=utf-8" });
  }
  if (path === "/admin") {
    return html(
      (await hasValidSession(request, env.SESSION_SECRET))
        ? renderAdmin(siteName(env))
        : renderLogin(siteName(env)),
    );
  }

  const match = path.match(/^\/([a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?)(\.(?:keys|sh))?$/);
  if (!match) throw new HttpError(404, "页面不存在");
  const identity = await getPublicIdentity(env, match[1] ?? "");
  if (!identity) throw new HttpError(404, "身份不存在");
  if (match[2] === ".keys") return text(rawKeys(identity.keys));
  if (match[2] === ".sh") return text(installer(identity, new URL(request.url).origin), "text/x-shellscript; charset=utf-8");
  return html(renderIdentity(siteName(env), identity, new URL(request.url).origin));
}

export async function handleRequest(request: Request, env: Env): Promise<Response> {
  try {
    validateConfiguration(env);
    const path = new URL(request.url).pathname;
    if (path.startsWith("/api/")) return await adminApi(request, env, path);
    return await publicRoute(request, env, path);
  } catch (error) {
    if (error instanceof HttpError) {
      if (new URL(request.url).pathname.startsWith("/api/")) return json({ error: error.message }, error.status);
      return html(
        `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${error.status}</title><link rel="stylesheet" href="/assets/app.css"><main class="login-wrap"><section class="login"><span class="eyebrow">ERROR ${error.status}</span><h1>${error.status}</h1><p>${error.message}</p><a class="btn" href="/">返回目录</a></section></main></html>`,
        error.status,
      );
    }
    console.error("Unhandled request error", error);
    return json({ error: "服务器内部错误" }, 500);
  }
}
