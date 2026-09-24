import { ADMIN_JS, APP_JS, CSS } from "./assets";
import {
  auditStatement,
  getInstallerSubject,
  getPublicIdentity,
  listAllIdentities,
  listAuditEvents,
  listPublicIdentities,
} from "./db";
import {
  clearSessionCookie,
  createSessionCookie,
  hasValidSession,
  isSameOrigin,
  passwordsEqual,
  privacyHash,
  rateLimitSubject,
} from "./security";
import { parsePublicKey } from "./ssh";
import type { Env, InstallerSubject, KeyRow } from "./types";
import { renderAdmin, renderError, renderHome, renderIdentity, renderLogin } from "./views";

const SECURITY_HEADERS: Record<string, string> = {
  "content-security-policy":
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  "referrer-policy": "no-referrer",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
};

const MAX_JSON_BYTES = 20_000;
const LOGIN_FREE_ATTEMPTS = 5;
const LOGIN_BASE_LOCK_SECONDS = 30;
const LOGIN_MAX_LOCK_SECONDS = 15 * 60;
const LOGIN_FAILURE_WINDOW_SECONDS = 24 * 60 * 60;
// Hostnames Cloudflare assigns to every deployment. Access policies bound to a
// custom domain do not cover them, so the admin surface is never served there.
const PLATFORM_HOST_SUFFIXES = [".pages.dev", ".workers.dev"];
const HANDLE_TAKEN = "该 Handle 已被使用或保留";

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

function canonicalOrigin(env: Env): string | null {
  const value = env.CANONICAL_ORIGIN?.trim();
  return value ? new URL(value).origin : null;
}

function validateConfiguration(env: Env): void {
  if (!env.ADMIN_PASSWORD || env.ADMIN_PASSWORD.length < 16) {
    throw new Error("ADMIN_PASSWORD must contain at least 16 characters");
  }
  if (!env.SESSION_SECRET || env.SESSION_SECRET.length < 32) {
    throw new Error("SESSION_SECRET must contain at least 32 characters");
  }
  const canonical = env.CANONICAL_ORIGIN?.trim();
  if (canonical) {
    let url: URL | null = null;
    try {
      url = new URL(canonical);
    } catch {
      // Reported below.
    }
    if (!url || url.protocol !== "https:" || url.pathname !== "/" || url.search || url.hash || url.username) {
      throw new Error("CANONICAL_ORIGIN must be an https:// origin without a path");
    }
  }
}

/** Reads at most `limit` bytes, cancelling the stream as soon as it is exceeded. */
async function readBody(request: Request, limit: number): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  if (request.body) {
    const reader = request.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > limit) {
        await reader.cancel().catch(() => {});
        throw new HttpError(413, "请求内容过大");
      }
      chunks.push(value);
    }
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

async function readJson(request: Request): Promise<Record<string, unknown>> {
  const length = Number(request.headers.get("content-length") ?? 0);
  if (length > MAX_JSON_BYTES) throw new HttpError(413, "请求内容过大");
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
    throw new HttpError(415, "请求必须使用 application/json");
  }
  const body = await readBody(request, MAX_JSON_BYTES);
  try {
    const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error();
    return value as Record<string, unknown>;
  } catch {
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

/**
 * Consumes one login attempt before the password is checked. The check and the
 * increment are a single UPDATE, so concurrent requests cannot share a budget.
 * Returns the attempt number, or null while the bucket is locked.
 */
async function reserveLoginAttempt(env: Env, bucket: string, now: number): Promise<number | null> {
  const failures = "(CASE WHEN updated_at <= ?2 - ?3 THEN 1 ELSE failures + 1 END)";
  const [, update] = await env.DB.batch([
    env.DB.prepare(
      "INSERT OR IGNORE INTO auth_attempts (bucket, failures, blocked_until, updated_at) VALUES (?1, 0, 0, ?2)",
    ).bind(bucket, now),
    env.DB.prepare(
      `UPDATE auth_attempts SET
         failures = ${failures},
         blocked_until = CASE WHEN ${failures} >= ?4 THEN ?2 + min(?6, ?5 << min(${failures} - ?4, 5)) ELSE 0 END,
         updated_at = ?2
       WHERE bucket = ?1 AND blocked_until <= ?2
       RETURNING failures`,
    ).bind(
      bucket,
      now,
      LOGIN_FAILURE_WINDOW_SECONDS,
      LOGIN_FREE_ATTEMPTS,
      LOGIN_BASE_LOCK_SECONDS,
      LOGIN_MAX_LOCK_SECONDS,
    ),
  ]);
  const row = update?.results?.[0] as { failures: number } | undefined;
  return row ? row.failures : null;
}

async function login(request: Request, env: Env): Promise<Response> {
  if (!isSameOrigin(request)) throw new HttpError(403, "拒绝跨站请求");
  const data = await readJson(request);
  const password = stringField(data, "password", 1024);
  const bucket = await privacyHash(env.SESSION_SECRET, `login:${rateLimitSubject(actorIp(request))}`);
  const now = Math.floor(Date.now() / 1000);
  const attempt = await reserveLoginAttempt(env, bucket, now);
  if (attempt === null) throw new HttpError(429, "登录尝试过多，请稍后重试");

  if (!(await passwordsEqual(password, env.ADMIN_PASSWORD))) {
    await auditStatement(env, "login.failed", "admin", `attempt ${attempt}`, await actorHash(request, env)).run();
    throw new HttpError(401, "口令错误");
  }

  await env.DB.batch([
    env.DB.prepare("DELETE FROM auth_attempts WHERE bucket = ?").bind(bucket),
    env.DB.prepare("DELETE FROM auth_attempts WHERE updated_at <= ? AND blocked_until <= ?").bind(
      now - LOGIN_FAILURE_WINDOW_SECONDS,
      now,
    ),
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
    return json({ identities, audit: audit.events, loginFailures24h: audit.loginFailures24h });
  }
  if (path === "/api/identities" && request.method === "POST") {
    const fields = identityFields(await readJson(request));
    const uid = crypto.randomUUID().replaceAll("-", "");
    const actor = await actorHash(request, env);
    try {
      // The handle registry row reserves the handle for this identity forever.
      await env.DB.batch([
        env.DB.prepare("INSERT INTO identity_handles (handle, identity_uid) VALUES (?, ?)").bind(fields.handle, uid),
        env.DB.prepare(
          "INSERT INTO identities (uid, handle, name, description, is_public) VALUES (?, ?, ?, ?, ?)",
        ).bind(uid, fields.handle, fields.name, fields.description, fields.isPublic),
        auditStatement(env, "identity.created", fields.handle, fields.name, actor),
      ]);
    } catch (error) {
      if (String(error).includes("UNIQUE")) throw new HttpError(409, HANDLE_TAKEN);
      throw error;
    }
    return json({ ok: true }, 201);
  }

  const identityMatch = path.match(/^\/api\/identities\/(\d+)$/);
  if (identityMatch && request.method === "PUT") {
    const id = integerId(identityMatch[1]);
    const fields = identityFields(await readJson(request));
    const existing = await env.DB.prepare("SELECT uid, handle FROM identities WHERE id = ?")
      .bind(id)
      .first<{ uid: string; handle: string }>();
    if (!existing) throw new HttpError(404, "身份不存在");
    const owner = await env.DB.prepare("SELECT identity_uid FROM identity_handles WHERE handle = ?")
      .bind(fields.handle)
      .first<{ identity_uid: string | null }>();
    if (owner && owner.identity_uid !== existing.uid) throw new HttpError(409, HANDLE_TAKEN);
    try {
      await env.DB.batch([
        env.DB.prepare("INSERT OR IGNORE INTO identity_handles (handle, identity_uid) VALUES (?, ?)").bind(
          fields.handle,
          existing.uid,
        ),
        env.DB.prepare(
          "UPDATE identities SET handle = ?, name = ?, description = ?, is_public = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
        ).bind(fields.handle, fields.name, fields.description, fields.isPublic, id),
        auditStatement(env, "identity.updated", fields.handle, `formerly ${existing.handle}`, await actorHash(request, env)),
      ]);
    } catch (error) {
      if (String(error).includes("UNIQUE")) throw new HttpError(409, HANDLE_TAKEN);
      throw error;
    }
    return json({ ok: true });
  }
  if (identityMatch && request.method === "DELETE") {
    const id = integerId(identityMatch[1]);
    const existing = await env.DB.prepare("SELECT handle FROM identities WHERE id = ?").bind(id).first<{ handle: string }>();
    if (!existing) throw new HttpError(404, "身份不存在");
    // identity_handles rows are kept: the handle stays reserved and its
    // installer URL keeps serving a revocation script.
    await env.DB.batch([
      env.DB.prepare("DELETE FROM identities WHERE id = ?").bind(id),
      auditStatement(env, "identity.deleted", existing.handle, "including all keys; handle stays reserved", await actorHash(request, env)),
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

/**
 * Generates the authorized_keys synchronizer for one identity.
 *
 * The managed block is marked with the identity's immutable uid. Blocks of
 * other identities are never touched. A published key that already appears
 * outside every block with authorized_keys options (restrict, command=,
 * from=, ...) aborts the run without changes: publishing an unrestricted copy
 * would lift those restrictions.
 */
export function installer(subject: InstallerSubject, origin: string): string {
  const { handle, keys, published } = subject;
  const lines = published ? rawKeys(keys) : "";
  const fingerprints = keys.map((key) => `#   ${key.fingerprint}`).join("\n");
  const summary = !published
    ? "# This identity is no longer published. Running this script revokes its managed keys."
    : fingerprints
      ? `# Expected fingerprints:\n${fingerprints}`
      : "# No public keys are currently published.";
  const outcome = published
    ? `@${handle}: synchronized ${keys.length} SSH public key(s).`
    : `@${handle}: not published; removed its managed SSH public keys.`;
  return `#!/bin/sh
# Synchronize SSH public keys for @${handle}.
# Source: ${origin}/${handle}.sh
${summary}
set -eu
umask 077

SSH_DIR="$HOME/.ssh"
AUTHORIZED_KEYS="$SSH_DIR/authorized_keys"
IDENTITY_UID='${subject.uid ?? ""}'
LEGACY_HANDLES='${subject.legacyHandles.join(" ")}'

mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"
touch "$AUTHORIZED_KEYS"
chmod 600 "$AUTHORIZED_KEYS"

KEYS_TMP=$(mktemp "$SSH_DIR/.keyring-keys.XXXXXX")
OUTPUT_TMP=$(mktemp "$SSH_DIR/.keyring-output.XXXXXX")
REPORT_TMP=$(mktemp "$SSH_DIR/.keyring-report.XXXXXX")
cleanup() { rm -f "$KEYS_TMP" "$OUTPUT_TMP" "$REPORT_TMP"; }
trap cleanup EXIT HUP INT TERM

cat > "$KEYS_TMP" <<'CLOUD_KEYRING_KEYS'
${lines}CLOUD_KEYRING_KEYS

STATUS=0
awk -v uid="$IDENTITY_UID" -v legacy="$LEGACY_HANDLES" -v report="$REPORT_TMP" '
  function algorithm(value) {
    return value ~ /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\\.com|sk-ecdsa-sha2-nistp256@openssh\\.com)$/
  }
  function key_fields(line, fields, copy) {
    copy = line
    sub(/^[ \\t]+/, "", copy)
    return split(copy, fields, /[ \\t]+/)
  }
  BEGIN {
    count = split(legacy, names, " ")
    for (i = 1; i <= count; i++) own["cloud-keyring/" names[i]] = 1
    if (uid != "") own["cloud-keyring:id=" uid] = 1
  }
  reading_existing != 1 {
    if (key_fields($0, fields) >= 2 && algorithm(fields[1])) managed[fields[1] " " fields[2]] = 1
    next
  }
  block == "" && $0 ~ /^# >>> cloud-keyring(:|\\/)[^ ]+ >>>$/ {
    block = $3
    mine = (block in own)
    if (!mine) {
      if (substr(block, 14, 1) == "/") print "notice: kept legacy block " block "; run the installer of that handle to migrate it" > report
      print
    }
    next
  }
  block != "" {
    if (!mine) print
    if ($0 == "# <<< " block " <<<") block = ""
    next
  }
  {
    count = key_fields($0, fields)
    if (count < 2 || fields[1] ~ /^#/) { print; next }
    if (algorithm(fields[1])) {
      # A plain copy of a published key is replaced by the managed block.
      if ((fields[1] " " fields[2]) in managed) next
      print
      next
    }
    for (position = 2; position < count; position++) {
      if (algorithm(fields[position]) && ((fields[position] " " fields[position + 1]) in managed)) {
        print "conflict: line " FNR " grants a published key with authorized_keys options" > report
        conflicts++
        break
      }
    }
    print
  }
  END {
    if (block != "") {
      print "error: block " block " has no end marker" > report
      exit 2
    }
    if (conflicts) exit 3
  }
' "$KEYS_TMP" reading_existing=1 "$AUTHORIZED_KEYS" > "$OUTPUT_TMP" || STATUS=$?

if [ -s "$REPORT_TMP" ]; then
  sed 's/^/cloud-keyring: /' "$REPORT_TMP" >&2
fi
if [ "$STATUS" -ne 0 ]; then
  if [ "$STATUS" -eq 3 ]; then
    printf '%s\\n' "cloud-keyring: publishing an unrestricted copy would lift the options on those lines." >&2
    printf '%s\\n' "cloud-keyring: remove the options entry or stop publishing that key, then run this script again." >&2
  fi
  printf '%s\\n' "cloud-keyring: $AUTHORIZED_KEYS was not modified." >&2
  exit "$STATUS"
fi

if [ -n "$IDENTITY_UID" ] && [ -s "$KEYS_TMP" ]; then
  {
    printf '%s\\n' "# >>> cloud-keyring:id=$IDENTITY_UID >>>"
    printf '%s\\n' '# @${handle}: managed by Cloud Keyring; edits inside this block are overwritten'
    cat "$KEYS_TMP"
    printf '%s\\n' "# <<< cloud-keyring:id=$IDENTITY_UID <<<"
  } >> "$OUTPUT_TMP"
fi

if ! cmp -s "$OUTPUT_TMP" "$AUTHORIZED_KEYS"; then
  BACKUP=$(mktemp "$AUTHORIZED_KEYS.keyring-$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")
  cat "$AUTHORIZED_KEYS" > "$BACKUP"
  chmod 600 "$OUTPUT_TMP"
  mv "$OUTPUT_TMP" "$AUTHORIZED_KEYS"
  # Keep the ten most recent backups.
  ls -1 "$AUTHORIZED_KEYS".keyring-* 2>/dev/null | sort -r | awk 'NR > 10' | while IFS= read -r old; do rm -f "$old"; done
fi
printf '%s\\n' '${outcome}'
`;
}

async function publicRoute(request: Request, env: Env, path: string, origin: string): Promise<Response> {
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
  if (match[2] === ".sh") {
    const subject = await getInstallerSubject(env, match[1] ?? "");
    if (!subject) throw new HttpError(404, "身份不存在");
    return text(installer(subject, origin), "text/x-shellscript; charset=utf-8");
  }
  const identity = await getPublicIdentity(env, match[1] ?? "");
  if (!identity) throw new HttpError(404, "身份不存在");
  if (match[2] === ".keys") return text(rawKeys(identity.keys));
  return html(renderIdentity(siteName(env), identity, origin));
}

export async function handleRequest(request: Request, env: Env): Promise<Response> {
  try {
    validateConfiguration(env);
    const url = new URL(request.url);
    const path = url.pathname;
    const canonical = canonicalOrigin(env);
    const offCanonical = canonical
      ? url.origin !== canonical
      : PLATFORM_HOST_SUFFIXES.some((suffix) => url.hostname.endsWith(suffix));
    if (offCanonical) {
      if (path === "/admin" || path.startsWith("/api/")) throw new HttpError(404, "页面不存在");
      if (canonical && (request.method === "GET" || request.method === "HEAD")) {
        return response(null, 308, { "cache-control": "no-store", location: `${canonical}${path}${url.search}` });
      }
    }
    if (path.startsWith("/api/")) return await adminApi(request, env, path);
    return await publicRoute(request, env, path, canonical ?? url.origin);
  } catch (error) {
    if (error instanceof HttpError) {
      if (new URL(request.url).pathname.startsWith("/api/")) return json({ error: error.message }, error.status);
      return html(renderError(error.status, error.message), error.status);
    }
    console.error("Unhandled request error", error);
    return json({ error: "服务器内部错误" }, 500);
  }
}
