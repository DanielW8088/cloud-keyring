import { describe, expect, it } from "vitest";
import { handleRequest } from "../src/app";
import { createSessionCookie } from "../src/security";
import type { Env } from "../src/types";
import { renderError } from "../src/views";
import { TestD1 } from "./d1";

const PASSWORD = "correct horse battery staple";
const SECRET = "a-secure-test-secret-that-is-long-enough";
const ORIGIN = "https://keys.example.test";
const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMW/LPEPctc8sALGAE7yeHsPfzAFthzpwmhxoX3gvOSU laptop";

function setup(extra: Partial<Env> = {}) {
  const db = new TestD1().applyMigrations();
  const env: Env = { DB: db.asD1(), ADMIN_PASSWORD: PASSWORD, SESSION_SECRET: SECRET, ...extra };
  return { db, env };
}

function login(env: Env, password: string, ip = "203.0.113.7") {
  return handleRequest(
    new Request(`${ORIGIN}/api/login`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: ORIGIN, "cf-connecting-ip": ip },
      body: JSON.stringify({ password }),
    }),
    env,
  );
}

async function admin(env: Env, method: string, path: string, body?: unknown) {
  const cookie = (await createSessionCookie(SECRET)).split(";")[0] ?? "";
  const response = await handleRequest(
    new Request(`${ORIGIN}${path}`, {
      method,
      headers: { "content-type": "application/json", origin: ORIGIN, cookie },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    }),
    env,
  );
  return { status: response.status, data: (await response.json()) as Record<string, unknown> };
}

const get = (env: Env, url: string) => handleRequest(new Request(url.startsWith("http") ? url : `${ORIGIN}${url}`), env);

const tally = (statuses: number[]) =>
  statuses.reduce<Record<number, number>>((counts, status) => ({ ...counts, [status]: (counts[status] ?? 0) + 1 }), {});

describe("login rate limiting", () => {
  it("lets only the allowed number of concurrent guesses reach the password check", async () => {
    const { env } = setup();
    const responses = await Promise.all(Array.from({ length: 30 }, (_, index) => login(env, `wrong guess ${index}`)));
    expect(tally(responses.map((response) => response.status))).toEqual({ 401: 5, 429: 25 });
  });

  it("escalates lockouts after they expire instead of resetting the counter", async () => {
    const { db, env } = setup();
    const expire = () => db.query("UPDATE auth_attempts SET blocked_until = unixepoch() - 1");
    const lockSeconds = () =>
      db.query<{ seconds: number }>("SELECT blocked_until - unixepoch() AS seconds FROM auth_attempts")[0]?.seconds ?? 0;

    for (let attempt = 0; attempt < 5; attempt++) expect((await login(env, "wrong password!!")).status).toBe(401);
    expect((await login(env, "wrong password!!")).status).toBe(429);
    expect(lockSeconds()).toBeGreaterThanOrEqual(29);

    for (const expected of [60, 120, 240]) {
      expire();
      expect((await login(env, "wrong password!!")).status).toBe(401);
      expect(lockSeconds()).toBeGreaterThanOrEqual(expected - 1);
      expect(lockSeconds()).toBeLessThanOrEqual(expected);
    }
  });

  it("treats an IPv6 /64 as one client", async () => {
    const { env } = setup();
    for (let host = 1; host <= 5; host++) expect((await login(env, "wrong password!!", `2001:db8:0:1::${host}`)).status).toBe(401);
    expect((await login(env, "wrong password!!", "2001:db8:0:1:ffff::9")).status).toBe(429);
    expect((await login(env, "wrong password!!", "2001:db8:0:2::1")).status).toBe(401);
  });

  it("clears the bucket after a successful login", async () => {
    const { db, env } = setup();
    for (let attempt = 0; attempt < 4; attempt++) await login(env, "wrong password!!");
    expect((await login(env, PASSWORD)).status).toBe(200);
    expect(db.query("SELECT * FROM auth_attempts")).toEqual([]);
  });

  it("keeps failed logins out of the management audit list", async () => {
    const { env } = setup();
    await admin(env, "POST", "/api/identities", { handle: "alice", name: "Alice", description: "", isPublic: true });
    for (let attempt = 0; attempt < 5; attempt++) await login(env, "wrong password!!", `198.51.100.${attempt}`);
    const { data } = await admin(env, "GET", "/api/admin/state");
    expect((data.audit as { action: string }[]).map((event) => event.action)).toEqual(["identity.created"]);
    expect(data.loginFailures24h).toBe(5);
  });
});

describe("request bodies", () => {
  it("stops reading an unauthenticated body once it exceeds the limit", async () => {
    const { env } = setup();
    let pulled = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (pulled >= 8 * 1024 * 1024) return controller.close();
        pulled += 65_536;
        controller.enqueue(new Uint8Array(65_536).fill(32));
      },
    });
    const response = await handleRequest(
      new Request(`${ORIGIN}/api/login`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: ORIGIN },
        body,
        duplex: "half",
      } as RequestInit),
      env,
    );
    expect(response.status).toBe(413);
    expect(pulled).toBeLessThan(4 * 65_536);
  });
});

describe("identity lifecycle", () => {
  async function createAlice(env: Env) {
    expect((await admin(env, "POST", "/api/identities", { handle: "alice", name: "Alice", description: "", isPublic: true })).status).toBe(201);
    const { data } = await admin(env, "GET", "/api/admin/state");
    const id = (data.identities as { id: number }[])[0]?.id;
    expect((await admin(env, "POST", `/api/identities/${id}/keys`, { publicKey: KEY, label: "", addedAt: "" })).status).toBe(201);
    return id;
  }

  const identity = (handle: string, isPublic = true) => ({ handle, name: "Alice", description: "", isPublic });

  it("keeps old handles pointing at the same identity after a rename", async () => {
    const { env } = setup();
    const id = await createAlice(env);
    expect((await admin(env, "PUT", `/api/identities/${id}`, identity("alicia"))).status).toBe(200);

    for (const handle of ["alice", "alicia"]) {
      const script = await (await get(env, `/${handle}.sh`)).text();
      expect(script).toContain("LEGACY_HANDLES='alice alicia'");
      expect(script).toContain(KEY);
    }
    expect((await get(env, "/alice.keys")).status).toBe(404);
  });

  it("never reassigns a handle to a different identity", async () => {
    const { env } = setup();
    const id = await createAlice(env);
    await admin(env, "PUT", `/api/identities/${id}`, identity("alicia"));
    expect((await admin(env, "POST", "/api/identities", identity("alice"))).status).toBe(409);

    await admin(env, "DELETE", `/api/identities/${id}`);
    expect((await admin(env, "POST", "/api/identities", identity("alicia"))).status).toBe(409);
    expect((await admin(env, "POST", "/api/identities", identity("bob"))).status).toBe(201);
  });

  it("allows an identity to return to one of its own previous handles", async () => {
    const { env } = setup();
    const id = await createAlice(env);
    await admin(env, "PUT", `/api/identities/${id}`, identity("alicia"));
    expect((await admin(env, "PUT", `/api/identities/${id}`, identity("alice"))).status).toBe(200);
  });

  it("serves a revocation script once an identity is hidden or deleted", async () => {
    const { env } = setup();
    const id = await createAlice(env);
    await admin(env, "PUT", `/api/identities/${id}`, identity("alice", false));
    const hidden = await (await get(env, "/alice.sh")).text();
    expect(hidden).toContain("no longer published");
    expect(hidden).not.toContain(KEY);
    expect((await get(env, "/alice.keys")).status).toBe(404);

    await admin(env, "DELETE", `/api/identities/${id}`);
    const deleted = await get(env, "/alice.sh");
    expect(deleted.status).toBe(200);
    expect(await deleted.text()).toMatch(/IDENTITY_UID='[0-9a-f]{32}'/);
    expect((await get(env, "/never-used.sh")).status).toBe(404);
  });
});

describe("migration 0002", () => {
  it("reserves handles retired before the registry existed as cleanup-only", async () => {
    const db = new TestD1().applyMigrations((name) => name.startsWith("0001"));
    db.query("INSERT INTO identities (handle, name) VALUES ('dave', 'Dave')");
    db.query(
      `INSERT INTO audit_events (action, target, detail, actor_hash) VALUES
       ('identity.created', 'carol', 'Carol', 'x'),
       ('identity.updated', 'dave', 'formerly carol', 'x'),
       ('identity.created', 'erin', 'Erin', 'x'),
       ('identity.deleted', 'erin', 'including all keys', 'x'),
       ('login.failed', 'admin', 'failure 1', 'x')`,
    );
    db.applyMigrations((name) => name.startsWith("0002"));

    const handles = db.query<{ handle: string; uid: string | null }>(
      "SELECT handle, identity_uid AS uid FROM identity_handles ORDER BY handle",
    );
    expect(handles.map(({ handle, uid }) => [handle, uid === null ? null : "uid"])).toEqual([
      ["carol", null],
      ["dave", "uid"],
      ["erin", null],
    ]);

    const env: Env = { DB: db.asD1(), ADMIN_PASSWORD: PASSWORD, SESSION_SECRET: SECRET };
    const script = await (await get(env, "/carol.sh")).text();
    expect(script).toContain("IDENTITY_UID=''");
    expect(script).toContain("LEGACY_HANDLES='carol'");
  });
});

describe("hostnames", () => {
  it("does not serve the admin surface on platform hostnames", async () => {
    const { env } = setup();
    expect((await get(env, "https://cloud-keyring.pages.dev/admin")).status).toBe(404);
    expect((await get(env, "https://abc123.cloud-keyring.pages.dev/api/admin/state")).status).toBe(404);
    expect((await get(env, "https://keyring.example.workers.dev/admin")).status).toBe(404);
    expect((await get(env, "https://cloud-keyring.pages.dev/")).status).toBe(200);
  });

  it("confines everything to CANONICAL_ORIGIN when configured", async () => {
    const { env } = setup({ CANONICAL_ORIGIN: "https://keys.example.com" });
    const redirect = await get(env, "https://abc123.cloud-keyring.pages.dev/alice.sh?x=1");
    expect(redirect.status).toBe(308);
    expect(redirect.headers.get("location")).toBe("https://keys.example.com/alice.sh?x=1");
    expect((await get(env, "https://other.example.com/admin")).status).toBe(404);
    expect((await get(env, "https://keys.example.com/admin")).status).toBe(200);
  });

  it("rejects a CANONICAL_ORIGIN with a path", async () => {
    const { env } = setup({ CANONICAL_ORIGIN: "https://keys.example.com/keys" });
    expect((await get(env, "https://keys.example.com/")).status).toBe(500);
  });
});

describe("error pages", () => {
  it("escapes the message", () => {
    expect(renderError(404, "<script>alert(1)</script>")).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });
});
