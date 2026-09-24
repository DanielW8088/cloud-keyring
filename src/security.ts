const encoder = new TextEncoder();
const SESSION_COOKIE = "keyring_session";
const SESSION_TTL_SECONDS = 8 * 60 * 60;

function toBase64Url(bytes: Uint8Array): string {
  let value = "";
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  try {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
    return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

async function hmac(secret: string, value: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(value)));
}

export function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  let difference = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index++) {
    difference |= (left[index % left.length] ?? 0) ^ (right[index % right.length] ?? 0);
  }
  return difference === 0;
}

export async function passwordsEqual(actual: string, expected: string): Promise<boolean> {
  const [actualHash, expectedHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(actual)),
    crypto.subtle.digest("SHA-256", encoder.encode(expected)),
  ]);
  return constantTimeEqual(new Uint8Array(actualHash), new Uint8Array(expectedHash));
}

export async function createSessionCookie(secret: string, now = Date.now()): Promise<string> {
  const payload = toBase64Url(
    encoder.encode(
      JSON.stringify({
        version: 1,
        expires: Math.floor(now / 1000) + SESSION_TTL_SECONDS,
        nonce: crypto.randomUUID(),
      }),
    ),
  );
  const signature = toBase64Url(await hmac(secret, payload));
  return `${SESSION_COOKIE}=${payload}.${signature}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}`;
}

export function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

function readCookie(request: Request, name: string): string | null {
  const cookies = request.headers.get("cookie")?.split(";") ?? [];
  for (const cookie of cookies) {
    const separator = cookie.indexOf("=");
    if (separator < 0) continue;
    if (cookie.slice(0, separator).trim() === name) return cookie.slice(separator + 1).trim();
  }
  return null;
}

export async function hasValidSession(
  request: Request,
  secret: string,
  now = Date.now(),
): Promise<boolean> {
  const value = readCookie(request, SESSION_COOKIE);
  if (!value) return false;
  const [payload, suppliedSignature, extra] = value.split(".");
  if (!payload || !suppliedSignature || extra) return false;
  const signature = fromBase64Url(suppliedSignature);
  if (!signature || !constantTimeEqual(signature, await hmac(secret, payload))) return false;
  const bytes = fromBase64Url(payload);
  if (!bytes) return false;
  try {
    const data = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
    return (
      data.version === 1 &&
      typeof data.expires === "number" &&
      data.expires > Math.floor(now / 1000) &&
      typeof data.nonce === "string"
    );
  } catch {
    return false;
  }
}

export function isSameOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  return origin !== null && origin === new URL(request.url).origin;
}

export async function privacyHash(secret: string, value: string): Promise<string> {
  return toBase64Url(await hmac(secret, `actor:${value}`)).slice(0, 22);
}

function ipv6Prefix64(address: string): string | null {
  const halves = address.toLowerCase().split("%")[0]?.split("::") ?? [];
  if (halves.length < 1 || halves.length > 2) return null;
  const groups = (part: string | undefined) => (part ? part.split(":") : []);
  const head = groups(halves[0]);
  const tail = groups(halves[1]);
  // An embedded IPv4 suffix occupies the last 32 bits, outside the /64 prefix.
  const last = tail.length ? tail : head;
  if (last.at(-1)?.includes(".")) last.splice(-1, 1, "0", "0");
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
  const all = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  if (!all.every((group) => /^[0-9a-f]{1,4}$/.test(group))) return null;
  return `${all.slice(0, 4).map((group) => parseInt(group, 16).toString(16)).join(":")}::/64`;
}

/**
 * Groups client addresses for rate limiting. IPv6 clients usually control a
 * whole /64, so limiting individual addresses would let them rotate freely.
 */
export function rateLimitSubject(ip: string): string {
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  if (mapped?.[1]) return mapped[1];
  if (!ip.includes(":")) return ip;
  return ipv6Prefix64(ip) ?? ip;
}
