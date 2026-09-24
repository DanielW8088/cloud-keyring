import { describe, expect, it } from "vitest";
import {
  createSessionCookie,
  hasValidSession,
  isSameOrigin,
  passwordsEqual,
  rateLimitSubject,
} from "../src/security";

const SECRET = "a-secure-test-secret-that-is-long-enough";

function requestWithCookie(cookie: string): Request {
  return new Request("https://keys.example.test/admin", { headers: { cookie } });
}

describe("session security", () => {
  it("accepts a valid signed cookie", async () => {
    const cookie = await createSessionCookie(SECRET, 1_000_000);
    expect(await hasValidSession(requestWithCookie(cookie.split(";")[0] ?? ""), SECRET, 1_000_001)).toBe(true);
  });

  it("rejects expired, tampered, and differently signed cookies", async () => {
    const cookie = (await createSessionCookie(SECRET, 1_000_000)).split(";")[0] ?? "";
    expect(await hasValidSession(requestWithCookie(cookie), SECRET, 40_000_000)).toBe(false);
    expect(await hasValidSession(requestWithCookie(`${cookie}x`), SECRET, 1_000_001)).toBe(false);
    expect(await hasValidSession(requestWithCookie(cookie), `${SECRET}-other`, 1_000_001)).toBe(false);
  });

  it("compares passwords and enforces exact request origins", async () => {
    expect(await passwordsEqual("correct horse battery staple", "correct horse battery staple")).toBe(true);
    expect(await passwordsEqual("correct horse battery staple", "wrong")).toBe(false);
    expect(
      isSameOrigin(
        new Request("https://keys.example.test/api/login", {
          headers: { origin: "https://keys.example.test" },
        }),
      ),
    ).toBe(true);
    expect(
      isSameOrigin(
        new Request("https://keys.example.test/api/login", {
          headers: { origin: "https://attacker.example" },
        }),
      ),
    ).toBe(false);
  });
});

describe("rateLimitSubject", () => {
  it("groups IPv6 addresses by /64 and keeps IPv4 addresses distinct", () => {
    expect(rateLimitSubject("203.0.113.7")).toBe("203.0.113.7");
    expect(rateLimitSubject("::ffff:203.0.113.7")).toBe("203.0.113.7");
    expect(rateLimitSubject("2001:db8:0:1::1")).toBe("2001:db8:0:1::/64");
    expect(rateLimitSubject("2001:0DB8:0000:0001:ffff:1:2:3")).toBe("2001:db8:0:1::/64");
    expect(rateLimitSubject("2001:db8::1")).toBe("2001:db8:0:0::/64");
    expect(rateLimitSubject("::1")).toBe("0:0:0:0::/64");
    expect(rateLimitSubject("64:ff9b::192.0.2.1")).toBe("64:ff9b:0:0::/64");
    expect(rateLimitSubject("not-an-address")).toBe("not-an-address");
  });
});
