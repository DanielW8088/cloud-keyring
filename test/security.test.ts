import { describe, expect, it } from "vitest";
import {
  createSessionCookie,
  hasValidSession,
  isSameOrigin,
  passwordsEqual,
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
