import { describe, expect, it } from "vitest";
import { parsePublicKey } from "../src/ssh";

const ED25519_KEY =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMW/LPEPctc8sALGAE7yeHsPfzAFthzpwmhxoX3gvOSU test-device";

describe("parsePublicKey", () => {
  it("parses and fingerprints a valid ED25519 key", async () => {
    const parsed = await parsePublicKey(ED25519_KEY);

    expect(parsed.type).toBe("ssh-ed25519");
    expect(parsed.comment).toBe("test-device");
    expect(parsed.line).toBe(ED25519_KEY);
    expect(parsed.fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
  });

  it("allows a descriptive comment containing spaces", async () => {
    const parsed = await parsePublicKey(ED25519_KEY.replace("test-device", "work laptop 2026"));
    expect(parsed.comment).toBe("work laptop 2026");
  });

  it("rejects private key material and multiline input", async () => {
    await expect(parsePublicKey("-----BEGIN OPENSSH PRIVATE KEY-----")).rejects.toThrow(
      "supported OpenSSH public key",
    );
    await expect(parsePublicKey(`${ED25519_KEY}\n${ED25519_KEY}`)).rejects.toThrow(
      "exactly one",
    );
    await expect(parsePublicKey(`${ED25519_KEY}\u001b[31m`)).rejects.toThrow("exactly one");
  });

  it("rejects a claimed type that differs from the encoded blob", async () => {
    await expect(parsePublicKey(ED25519_KEY.replace("ssh-ed25519", "ssh-rsa"))).rejects.toThrow(
      "does not match",
    );
  });

  it("rejects authorized_keys options and unsupported DSA keys", async () => {
    await expect(parsePublicKey(`from=\"10.0.0.1\" ${ED25519_KEY}`)).rejects.toThrow(
      "supported OpenSSH public key",
    );
    await expect(parsePublicKey(ED25519_KEY.replace("ssh-ed25519", "ssh-dss"))).rejects.toThrow(
      "supported OpenSSH public key",
    );
  });

  it("rejects Object.prototype property names as key types", async () => {
    for (const type of ["toString", "__proto__", "constructor", "hasOwnProperty"]) {
      const field = Buffer.alloc(4 + type.length);
      field.writeUInt32BE(type.length, 0);
      field.write(type, 4);
      await expect(parsePublicKey(`${type} ${field.toString("base64")} x`)).rejects.toThrow(
        "supported OpenSSH public key",
      );
    }
  });
});
