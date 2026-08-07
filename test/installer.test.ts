import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { installer } from "../src/app";
import type { IdentityRow, KeyRow } from "../src/types";

const KEY_BODY =
  "AAAAC3NzaC1lZDI1NTE5AAAAIMW/LPEPctc8sALGAE7yeHsPfzAFthzpwmhxoX3gvOSU";
const MANAGED_KEY = `ssh-ed25519 ${KEY_BODY} managed-comment`;
const OTHER_KEY =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDb+e6Z7Y1I27Hd7d1LtgKQZyf/lqGEq/Gg5pQq2QgZx other-device";

const identity: IdentityRow & { keys: KeyRow[] } = {
  id: 1,
  handle: "alice",
  name: "Alice",
  description: "",
  is_public: 1,
  created_at: "2026-08-07T00:00:00.000Z",
  updated_at: "2026-08-07T00:00:00.000Z",
  keys: [
    {
      id: 1,
      identity_id: 1,
      public_key: MANAGED_KEY,
      key_type: "ssh-ed25519",
      fingerprint: "SHA256:test",
      label: "managed",
      key_comment: "managed-comment",
      added_at: "2026-08-07",
      created_at: "2026-08-07T00:00:00.000Z",
      updated_at: "2026-08-07T00:00:00.000Z",
    },
  ],
};

const homes: string[] = [];

afterEach(() => {
  for (const home of homes.splice(0)) rmSync(home, { recursive: true, force: true });
});

function runInstaller(keys: KeyRow[], initial: string): string {
  const home = mkdtempSync(join(tmpdir(), "cloud-keyring-installer-"));
  homes.push(home);
  const sshDirectory = join(home, ".ssh");
  const authorizedKeys = join(sshDirectory, "authorized_keys");
  const script = join(home, "installer.sh");
  mkdirSync(sshDirectory);
  writeFileSync(authorizedKeys, initial);
  writeFileSync(script, installer({ ...identity, keys }, "https://keys.example.test"));
  execFileSync("/bin/sh", [script], { env: { ...process.env, HOME: home } });
  return readFileSync(authorizedKeys, "utf8");
}

describe("installer", () => {
  it("deduplicates by algorithm and Base64 body despite different comments or options", () => {
    const initial = [
      `ssh-ed25519 ${KEY_BODY} old-comment`,
      `restrict ssh-ed25519 ${KEY_BODY} option-comment`,
      OTHER_KEY,
      "# an unmanaged comment",
      "",
    ].join("\n");

    const result = runInstaller(identity.keys, initial);

    expect(result.match(new RegExp(KEY_BODY, "g"))).toHaveLength(1);
    expect(result).toContain(MANAGED_KEY);
    expect(result).toContain(OTHER_KEY);
    expect(result).toContain("# an unmanaged comment");
    expect(result).not.toContain("old-comment");
    expect(result).not.toContain("option-comment");
  });

  it("is idempotent", () => {
    const first = runInstaller(identity.keys, `${OTHER_KEY}\n`);
    const second = runInstaller(identity.keys, first);

    expect(second).toBe(first);
  });

  it("removes the managed block on full revocation without deleting unmanaged entries", () => {
    const installed = runInstaller(identity.keys, `${OTHER_KEY}\n`);
    const revoked = runInstaller([], installed);

    expect(revoked).toContain(OTHER_KEY);
    expect(revoked).not.toContain(KEY_BODY);
    expect(revoked).toContain("# >>> cloud-keyring/alice >>>\n# <<< cloud-keyring/alice <<<");
  });
});
