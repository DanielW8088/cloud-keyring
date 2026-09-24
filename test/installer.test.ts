import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { installer } from "../src/app";
import type { InstallerSubject, KeyRow } from "../src/types";

const KEY_BODY =
  "AAAAC3NzaC1lZDI1NTE5AAAAIMW/LPEPctc8sALGAE7yeHsPfzAFthzpwmhxoX3gvOSU";
const MANAGED_KEY = `ssh-ed25519 ${KEY_BODY} managed-comment`;
const OTHER_KEY =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDb+e6Z7Y1I27Hd7d1LtgKQZyf/lqGEq/Gg5pQq2QgZx other-device";
const ALICE_UID = "0123456789abcdef0123456789abcdef";
const BOB_UID = "fedcba9876543210fedcba9876543210";

function key(publicKey: string): KeyRow {
  return {
    id: 1,
    identity_id: 1,
    public_key: publicKey,
    key_type: "ssh-ed25519",
    fingerprint: "SHA256:test",
    label: "",
    key_comment: "",
    added_at: "2026-08-07",
    created_at: "2026-08-07T00:00:00.000Z",
    updated_at: "2026-08-07T00:00:00.000Z",
  };
}

function subject(overrides: Partial<InstallerSubject> = {}): InstallerSubject {
  return {
    uid: ALICE_UID,
    handle: "alice",
    legacyHandles: ["alice"],
    published: true,
    keys: [key(MANAGED_KEY)],
    ...overrides,
  };
}

const bob = (keys: KeyRow[]) =>
  subject({ uid: BOB_UID, handle: "bob", legacyHandles: ["bob"], keys });

const aliceBlock = (...lines: string[]) =>
  [`# >>> cloud-keyring:id=${ALICE_UID} >>>`, "# @alice: managed by Cloud Keyring; edits inside this block are overwritten", ...lines, `# <<< cloud-keyring:id=${ALICE_UID} <<<`].join("\n");

const SHELLS = ["/bin/sh", "/bin/dash", "/bin/bash"].filter((shell) => existsSync(shell));
const homes: string[] = [];

afterEach(() => {
  for (const home of homes.splice(0)) rmSync(home, { recursive: true, force: true });
});

function createHome(initial: string): string {
  const home = mkdtempSync(join(tmpdir(), "cloud-keyring-installer-"));
  homes.push(home);
  mkdirSync(join(home, ".ssh"));
  writeFileSync(join(home, ".ssh", "authorized_keys"), initial);
  return home;
}

function run(home: string, target: InstallerSubject, shell = "/bin/sh") {
  const script = join(home, "installer.sh");
  writeFileSync(script, installer(target, "https://keys.example.test"));
  const result = spawnSync(shell, [script], { env: { PATH: process.env.PATH, HOME: home }, encoding: "utf8" });
  return {
    status: result.status,
    stderr: result.stderr,
    content: readFileSync(join(home, ".ssh", "authorized_keys"), "utf8"),
    backups: readdirSync(join(home, ".ssh")).filter((name) => name.startsWith("authorized_keys.keyring-")),
    leftovers: readdirSync(join(home, ".ssh")).filter((name) => name.startsWith(".keyring-")),
  };
}

describe.each(SHELLS)("installer under %s", (shell) => {
  const sync = (home: string, target: InstallerSubject) => run(home, target, shell);

  it("publishes a uid-marked block and replaces plain copies regardless of comments", () => {
    const home = createHome([`ssh-ed25519 ${KEY_BODY} old-comment`, OTHER_KEY, "# an unmanaged comment", ""].join("\n"));
    const result = sync(home, subject());

    expect(result.status).toBe(0);
    expect(result.content).toBe(`${OTHER_KEY}\n# an unmanaged comment\n${aliceBlock(MANAGED_KEY)}\n`);
    expect(result.leftovers).toEqual([]);
  });

  it("refuses to lift authorized_keys options and leaves the file untouched", () => {
    const restricted = [
      `restrict,command="/usr/local/bin/backup",from="192.0.2.5" ssh-ed25519 ${KEY_BODY} backup`,
      `command="/bin/check ssh-ed25519" ssh-ed25519 ${KEY_BODY} tricky`,
      `cert-authority ssh-ed25519 ${KEY_BODY} ca`,
    ];
    for (const line of restricted) {
      const initial = `${OTHER_KEY}\n${line}\n`;
      const home = createHome(initial);
      const result = sync(home, subject());

      expect(result.status).toBe(3);
      expect(result.content).toBe(initial);
      expect(result.stderr).toContain("line 2 grants a published key with authorized_keys options");
      expect(result.stderr).toContain("was not modified");
      expect(result.backups).toEqual([]);
      expect(result.leftovers).toEqual([]);
    }
  });

  it("ignores commented-out copies and unrelated option lines", () => {
    const initial = [`# ssh-ed25519 ${KEY_BODY} disabled`, `restrict ${OTHER_KEY}`, ""].join("\n");
    const result = sync(createHome(initial), subject());

    expect(result.status).toBe(0);
    expect(result.content).toBe(`${initial}${aliceBlock(MANAGED_KEY)}\n`);
  });

  it("never removes keys from blocks that belong to other identities", () => {
    const home = createHome("");
    sync(home, subject());
    const shared = sync(home, bob([key(MANAGED_KEY)]));
    expect(shared.content.match(new RegExp(KEY_BODY, "g"))).toHaveLength(2);

    const revoked = sync(home, bob([]));
    expect(revoked.content).toBe(`${aliceBlock(MANAGED_KEY)}\n`);
  });

  it("revokes keys left under a previous handle after a rename", () => {
    const legacy = `# >>> cloud-keyring/alice >>>\n${MANAGED_KEY}\n# <<< cloud-keyring/alice <<<\n`;
    const home = createHome(`${OTHER_KEY}\n${legacy}`);
    const result = sync(home, subject({ handle: "alicia", legacyHandles: ["alice", "alicia"], keys: [] }));

    expect(result.status).toBe(0);
    expect(result.content).toBe(`${OTHER_KEY}\n`);
  });

  it("keeps legacy blocks of other handles and reports them", () => {
    const legacy = `# >>> cloud-keyring/bob >>>\n${OTHER_KEY}\n# <<< cloud-keyring/bob <<<\n`;
    const result = sync(createHome(legacy), subject());

    expect(result.status).toBe(0);
    expect(result.content).toBe(`${legacy}${aliceBlock(MANAGED_KEY)}\n`);
    expect(result.stderr).toContain("kept legacy block cloud-keyring/bob");
  });

  it("revokes everything for hidden, deleted and pre-registry handles", () => {
    const home = createHome(`${OTHER_KEY}\n`);
    sync(home, subject());
    const hidden = sync(home, subject({ published: false, keys: [] }));
    expect(hidden.content).toBe(`${OTHER_KEY}\n`);
    expect(hidden.stderr).toBe("");

    const legacy = createHome(`# >>> cloud-keyring/carol >>>\n${MANAGED_KEY}\n# <<< cloud-keyring/carol <<<\n${OTHER_KEY}\n`);
    const cleanup = sync(legacy, { uid: null, handle: "carol", legacyHandles: ["carol"], published: false, keys: [] });
    expect(cleanup.content).toBe(`${OTHER_KEY}\n`);
  });

  it("aborts when its own block has no end marker", () => {
    const initial = `# >>> cloud-keyring:id=${ALICE_UID} >>>\n${OTHER_KEY}\n`;
    const result = sync(createHome(initial), subject());

    expect(result.status).toBe(2);
    expect(result.content).toBe(initial);
    expect(result.stderr).toContain("has no end marker");
  });

  it("is idempotent and only backs up files it changes, without overwriting older backups", () => {
    const home = createHome(`${OTHER_KEY}\n`);
    const first = sync(home, subject());
    const second = sync(home, subject());

    expect(second.content).toBe(first.content);
    expect(first.backups).toHaveLength(1);
    expect(second.backups).toEqual(first.backups);
    expect(readFileSync(join(home, ".ssh", first.backups[0] ?? ""), "utf8")).toBe(`${OTHER_KEY}\n`);

    for (let index = 0; index < 11; index++) sync(home, subject({ keys: index % 2 ? [key(MANAGED_KEY)] : [] }));
    expect(sync(home, subject()).backups).toHaveLength(10);
  });
});
