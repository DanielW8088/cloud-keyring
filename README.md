# Cloud Keyring

[English](README.md) | [简体中文](README.zh-CN.md)

A secure, self-hosted SSH **public key** directory built for Cloudflare Workers, Pages Functions, and D1.

Cloud Keyring provides a protected web console for managing identities and public keys, human-readable identity pages, raw `.keys` endpoints, and idempotent `authorized_keys` synchronization scripts.

> Cloud Keyring never needs or accepts SSH private keys. If a private key is ever submitted to a website, database, or Git repository, treat it as compromised and rotate it immediately.

## Features

- Create, edit, hide, and delete identities from a web console
- Add, validate, publish, and revoke SSH public keys
- Support ED25519, RSA 2048+, NIST ECDSA, and OpenSSH FIDO2 public keys
- Validate the SSH wire format and compute OpenSSH-compatible `SHA256:` fingerprints
- Serve responsive identity and fingerprint pages at `/<handle>`
- Serve canonical `authorized_keys` lines at `/<handle>.keys`
- Serve idempotent synchronization scripts at `/<handle>.sh`
- Store identities, public keys, login throttles, and audit events in D1
- Deploy the same application core to Cloudflare Workers or Pages Functions
- Enforce strict security headers, origin checks, signed sessions, and no-store revocation semantics

## Endpoints

| Endpoint | Purpose |
| --- | --- |
| `/` | Public identity directory |
| `/<handle>` | Identity page with key metadata and fingerprints |
| `/<handle>.keys` | Raw SSH public keys, one key per line |
| `/<handle>.sh` | Idempotent `authorized_keys` synchronization script |
| `/admin` | Password-protected management console |
| `/api/*` | Authenticated management API |

## Installer Behavior

Each identity owns one block in `authorized_keys`. The block is marked with the identity's immutable ID instead of its handle, so renaming an identity does not orphan its keys:

```text
# >>> cloud-keyring:id=3f2a...c9 >>>
# @alice: managed by Cloud Keyring; edits inside this block are overwritten
ssh-ed25519 AAAA... alice-laptop
# <<< cloud-keyring:id=3f2a...c9 <<<
```

The installer:

- Replaces only its own block. Blocks of other identities are never modified, so revoking a key from one identity does not remove a copy published by another.
- Removes plain copies of a published key outside all blocks. Keys are compared by `algorithm + Base64 public key body`, ignoring comments and spacing.
- **Refuses to run** when a published key already appears outside the blocks with `authorized_keys` options such as `restrict`, `command=`, or `from=`, or as a `cert-authority` line. An unrestricted copy would lift those restrictions. The file is left untouched: remove the options line or stop publishing that key, then run the installer again.
- Aborts without changes if its own block has no end marker.
- Migrates blocks written by earlier versions (`# >>> cloud-keyring/<handle> >>>`) for every handle the identity has used. It keeps legacy blocks that belong to other handles and reports them.
- Writes only when the result differs. Before each change it saves a timestamped backup, `~/.ssh/authorized_keys.keyring-<UTC time>.XXXXXX`, and keeps the ten most recent.

Handles are permanent. Every handle an identity has used keeps resolving to that identity's installer and is never assigned to another identity. When an identity is hidden or deleted, its `.sh` endpoint serves a revocation script that removes its block, so hosts that sync on a schedule converge. Handles retired before handle tracking existed serve a script that removes their legacy block.

## Security Model

- D1 stores public keys and display metadata only. It does not store private keys.
- `ADMIN_PASSWORD` and `SESSION_SECRET` are Cloudflare Secrets, not source-controlled variables.
- Sessions use HMAC signatures and `HttpOnly; Secure; SameSite=Strict` cookies with an eight-hour lifetime.
- Every management write requires a valid session and an exact same-origin `Origin` header.
- Each login attempt is recorded atomically in D1 before the password check, per client IPv4 address or IPv6 /64, stored as an HMAC hash. After five attempts the client is locked out for 30 seconds, doubling with each further failure up to 15 minutes. The counter resets after a successful login or 24 hours without attempts.
- Request bodies are read as a stream and cancelled once they exceed 20 KB.
- Audit events store actions and actor hashes, not raw client IP addresses or passwords. Failed logins are counted separately from management events so they cannot push them out of view.
- The console and API are never served on `*.pages.dev` or `*.workers.dev` hostnames, which Access policies on a custom domain do not cover. With `CANONICAL_ORIGIN` set, they are served only on that origin.
- Public keys are parsed as SSH binary structures. The parser rejects DSA, RSA keys below 2048 bits, private keys, multiline input, malformed encodings, and mismatched inner and outer algorithms.
- Dynamic HTML is escaped and the Content Security Policy does not allow inline scripts.
- Public identity, `.keys`, and `.sh` responses use `Cache-Control: no-store` so revocations are not retained in edge caches.
- The installer uses `mktemp`, `trap`, restrictive permissions, timestamped backups, and atomic replacement, and never lifts existing `authorized_keys` restrictions.

The built-in single-admin login is appropriate for a personal deployment or a small trusted team. For production, protect `/admin*` and `/api/*` with Cloudflare Access and MFA as an additional layer.

See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for the upstream audit, implemented controls, and residual risks.

## Requirements

- Node.js 22.13 or newer
- A Cloudflare account
- A Cloudflare-managed zone for a custom domain
- Wrangler authentication through `npx wrangler login` or a scoped API token in CI

Install dependencies:

```sh
npm install
```

## Configuration

Before deploying a fork, replace the Worker route and D1 identifiers in the Wrangler configuration with resources from your own Cloudflare account. D1 IDs are resource identifiers, not credentials.

### Create D1

```sh
npx wrangler d1 create cloud-keyring
```

Copy the returned `database_id` into both:

- `wrangler.worker.toml`
- `wrangler.toml`

Keep the binding name as `DB`.

### Configure a Worker Domain

Edit `wrangler.worker.toml`:

```toml
workers_dev = false

[[routes]]
pattern = "keys.example.com"
custom_domain = true
```

Cloudflare creates the DNS record and certificate during deployment. The hostname must belong to an active zone in the same Cloudflare account and must not already have a conflicting CNAME record.

### Set the Canonical Origin

Set `CANONICAL_ORIGIN` to the public HTTPS origin in the `[vars]` section of `wrangler.worker.toml` or `wrangler.toml`:

```toml
[vars]
CANONICAL_ORIGIN = "https://keys.example.com"
```

When it is set, the console and API are served only on that origin, other hostnames (including Pages preview URLs) redirect public pages to it, and install commands always point at it. When it is unset, the console is still refused on `*.pages.dev` and `*.workers.dev`. Leave it unset for local development.

### Configure Local Secrets

Copy `.dev.vars.example` to `.dev.vars` and set independent high-entropy values:

```dotenv
ADMIN_PASSWORD="at-least-16-random-characters"
SESSION_SECRET="at-least-32-different-random-characters"
SITE_NAME="Cloud Keyring"
```

Generate suitable values with:

```sh
openssl rand -base64 32
openssl rand -base64 48
```

`.dev.vars` is ignored by Git. Never commit it.

## Local Development

Apply local migrations and start the Worker development server:

```sh
npm run db:migrate:local
npm run dev
```

Open `http://localhost:8787/admin`. Local data is stored in Wrangler's local D1 state under `.wrangler/`.

Run all checks:

```sh
npm run check
npm audit
```

The installer tests run generated scripts in isolated temporary `HOME` directories under `/bin/sh`, `dash`, and `bash`, whichever are installed. They cover deduplication, refusal to lift options, isolation between identities, renames, revocation, backups, and idempotency. The application tests run the real migrations and SQL on `node:sqlite`, including concurrent login attempts.

## Upgrading from 1.0.0

1. Apply `migrations/0002_identity_lifecycle.sql` with the migrate script for your target before deploying the new code.
2. Earlier installers dropped `authorized_keys` options from copies of published keys, removed keys shared with other identities, and left keys behind after renames, hiding, or deletion. On every host that ran an installer, check `authorized_keys` and `authorized_keys.keyring.bak` for lost `restrict`, `command=`, or `from=` options and for `cloud-keyring/<handle>` blocks of renamed or removed identities. Then run the current installer again.

## Deploy to Workers

Apply remote migrations:

```sh
npm run db:migrate:worker
```

Set production secrets:

```sh
npx wrangler secret put ADMIN_PASSWORD -c wrangler.worker.toml
npx wrangler secret put SESSION_SECRET -c wrangler.worker.toml
```

Deploy the Worker and custom domain:

```sh
npm run deploy:worker
```

Validate the deployment:

```sh
curl -I https://keys.example.com/
curl -fsSL https://keys.example.com/alice.keys
curl -fsSL https://keys.example.com/alice.sh
```

## Deploy to Pages

Create a Pages project named `cloud-keyring`, then apply the D1 migration:

```sh
npm run db:migrate:pages
```

Set Pages secrets:

```sh
npx wrangler pages secret put ADMIN_PASSWORD --project-name cloud-keyring
npx wrangler pages secret put SESSION_SECRET --project-name cloud-keyring
```

Deploy the static output and Pages Function:

```sh
npm run deploy:pages
```

When connecting the repository through the Cloudflare dashboard, leave the build command empty, set the output directory to `public`, and configure a D1 binding named `DB` for the same database. Add the custom domain from the Pages project settings.

## Usage

Open `/admin`, create an identity, and paste one complete OpenSSH public key:

```text
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... device-name
```

The final field is a comment. It can be changed without changing the public key fingerprint. The algorithm and Base64 body must not be modified.

Fetch published keys:

```sh
curl -fsSL https://keys.example.com/alice.keys
```

Review the installer before running it:

```sh
curl -fsSL https://keys.example.com/alice.sh
```

After verifying the HTTPS hostname and script content:

```sh
curl -fsSL https://keys.example.com/alice.sh | sh
```

Running remote shell code is a supply-chain decision. Review the script first and protect the domain, Cloudflare account, deployment credentials, and source repository.

## Operations

- Rotate `ADMIN_PASSWORD` with `wrangler secret put` when administrator access changes.
- Rotate `SESSION_SECRET` to invalidate all existing login sessions immediately.
- After revoking a key, inspect `/<handle>.keys` and rerun the installer on every target machine.
- Hiding or deleting an identity revokes its keys the next time each host runs its installer. Because a hidden handle still answers `.sh` with a revocation script, the handle's existence is visible.
- Handles cannot be released or reassigned. Choose new handles for new people.
- Back up D1 and regularly test recovery.
- Enable Cloudflare Access, MFA, WAF rules, and rate limiting for the management endpoints.
- Review audit events from the admin console.
- Never commit `.dev.vars`, API tokens, administrator passwords, cookie values, or private keys.

## Project Layout

```text
functions/              Pages Functions entrypoint
migrations/             D1 SQL migrations
public/                 Pages static output and route configuration
src/app.ts              HTTP routing, authentication, CRUD, installer
src/security.ts         Sessions, constant-time comparison, privacy hashes
src/ssh.ts              SSH key parsing and fingerprints
src/views.ts            Server-rendered HTML
src/worker.ts           Workers entrypoint
test/                   Security, SSH parser, installer, and application tests
wrangler.toml           Pages configuration
wrangler.worker.toml    Workers and custom-domain configuration
```

## Acknowledgements

The product direction was inspired by [patrickhere/keys](https://github.com/patrickhere/keys), a source-managed SSH public key identity site. Cloud Keyring is an independent reimplementation with D1-backed runtime management, stronger key validation, authenticated administration, audit events, and hardened installer behavior.
