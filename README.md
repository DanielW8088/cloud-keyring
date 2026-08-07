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

The generated installer manages only the block associated with one identity:

```text
# >>> cloud-keyring/alice >>>
ssh-ed25519 AAAA... alice-laptop
# <<< cloud-keyring/alice <<<
```

Before changing `authorized_keys`, it creates:

```text
~/.ssh/authorized_keys.keyring.bak
```

Key deduplication uses the key identity:

```text
algorithm + Base64 public key body
```

Comments, spacing, and supported `authorized_keys` options do not make duplicate copies distinct. For example, these are treated as the same key:

```text
ssh-ed25519 AAAAC3... old-comment
ssh-ed25519 AAAAC3... new-comment
restrict ssh-ed25519 AAAAC3... option-comment
```

The installer removes equivalent copies outside its managed block, writes the currently published form once, preserves unrelated keys and comments, and remains idempotent across repeated runs.

Management blocks for different handles remain independent. Revoking a key from one handle does not remove a copy intentionally published by another handle.

## Security Model

- D1 stores public keys and display metadata only. It does not store private keys.
- `ADMIN_PASSWORD` and `SESSION_SECRET` are Cloudflare Secrets, not source-controlled variables.
- Sessions use HMAC signatures and `HttpOnly; Secure; SameSite=Strict` cookies with an eight-hour lifetime.
- Every management write requires a valid session and an exact same-origin `Origin` header.
- Failed logins are rate-limited using a privacy-preserving HMAC hash of the client IP.
- Audit events store actions and actor hashes, not raw client IP addresses or passwords.
- Public keys are parsed as SSH binary structures. The parser rejects DSA, RSA keys below 2048 bits, private keys, multiline input, malformed encodings, and mismatched inner and outer algorithms.
- Dynamic HTML is escaped and the Content Security Policy does not allow inline scripts.
- Public identity, `.keys`, and `.sh` responses use `Cache-Control: no-store` so revocations are not retained in edge caches.
- The installer uses `mktemp`, `trap`, restrictive permissions, a local backup, and atomic replacement.

The built-in single-admin login is appropriate for a personal deployment or a small trusted team. For production, protect `/admin*` and `/api/*` with Cloudflare Access and MFA as an additional layer.

See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for the upstream audit, implemented controls, and residual risks.

## Requirements

- Node.js 22 or newer
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

The installer tests execute the generated script with `/bin/sh` in an isolated temporary `HOME`. They cover comment-insensitive deduplication, supported options, idempotency, and full revocation without deleting unrelated entries.

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
test/                   Security, SSH parser, and shell installer tests
wrangler.toml           Pages configuration
wrangler.worker.toml    Workers and custom-domain configuration
```

## Acknowledgements

The product direction was inspired by [patrickhere/keys](https://github.com/patrickhere/keys), a source-managed SSH public key identity site. Cloud Keyring is an independent reimplementation with D1-backed runtime management, stronger key validation, authenticated administration, audit events, and hardened installer behavior.
