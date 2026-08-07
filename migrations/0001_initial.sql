PRAGMA foreign_keys = ON;

CREATE TABLE identities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  handle TEXT NOT NULL COLLATE NOCASE UNIQUE,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  is_public INTEGER NOT NULL DEFAULT 1 CHECK (is_public IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE ssh_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  identity_id INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  public_key TEXT NOT NULL,
  key_type TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  key_comment TEXT NOT NULL DEFAULT '',
  added_at TEXT NOT NULL DEFAULT (date('now')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (identity_id, fingerprint)
);

CREATE INDEX ssh_keys_identity_id ON ssh_keys(identity_id);

CREATE TABLE auth_attempts (
  bucket TEXT PRIMARY KEY,
  failures INTEGER NOT NULL,
  blocked_until INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  actor_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX audit_events_created_at ON audit_events(created_at DESC);
