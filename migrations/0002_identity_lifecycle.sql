-- Immutable identity IDs and a permanent handle registry.
--
-- Installers mark authorized_keys blocks with the immutable uid instead of the
-- mutable handle, so renames, hiding and deletion can still revoke keys. Every
-- handle ever assigned stays reserved for the identity that used it: old
-- installer URLs keep converging on that identity's state and can never be
-- taken over by a different identity.

ALTER TABLE identities ADD COLUMN uid TEXT;
UPDATE identities SET uid = lower(hex(randomblob(16))) WHERE uid IS NULL;
CREATE UNIQUE INDEX identities_uid ON identities(uid);

CREATE TABLE identity_handles (
  handle TEXT PRIMARY KEY COLLATE NOCASE,
  -- NULL marks a handle retired before this registry existed. Its installer
  -- only removes the legacy block for that handle.
  identity_uid TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX identity_handles_identity_uid ON identity_handles(identity_uid);

INSERT INTO identity_handles (handle, identity_uid)
SELECT handle, uid FROM identities;

-- Handles that were renamed away or deleted before this migration cannot be
-- attributed reliably, so they are reserved as cleanup-only handles.
INSERT OR IGNORE INTO identity_handles (handle, identity_uid)
SELECT DISTINCT target, NULL FROM audit_events
WHERE action IN ('identity.created', 'identity.updated', 'identity.deleted', 'key.created', 'key.deleted');

INSERT OR IGNORE INTO identity_handles (handle, identity_uid)
SELECT DISTINCT substr(detail, 10), NULL FROM audit_events
WHERE action = 'identity.updated' AND detail LIKE 'formerly %';

-- Management events are listed separately from login noise, so failed login
-- floods cannot push them out of the admin view.
CREATE INDEX audit_events_management ON audit_events(id)
WHERE substr(action, 1, 6) <> 'login.';
