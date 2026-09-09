-- StegoShare schema.
--
-- Design note that matters more than any other line in this file:
-- grants.wrapped_dek is NULL until the approval threshold is met. An
-- unapproved recipient does not hold a permission flag we have to remember
-- to check -- they hold no key material at all. Authorization and key
-- retrieval are the same query (see security.dek_for).

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name  TEXT NOT NULL,
    password_hash TEXT NOT NULL,              -- argon2id; never the password
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- One share = one payload encrypted once under one data key (DEK).
--   reference mode: ciphertext in object storage, capsule carries a locator
--   inline mode:    ciphertext embedded in the image itself, no server needed
CREATE TABLE IF NOT EXISTS shares (
    id                 INTEGER PRIMARY KEY,
    public_id          TEXT    NOT NULL UNIQUE,   -- uuid4 hex; goes in the capsule
    owner_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mode               TEXT    NOT NULL CHECK (mode IN ('reference', 'inline')),
    kind               TEXT    NOT NULL CHECK (kind IN ('file', 'text')),
    display_name       TEXT    NOT NULL,
    content_type       TEXT    NOT NULL,
    byte_size          INTEGER NOT NULL CHECK (byte_size >= 0),
    object_key         TEXT    UNIQUE,            -- NULL in inline mode
    -- SHA-256 of the capability token carried inside the stego image. We store
    -- only the digest, so the database alone never yields a working token:
    -- opening a reference share requires the image as well as an approved
    -- grant. Inline shares are self-contained and carry no locator, so this is
    -- NULL for them.
    secret_digest      BLOB,
    approvals_required INTEGER NOT NULL DEFAULT 1 CHECK (approvals_required >= 0),
    created_at         TEXT    NOT NULL DEFAULT (datetime('now')),

    -- Reference shares live on the server and must be openable; inline shares
    -- never touch storage. Keep the two shapes from drifting into each other.
    CHECK (mode <> 'reference' OR (object_key IS NOT NULL AND secret_digest IS NOT NULL)),
    CHECK (mode <> 'inline'    OR (object_key IS NULL     AND secret_digest IS NULL))
);

-- One row per (share, recipient). The owner is auto-granted at creation.
CREATE TABLE IF NOT EXISTS grants (
    share_id     INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped_dek  BLOB,                            -- NULL until approved
    granted_at   TEXT,
    PRIMARY KEY (share_id, recipient_id)
);

-- The UNIQUE constraint is what stops duplicate-request spam at the
-- database level rather than in a check somebody forgets to write.
CREATE TABLE IF NOT EXISTS access_requests (
    id           INTEGER PRIMARY KEY,
    share_id     INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    approver_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'approved', 'denied')),
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    decided_at   TEXT,
    UNIQUE (share_id, requester_id, approver_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY,
    actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action   TEXT NOT NULL,                       -- 'share.create', 'share.open', ...
    share_id INTEGER,
    detail   TEXT,
    ip       TEXT,
    at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_shares_owner      ON shares (owner_id);
CREATE INDEX IF NOT EXISTS idx_grants_recipient  ON grants (recipient_id);
CREATE INDEX IF NOT EXISTS idx_requests_approver ON access_requests (approver_id, status);
CREATE INDEX IF NOT EXISTS idx_requests_share    ON access_requests (share_id, requester_id);
CREATE INDEX IF NOT EXISTS idx_audit_share       ON audit_log (share_id, at);
