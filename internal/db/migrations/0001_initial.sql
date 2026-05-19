-- peipkg package database — schema version 1.
--
-- The consumer-side package manager's private state store, at
-- /var/lib/peipkg/db.sqlite. This is an internal ledger of *fact* —
-- what is installed, and the transaction history — NOT configuration.
-- Repository configuration lives in /conf/peipkg/*.repo and never here.
--
-- Migrations are append-only: once released, this file is never
-- edited. A schema change adds 000N_<name>.sql. The migration runner
-- (internal/db) owns meta.schema_version and the per-connection PRAGMAs
-- (foreign_keys, journal_mode=WAL, synchronous=FULL, busy_timeout) —
-- this file is pure DDL.

-- ----------------------------------------------------------------------
-- meta — key/value store for database-global facts.
--
-- Holds schema_version (managed by the migration runner), primary_arch,
-- and the creation provenance. Key/value rather than a fixed-column row
-- so a new global fact never needs a migration.
-- ----------------------------------------------------------------------
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- ----------------------------------------------------------------------
-- package — one row per installed package.
--
-- manifest holds the package's manifest verbatim (the exact bytes, not
-- a re-serialisation) so the resolver has full dependency metadata for
-- already-installed packages without re-reading the original .peipkg.
-- ----------------------------------------------------------------------
CREATE TABLE package (
    name         TEXT    PRIMARY KEY,
    version      TEXT    NOT NULL,
    architecture TEXT    NOT NULL,
    origin_repo  TEXT,                  -- NULL for a local-file install
    installed_at INTEGER NOT NULL,      -- unix epoch seconds
    manifest     TEXT    NOT NULL       -- verbatim manifest JSON
);

-- origin_repo is deliberately NOT a foreign key to repository(name): a
-- repository may be removed from configuration while packages installed
-- from it remain. Installed state must outlive repository configuration.

-- ----------------------------------------------------------------------
-- package_file — one row per filesystem object a package owns.
--
-- This table is the "the database reflects disk" invariant: every entry
-- here is a path peipkg installed and is responsible for. hash carries
-- the content digest of a file (also the /etc modified-detection
-- baseline); symlink_target carries a symlink's target.
-- ----------------------------------------------------------------------
CREATE TABLE package_file (
    package_name   TEXT NOT NULL REFERENCES package(name) ON DELETE CASCADE,
    path           TEXT NOT NULL,
    type           TEXT NOT NULL CHECK (type IN ('file', 'dir', 'symlink')),
    hash           TEXT,            -- sha256 hex, files only
    symlink_target TEXT,            -- target, symlinks only

    PRIMARY KEY (package_name, path),

    -- A file carries a hash and no target; a symlink carries a target
    -- and no hash; a directory carries neither. Enforced structurally
    -- so a malformed write cannot land in the table.
    CHECK (type != 'file'    OR (hash IS NOT NULL AND symlink_target IS NULL)),
    CHECK (type != 'symlink' OR (symlink_target IS NOT NULL AND hash IS NULL)),
    CHECK (type != 'dir'     OR (hash IS NULL AND symlink_target IS NULL))
);

-- Two packages may freely share a directory tree (§3.4.10) but never a
-- non-directory path. This partial unique index makes the no-collision
-- rule a structural guarantee — peipkg cannot register a colliding file
-- even by mistake; the conflicting INSERT fails.
CREATE UNIQUE INDEX idx_package_file_collision
    ON package_file (path) WHERE type != 'dir';

-- General path lookup, for `peipkg owns <path>` and plan-time checks.
-- (The partial index above does not cover directory rows.)
CREATE INDEX idx_package_file_path ON package_file (path);

-- ----------------------------------------------------------------------
-- repository — per-repository derived trust and freshness state.
--
-- The freshness floors (§6.2) defeat rollback/freeze attacks: an index
-- below a recorded floor is rejected. trust_keys is the verified
-- signing-key set adopted from the last good descriptor (§6.5.2) — read
-- and written as a unit, never queried per key, so a JSON document
-- column is the right fit and keeps the schema at seven tables.
-- ----------------------------------------------------------------------
CREATE TABLE repository (
    name                  TEXT    PRIMARY KEY,        -- local handle (.repo filename)
    highest_index_version INTEGER NOT NULL DEFAULT 0,  -- index_version floor
    generated_at_floor    INTEGER NOT NULL DEFAULT 0,  -- generated_at floor, epoch seconds
    last_refresh_at       INTEGER,                     -- NULL until first refresh
    trust_keys            TEXT    NOT NULL DEFAULT '[]'-- JSON array of verified keys
);

-- ----------------------------------------------------------------------
-- txn — the transaction ledger. Every install/upgrade/downgrade/
-- uninstall is one row.
--
-- The single row with state = 'pending' IS the crash-recovery journal:
-- there is no separate journal file. journal_schema_version lets a
-- different peipkg version (e.g. after a self-upgrade) decide whether it
-- can recover a crashed transaction directly or must defer to manual
-- recovery.
-- ----------------------------------------------------------------------
CREATE TABLE txn (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    state                  TEXT    NOT NULL
                               CHECK (state IN ('pending', 'committed', 'rolled-back')),
    started_at             INTEGER NOT NULL,   -- unix epoch seconds
    finished_at            INTEGER,            -- NULL while pending
    op_summary             TEXT    NOT NULL DEFAULT '',  -- human summary for `history`
    started_by_version     TEXT    NOT NULL,   -- peipkg version that opened the txn
    journal_schema_version INTEGER NOT NULL,   -- versioned journal format

    -- finished_at is set exactly when the transaction leaves 'pending'.
    CHECK (state =  'pending' OR finished_at IS NOT NULL),
    CHECK (state != 'pending' OR finished_at IS NULL)
);

-- AUTOINCREMENT (not bare rowid) so transaction ids are monotonic and
-- never reused — `peipkg history` ids and .peipkg-staged-<id> filenames
-- stay stable for the life of the system.

-- At most one transaction may be pending at any time: the single-writer
-- invariant, structural. The advisory lock file is the friendly fast
-- path (clear error, stale-holder detection); this index is the
-- backstop that a second writer cannot get past.
CREATE UNIQUE INDEX idx_txn_one_pending ON txn (state) WHERE state = 'pending';

-- ----------------------------------------------------------------------
-- txn_op — the per-package operations within a transaction.
--
-- Drives `peipkg history` and `peipkg undo`. seq is the topological
-- apply order (dependencies before dependents).
-- ----------------------------------------------------------------------
CREATE TABLE txn_op (
    txn_id       INTEGER NOT NULL REFERENCES txn(id) ON DELETE CASCADE,
    seq          INTEGER NOT NULL,
    package_name TEXT    NOT NULL,
    action       TEXT    NOT NULL
                     CHECK (action IN ('install', 'upgrade', 'downgrade', 'remove')),
    from_version TEXT,                  -- NULL for install
    to_version   TEXT,                  -- NULL for remove
    origin_repo  TEXT,                  -- NULL for remove / local-file install

    PRIMARY KEY (txn_id, package_name),
    UNIQUE (txn_id, seq),

    -- Version columns are populated exactly as the action requires.
    CHECK (action != 'install' OR (from_version IS NULL     AND to_version IS NOT NULL)),
    CHECK (action != 'remove'  OR (from_version IS NOT NULL AND to_version IS NULL)),
    CHECK (action IN ('install', 'remove')
           OR (from_version IS NOT NULL AND to_version IS NOT NULL))
);

-- package_name is deliberately NOT a foreign key to package: a 'remove'
-- op names a package that no longer exists after commit, and history
-- must remain readable for packages that are long gone.

-- ----------------------------------------------------------------------
-- txn_file — the per-file actions of a transaction: the journal's
-- actionable content and the backup map.
--
-- Rows are write-once — inserted during Stage, never updated. Crash
-- recovery reverses every row of a pending transaction idempotently
-- (rename backup_path back over final_path if it exists; discard
-- staged_path if it exists), so no mutable per-file "applied" flag is
-- needed. seq is the apply order — parent directories before their
-- children; rollback walks it in reverse.
-- ----------------------------------------------------------------------
CREATE TABLE txn_file (
    txn_id       INTEGER NOT NULL,
    seq          INTEGER NOT NULL,
    package_name TEXT    NOT NULL,
    final_path   TEXT    NOT NULL,      -- the install destination
    action       TEXT    NOT NULL CHECK (action IN ('create', 'replace', 'remove')),
    staged_path  TEXT,                  -- incoming content; NULL for a pure remove
    backup_path  TEXT,                  -- displaced old content; NULL for a pure create

    PRIMARY KEY (txn_id, final_path),
    UNIQUE (txn_id, seq),

    -- Every file belongs to a declared package operation of the same
    -- transaction. The cascade chain is txn -> txn_op -> txn_file.
    FOREIGN KEY (txn_id, package_name)
        REFERENCES txn_op (txn_id, package_name) ON DELETE CASCADE,

    -- create  installs new content, displaces nothing.
    -- replace  installs new content over an existing file, backed up.
    -- remove   deletes an existing file, backed up, installs nothing.
    CHECK (action != 'create'  OR (staged_path IS NOT NULL AND backup_path IS NULL)),
    CHECK (action != 'replace' OR (staged_path IS NOT NULL AND backup_path IS NOT NULL)),
    CHECK (action != 'remove'  OR (staged_path IS NULL     AND backup_path IS NOT NULL))
);
