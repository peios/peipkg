-- peipkg package database — schema version 5: cross-root transactions
-- (DESIGN-named-roots.md → cross-root dependencies).
--
-- A single install/upgrade may touch more than one root when a package's
-- dependency is placed in a different root than the depender (§4.1.1). The
-- result must be all-or-nothing across those roots, so the participating
-- roots' per-root txn rows are tied together by a shared identifier: each
-- root records the same cross_root_id, and crash recovery reconciles every
-- row sharing one id as a single logical transaction (roll forward to
-- completion, else roll back all).
--
-- The column is nullable and NULL for an ordinary single-root transaction
-- — every transaction written before this migration, and every one that
-- stays within one root. Adding it changes no existing row and no
-- single-root behaviour; it is the storage the cross-root executor builds
-- on. SQLite's ALTER TABLE ADD COLUMN is a metadata-only operation.
ALTER TABLE txn ADD COLUMN cross_root_id TEXT;

-- Group lookup for recovery: find every root's row in one cross-root
-- transaction by its shared id. Partial — single-root rows (the common
-- case) carry NULL and stay out of the index.
CREATE INDEX idx_txn_cross_root ON txn (cross_root_id) WHERE cross_root_id IS NOT NULL;
