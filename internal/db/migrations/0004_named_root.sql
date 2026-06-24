-- peipkg package database — schema version 4: named roots
-- (DESIGN-named-roots.md).
--
-- A named root maps a local name to a filesystem path so `--root <name>`
-- resolves a registered name instead of a repeated path. The registry is
-- per-root *fact* — what roots this root knows of — not configuration, so
-- it lives in the database beside the package ledger, never in /conf.
--
-- path is stored relative to the root that owns this registry, which
-- keeps a whole root tree relocatable: moving the tree moves every
-- registered path with it. Resolution of a dotted reference
-- (initramfs.subroot) recurses — it walks from one root's registry into
-- the named child's own registry — so each registry stays flat and
-- self-describes only its own children.
-- ----------------------------------------------------------------------
CREATE TABLE named_root (
    name       TEXT    PRIMARY KEY,
    path       TEXT    NOT NULL,       -- relative to the owning root
    created_at INTEGER NOT NULL        -- unix epoch seconds
);
