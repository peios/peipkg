-- peipkg package database — schema version 3: claims (PSD-009 §4.4).
--
-- A claim binds a contended filesystem name to a file supplied by the
-- package that holds a role. Several installed packages may provide the
-- same role; at most one holds it. The holder's targets fill the role's
-- claim paths as package-manager-owned symlinks — tracked here, never in
-- package_file, so two providers coexist without colliding (§4.4.4).

-- ----------------------------------------------------------------------
-- claim_holder — the single holder of each role.
--
-- holder cascades from package: uninstalling the holding package clears
-- the row, leaving the role unheld. The uninstall procedure removes the
-- materialised links first and warns (§7.7.6); this cascade keeps the
-- ledger consistent even on a degraded path.
-- ----------------------------------------------------------------------
CREATE TABLE claim_holder (
    role   TEXT PRIMARY KEY,
    holder TEXT NOT NULL REFERENCES package(name) ON DELETE CASCADE
);

-- ----------------------------------------------------------------------
-- claim_link — one row per materialised claim symlink: the
-- "database reflects disk" invariant for manager-owned claim links,
-- analogous to package_file. path is the symlink location (unique across
-- the system); target is the holder file it points at; slot records
-- which of the role's channels it serves.
--
-- A link belongs to a held role; when the holder row goes, its links go
-- by cascade (and the on-disk symlinks are removed by the procedure that
-- triggered the change).
-- ----------------------------------------------------------------------
CREATE TABLE claim_link (
    path   TEXT PRIMARY KEY,
    role   TEXT NOT NULL REFERENCES claim_holder(role) ON DELETE CASCADE,
    slot   TEXT NOT NULL,
    target TEXT NOT NULL
);

CREATE INDEX idx_claim_link_role ON claim_link (role);
