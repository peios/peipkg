package db

import "time"

// Package is one row of the package table: a package installed on the
// system.
type Package struct {
	Name         string
	Version      string
	Architecture string
	// OriginRepo is the repository the package was installed from, or ""
	// for a package installed from a local .peipkg file.
	OriginRepo  string
	InstalledAt time.Time
	// Manifest is the package's manifest, stored verbatim so the
	// resolver has full dependency metadata without re-reading the
	// original archive.
	Manifest string
}

// FileType is the kind of filesystem object a package owns.
type FileType string

const (
	FileTypeFile    FileType = "file"
	FileTypeDir     FileType = "dir"
	FileTypeSymlink FileType = "symlink"
)

// PackageFile is one row of the package_file table: a single filesystem
// object a package owns. The set of these rows is the "the database
// reflects disk" invariant.
type PackageFile struct {
	PackageName string
	Path        string
	Type        FileType
	// Hash is the sha256 hex digest of a file's contents; "" for a
	// directory or symlink.
	Hash string
	// SymlinkTarget is the target of a symlink; "" for a file or
	// directory.
	SymlinkTarget string
}

// Repository is one row of the repository table: the derived trust and
// freshness state of a configured repository. The repository's
// configuration lives in /lcl/conf/peipkg/*.repo, never here.
type Repository struct {
	// Name is the LOCAL HANDLE — the .repo filename an operator chose.
	// PSPU §5.31 does not require it to equal the descriptor's repo.name.
	Name string
	// DescriptorName is the repo.name the verified descriptor declares.
	// An index's `repo` field is compared against this, never against
	// the handle. Empty for a row written before schema 7, and for a
	// repository in unsigned mode whose descriptor was never verified.
	DescriptorName string
	// HighestIndexVersion is the index_version freshness floor: an index
	// below it is rejected as a rollback (§6.2).
	HighestIndexVersion int64
	// GeneratedAtFloor is the generated_at freshness floor, in unix
	// epoch seconds; 0 means no floor has been recorded yet.
	GeneratedAtFloor int64
	// LastRefreshAt is when the repository last refreshed successfully;
	// the zero Time means it never has.
	LastRefreshAt time.Time
	// TrustKeys is the verified signing-key set, an opaque JSON document
	// to this layer — the repository layer defines its shape.
	TrustKeys string
}

// TxnState is the lifecycle state of a transaction.
type TxnState string

const (
	// TxnPending is a transaction that has not yet reached its
	// durability boundary. At most one transaction is pending at a time,
	// and that one row is the crash-recovery journal.
	TxnPending TxnState = "pending"
	// TxnCommitted is a transaction that completed successfully.
	TxnCommitted TxnState = "committed"
	// TxnRolledBack is a transaction that was undone before committing.
	TxnRolledBack TxnState = "rolled-back"
)

// Txn is one row of the txn table: a single install/upgrade/downgrade/
// uninstall transaction.
type Txn struct {
	ID    int64
	State TxnState
	// StartedAt is when the transaction opened; FinishedAt is when it
	// reached a terminal state, and is the zero Time while pending.
	StartedAt  time.Time
	FinishedAt time.Time
	// OpSummary is a human-readable one-line summary, for `peipkg
	// history`.
	OpSummary string
	// StartedByVersion is the peipkg version that opened the
	// transaction; JournalSchemaVersion is the journal format it wrote,
	// so a different peipkg can tell whether it can recover it.
	StartedByVersion     string
	JournalSchemaVersion int
	// CrossRootID groups the per-root txn rows of one cross-root
	// transaction (DESIGN-named-roots.md). It is empty for an ordinary
	// single-root transaction — the common case — and a shared identifier
	// across the participating roots otherwise.
	CrossRootID string
}

// OpAction is what a transaction does to one package.
type OpAction string

const (
	OpInstall   OpAction = "install"
	OpUpgrade   OpAction = "upgrade"
	OpDowngrade OpAction = "downgrade"
	OpRemove    OpAction = "remove"
	// OpClaim is a standalone grant or revoke of a role's holder (§7.7):
	// it changes a holder pointer and the role's claim symlinks, not any
	// package's version, so it carries no from/to version.
	OpClaim OpAction = "claim"
)

// TxnOp is one row of the txn_op table: a transaction's operation on a
// single package. Seq is the topological apply order.
type TxnOp struct {
	TxnID       int64
	Seq         int
	PackageName string
	Action      OpAction
	// FromVersion is the version before the operation, "" for an
	// install; ToVersion is the version after, "" for a remove.
	FromVersion string
	ToVersion   string
	// OriginRepo is where the new version came from, "" for a remove or
	// a local-file install.
	OriginRepo string
}

// FileAction is what a transaction does to one filesystem path.
type FileAction string

const (
	// FileCreate installs new content where nothing existed.
	FileCreate FileAction = "create"
	// FileReplace installs new content over an existing file, which is
	// backed up first.
	FileReplace FileAction = "replace"
	// FileRemove deletes an existing file, which is backed up first.
	FileRemove FileAction = "remove"
)

// TxnFile is one row of the txn_file table: a transaction's action on a
// single path, and its entry in the backup map. Rows are write-once;
// crash recovery reverses each one idempotently. Seq is the apply order
// — parent directories before their children; rollback walks it back.
type TxnFile struct {
	TxnID       int64
	Seq         int
	PackageName string
	FinalPath   string
	Action      FileAction
	// StagedPath is the incoming content awaiting its final name; "" for
	// a pure remove. BackupPath is the displaced old content; "" for a
	// pure create.
	StagedPath string
	BackupPath string
}

// TxnDir is one directory the transaction may create during staging.
// Recovery removes these in reverse order after reversing txn_file rows.
type TxnDir struct {
	TxnID int64
	Seq   int
	Path  string
}

// ClaimHolder is one row of the claim_holder table: the package that
// currently holds a role (§4.4). Deleting the holder package clears the
// row by cascade, leaving the role unheld.
type ClaimHolder struct {
	Role   string
	Holder string
}

// NamedRoot is one row of the named_root table: a name in this root's
// registry mapped to a path relative to this root (DESIGN-named-roots.md).
// The registry is per-root state, so the same name may map differently in
// two roots; resolution of a dotted reference chains these flat lookups.
type NamedRoot struct {
	Name string
	// Path is relative to the root that owns the registry, keeping the
	// root tree relocatable.
	Path      string
	CreatedAt time.Time
}

// ClaimLink is one row of the claim_link table: a materialised claim
// symlink the package manager owns (§4.4.4). Path is the link location,
// Target the holder file it points at, Slot the role channel it serves.
// These rows are the claim layer's "database reflects disk" invariant,
// the counterpart of [PackageFile] for package-owned files.
type ClaimLink struct {
	Path   string
	Role   string
	Slot   string
	Target string
}
