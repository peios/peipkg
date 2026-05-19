# peipkg — Consumer Design

Status: design complete, no code yet. Settled across a design pass on
2026-05-17 — 2026-05-18.

Normative format reference: PSD-009 v0.22 at
`learn/specs/psd-009--peipkg/v0.22/`. Section numbers below (§x.y) cite
that spec. Where this document and the spec disagree on the **package
format or repository protocol** (chapters 1–6), the spec wins. For
**consumer mechanics** (chapter 7) the relationship is different — see
"Relationship to PSD-009".

## What this is

`peipkg` is the **consumer-side package manager**: the client tool that
runs on a Peios system and installs, upgrades, removes, and queries
packages — `peipkg install nginx`. It is the counterpart to the
producer side (`peipkg-build`, `peipkg-repo`, `peipkg-manager`), which
is already built and produces and serves `.peipkg` files and
repositories.

In one sentence: **given a request and a set of trusted repositories,
bring the system's installed package set to a new, consistent state —
atomically, verifiably, reversibly.**

## What this is not

- **The producer side.** Building, assembling repositories, signing
  indexes — `peipkg-build` / `-repo` / `-manager`, separate and done.
- **Roles and features.** PSD-009 §1 is explicit: a package is a
  low-level primitive; roles, role features, and applets are
  user-facing layers *above* peipkg, specified separately. peipkg
  installs packages; it does not know what a role is. Curated, scoped
  installation ("let Alice install the web-server role without granting
  her general write to `/usr`") belongs to the roles layer.
- **A daemon.** peipkg is a transient CLI process — see "Privilege
  model". It is not one of the long-running Peios daemons.

## Relationship to PSD-009

PSD-009 v0.22 has two halves, with two different statuses here:

- **Chapters 1–6 — package format and repository protocol** (container,
  manifest, versioning, dependencies, signing, repository descriptor
  and indexes). **Authoritative.** peipkg consumes this as given.
- **Chapter 7 — consumer mechanics** (install, upgrade, transactions,
  rollback, security model). Treated as a **threat-model and audit
  source, not as a normative specification.**

Chapter 7 was written before the consumer existed and assumes a Peios —
a privileged package-manager principal, a reconciler framework, eventd,
several KACS authorisation primitives — much of which does not exist or
is modelled differently here. Rather than inherit its mechanisms, this
design re-derives consumer behaviour from first principles and uses
chapter 7 as a checklist: every threat §7 enumerates is accounted for,
and every divergence is recorded deliberately (Appendix A).

Convergence with §7 is a confidence signal; divergence is allowed and
expected. v0.22 is a draft — divergences here are expected to feed a
future §7 revision.

---

## Foundational decisions

### Privilege model — "model C": no package-manager principal

peipkg runs **as the calling user**. It holds no principal, no special
identity, no ambient authority of its own. When it writes a file, KACS
(PSD-004) checks the *caller's* token against the target's security
descriptor: authorised → the write succeeds; not → it fails. Install
authority is therefore nothing more than SDs on the system directories
("Alice may install into `/opt/webapp`" is just an SD), and the
authority to install is held by whoever the SDs say — Administrators by
default.

Consequences:

- No daemon, no privileged broker, no setuid, no impersonation, no
  socket-and-`SO_PEERCRED` authorisation layer. peipkg is just a
  program.
- A package's `sd_overrides` can only assign SDs the *caller* already
  has the authority to assign. A package cannot grant the installer
  rights the installer lacks.
- The authoritative audit record is the kernel's (KACS → KMES) record
  of the actual file operations, which the caller cannot suppress.
  peipkg's own emitted events are a semantic summary, not the security
  boundary.
- peipkg cannot offer *scoped* elevation ("install this one curated
  thing without general write"). That is correct: it is the roles
  layer's job, and that layer can broker it.

`elex` ("elevated executables" — a future Peios concept: an executable
that carries specific, narrow groups/privileges, setuid-shaped but
scoped) is **not used** by v1 peipkg. It is noted as a future option
for hardening the package database (below); v1 does not depend on it.

### Language — Go

peipkg is normal userspace, not the lean low-level tier (peinit,
coreutils) for which Rust is used. It is a transient, occasionally-run,
I/O- and orchestration-heavy tool — footprint is irrelevant, the
difficulty is logic. The majority of Peios userspace will be Go;
`libp-go` wrappers will exist and peipkg is an early consumer of them.
It is also a member of the *packaging family* — it shares the format,
version algorithm, index schema, signing envelope and trust model with
the three Go producer tools, and a shared `peipkg-core` Go module makes
spec-mandated version-comparison parity (§2.2.9) structural rather than
test-enforced.

### The package database — a private SQLite store

Installed-package state lives in a **private SQLite database** at
`/var/lib/peipkg/db.sqlite`, **not** in the registry (LCS). The registry
is for *configuration* — mutable state that reconcilers materialise; the
package database is an *internal ledger* of fact. A registry-backed DB
would also gate peipkg v1 on LCS (unimplemented) and create a
bootstrapping circularity (peipkg installs the registry components).
Schema: see "The package database".

The DB, the transaction journal, the staging area and the download
cache all live under `/var/lib/peipkg/`, with an SD granting write to
the install-authority tier. A member of that tier can therefore corrupt
the shared DB — the same trust posture as `dpkg`'s status file under
root, acceptable within one tier. When `elex` exists, the DB can be
moved behind a narrow `Peipkg-Database` group carried by the peipkg
binary, so only peipkg-the-binary can write it; that is a non-breaking
tightening (only the DB's SD changes) and explicitly *optional* — not a
v1 dependency.

---

## The operation model

Every operation — install, upgrade, uninstall, downgrade — is a
**transaction** and runs through the same three-phase skeleton, with two
hard boundaries:

**Phase 1 — Plan.** *Read-only, no lock, freely abortable.*
Parse the request; refresh repository metadata if stale (see
"Repositories"); load the installed set from the DB; resolve to an
ordered plan or a rejection; present the plan.

→ **Boundary A — confirmation gate.** The operator sees the plan and
approves. `--dry-run` stops here; `-y` skips the prompt. Nothing has
touched the system or taken a lock.

**Phase 2 — Stage.** *Single-writer lock held; no visible mutation.*
Acquire the transaction lock; run crash recovery first if a prior
journal is pending; fetch every `.peipkg` in the plan; **verify all of
them before staging any** (§7.4.3 — stops one package's extraction from
influencing another's verification); extract verified payloads to
staging, per-file hash-checked.

**Phase 3 — Commit.** *The atomic flip.*
Apply file changes; then one SQLite transaction commits the new package
state and clears the journal; run side effects.

→ **Boundary B — the durability boundary**, which is the SQLite commit
(see "The execution half"). Before it: any failure, signal, or power
loss rolls fully back — nothing happened. After it: the operation is
complete.

Properties: Phase 1 is lockless, so dry-runs and queries never block on
an in-flight transaction (they read committed state through SQLite WAL).
The skeleton is operation-agnostic — uninstall simply has a near-empty
Stage phase.

---

## Repositories

### Configuration vs state

Two distinct things, two homes, opposite lifecycles:

- **Configuration** — operator intent: which repositories exist, their
  trust anchors, signature policy, priority. Lives in `/conf/peipkg/*`.
- **Derived state** — descriptors, indexes, freshness counters. Lives in
  `/var/lib/peipkg/` (the SQLite DB and a cache directory).

`/conf/peipkg/*` is a **temporary placeholder**: when LCS lands,
repository configuration moves into the registry. The config/state split
is therefore the **LCS-migration seam** — config migrates to the
registry, the state DB stays SQLite forever. peipkg reads configuration
through a single provider interface (a TOML-file implementation now, an
LCS implementation later) so the migration is one contained change.

### Repository config files

One file per repository: `/conf/peipkg/<name>.repo`, the
`sources.list.d` pattern. The file is **fully flat TOML** — every
top-level key maps 1:1 to a future Windows-style registry value, so
every field is a scalar or a list-of-scalars (no nested tables, no
arrays-of-records):

```toml
base_url         = "https://pkgs.peios.org"   # → REG_SZ
priority         = 10                          # → REG_DWORD; lower = higher priority
signature_policy = "required"                  # → REG_SZ; required | optional
trust_anchors    = ["ef86709c…"]               # → REG_MULTI_SZ; one or more 64-hex fingerprints
```

The local handle for a repository is its filename. Configuration is
hand-editable — a trust anchor written into the file *is* the operator
supplying it out-of-band (§6.5.2). `peipkg repo add` is a convenience
that runs the §6.5.2 interactive trust ceremony (fetch descriptor,
display the fetched fingerprint grouped for visual comparison, confirm)
and writes the file. Who may write repository config is the SD on
`/conf/peipkg/`; a rogue `.repo` file is not itself an exploit, since
installing from a repository still passes install-target authority and
signature verification.

### Refresh and trust verification

`peipkg refresh` (and Phase 1, implicitly, when metadata is stale), per
repository:

1. Fetch `repo.json` + `repo.json.sig`.
2. Verify the descriptor signature — against any key that was `active`
   or `transitioning` in the *previously-trusted* descriptor; on
   first-add, against the operator-supplied trust anchors.
3. Adopt the new descriptor as current trust state — its signing keys
   (with statuses) replace the prior set. This propagates key rotation;
   `transitioning` keys are honoured until `valid_until`, `revoked`
   keys never.
4. Fetch the active index + signature; verify against the new
   descriptor's keys.
5. **Freshness gate** (§6.2): reject an `index_version` below the
   recorded floor; reject a `generated_at` below its floor; if both
   *equal* the floor, treat the refresh as no-progress and do not
   advance the last-refresh timestamp (defeats a freeze attack that
   would hold the consumer still while the clock burns past the maximum
   trusted age). On genuine progress, advance the floor counters and
   last-refresh time in the DB.
6. Cache the verified descriptor and index. The archive index is fetched
   only on demand (downgrade, pinning, history), never in a routine
   refresh.

A failed refresh retains the previous trust state and reports — it never
falls back to unverified content (§6.5.4). Repositories are independent;
one failing does not block others.

---

## The resolver

The resolver is a **pure function**: `(request, installed-set,
available-set) → plan | rejection`. Purity gives determinism (§4.2.6
requires the dry-run plan to equal the executed plan), testability, and
safe re-execution under the lock.

- *request* — install / upgrade / uninstall / downgrade, by name or by
  local file (`peipkg install ./foo.peipkg` — the file's own manifest
  becomes a candidate).
- *installed-set* — from the SQLite DB.
- *available-set* — the union of configured repositories' cached active
  indexes, each candidate tagged with its repository and priority; the
  archive index joins only for downgrade/pin.

The resolver **never downloads a `.peipkg`** — it plans entirely from
index and manifest metadata. Fetching is Phase 2.

### The constraint model

The design fixes the *problem representation*; the *algorithm* is an
implementation choice (see below). The model:

- The package universe is real packages **plus virtual packages** —
  each `provides` entry becomes a virtual package whose "versions" are
  its providers.
- Each package has a set of versioned candidates; dependencies and
  conflicts are **version-range constraints** between packages.
- The request is a set of root constraints; a solution assigns
  one-version-or-none per package satisfying all constraints.

This is the SAT-shaped model §4.2 implies. It is the adaptation layer
that lets either algorithm plug in.

### Algorithm

Deferred to implementation time. **pubgrub is the recommended target** —
it fits peipkg well (conflicts map natively to incompatibilities;
versions/ranges map cleanly; cleaner than Debian since peipkg has no
Pre-Depends/Breaks cruft), needs only the adaptation layer above
(`provides` as virtual packages, `!=` as non-contiguous version sets,
candidate ordering by §4.2.4, installed-version bias for upgrades,
pinned decision heuristic for determinism). A greedy deterministic
resolver is an acceptable bootstrap. Either way the design requires
**determinism** (§4.2.6) and a **bounded-work cap** (§4.2.8 — a
backtracking solver can be DoS'd by a hostile dependency graph).

No mature Go pubgrub library is known to exist; an in-house port is
likely. The algorithm is well-documented and bounded work.

### Output

A topologically-ordered operation list (install P@v from repo R / 
upgrade Q v1→v2 / remove S — dependencies before dependents), plus
display metadata for the gate (download size, installed-size delta, new
vs upgraded vs removed) and **confirmation-required annotations**:
downgrades, a non-official repository's `replaces`/`conflicts` hitting a
higher-priority package, low-trust `provides` shadowing an official
package. Optional dependencies are surfaced as suggestions, never
auto-added (§4.2.7). A removal computes the reverse-dependency closure
and hands it to the gate; cascade-vs-refuse is a per-transaction policy.

---

## The execution half

### F1 — atomicity mechanism

Staging + journal + per-file `rename`. `rename(2)` is the only atomic
filesystem primitive available everywhere, and the default Peios root is
a plain single partition (no copy-on-write guarantee). CoW snapshots
(btrfs/ZFS reflinks) are an *opportunistic accelerator* where the
filesystem supports them, never the baseline.

### F2 — the commit model: roll-back-only, SQLite as the boundary

The transaction is a *sequence* of atomic steps that is not itself
atomic. Rather than §7's two-sided (roll-forward + roll-back) journal,
peipkg is **roll-back-only**, and reuses an atomicity primitive it
already has: **the package DB is SQLite, and a SQLite transaction is
atomic.** The SQLite metadata-commit *is* the durability boundary.

The journal is **rows in that same database** — a `txn` table; the
pending transaction is the single row with `state = 'pending'`. There is
no separate journal file, no bespoke format, no HMAC (§7's HMAC binds to
a package-manager principal, which model C does not have; the journal's
protection is its SD, and `elex` later).

Sequence: record intent + backup map (a SQLite write) → apply all file
renames (each individually undoable via backups throughout) → one SQLite
transaction commits the new package state and clears the pending row.
Crash before that commit → roll back file renames from the backup map,
the DB never moved. Crash after → the transaction is complete; clean up.
Side effects run post-commit (see "Side effects").

### F3 — backup data: backup-by-rename

Because every file operation stays within the destination's own
directory (see "rename and EXDEV"), the backup of a replaced or removed
file is made by **renaming the old file to a sibling temporary name** in
the same directory — atomic, zero data copy, filesystem-independent.
Rollback renames it back. CoW reflink is an optional accelerator; a
copy is never needed.

### F4 — post-commit retention

Transaction backups may be retained *after* commit, so a later revert is
instant and offline. Retention is a **knob** (retain for N recent
transactions / N days; modest default). The default must outlast the
time an operator needs to notice a bad package — short in practice.

### F5 — rollback granularity

- **Per-package version rollback** — "revert nginx to the old version."
  Free: it is `install` of an older version via the archive index.
- **Transaction-level undo** — `peipkg history`, `peipkg undo <txn>`,
  reverting a whole multi-package transaction. Included: nearly free
  given F4 retained backups and the recorded transaction history.
- **Full system generations** (Nix/OSTree-style boot-into-a-past-state)
  — out of scope; that is the OS-image/updates layer. peipkg coexists
  with it.

### rename and EXDEV

`rename`/`renameat2` returns `EXDEV` across filesystems — a hard kernel
limit. A transaction can span filesystems (`/var`, `/boot`, `/opt` are
commonly separate mounts). Therefore **the commit never renames across a
directory boundary**: each file is staged as a temporary file *inside
its own destination directory*, then renamed in place — same directory,
guaranteed same filesystem, atomic, `EXDEV` impossible. `/var/lib/peipkg/`
holds the DB and download cache, which are read in place, never renamed
onto another filesystem.

### Temporary file naming

Staging and backup files are named explicitly and visibly, for
post-crash legibility:

- incoming (new content, pre-rename): `<finalname>.peipkg-staged-<txnid>`
- outgoing (old content, the backup): `<finalname>.peipkg-backup-<txnid>`

No leading dot — a visible, clearly-named leftover is what an operator
should trip over and understand. The transaction id ties a stray file to
a row in `peipkg history`. If `<finalname>` plus the marker would exceed
the 255-byte path-component limit (§3.2.7), the `<finalname>` portion is
truncated to fit. peipkg never identifies its temp/backup files by
name-pattern — it records exact paths in the journal and keys all logic
off that; the name is purely for humans.

---

## The extraction layer

### TOCTOU-safe writes

The threat is **footprint escape**, not privilege escalation: a payload
symlink (or a racing process swapping a directory for a symlink) could
redirect a write so the bytes land outside the package's declared
manifest paths. Under model C this is not a confused-deputy escalation —
peipkg has no authority the caller lacks — but it is still serious:

- It **defeats collision/ownership checks**, which reason about
  *declared* paths. A package declaring `/usr/share/myapp/*` could, via
  a planted symlink, land bytes on `/usr/bin/sshd` or another package's
  files without tripping collision detection.
- It **desynchronises the database from disk** — the DB records the
  declared paths, the bytes went elsewhere; uninstall, upgrade-diff and
  integrity checks silently break.

Defence: resolve every install path **fd-relative** (holding a verified
parent-directory fd; operate relative to it, never via a re-resolvable
string path) and **refuse to follow symlinks** —
`openat2(..., RESOLVE_NO_SYMLINKS)` (with `RESOLVE_BENEATH` /
`NO_MAGICLINKS` / `NO_XDEV` as belt-and-braces; trimmable). No symlink
is ever traversed, including one peipkg itself created — a well-formed
package never has a payload file whose ancestor is a symlink, so the
rule fires only on a malformed or hostile package, where aborting is
correct. The justification is **correctness** (peipkg writes exactly the
manifest, nowhere else, so the checks are real and the DB is true), with
partial-trust containment as a secondary benefit. Symlinks as *leaf*
payload entries are created normally; they are simply never traversed.

### Collision / unowned-file policy

Directories never collide — directory creation is idempotent and
packages share directory trees freely (§3.4.10). Only non-directory
entries collide. For a non-directory target path P that already exists:

- **P owned by another installed package** → a genuine conflict, caught
  at *plan* time from the DB, before anything is fetched. (The same
  package being upgraded, or a `replaces` target, is not a conflict.)
- **P unowned** → **fail closed** with a precise error, plus an explicit
  `--overwrite-unowned` escape hatch that *displaces* the existing file
  (renames it aside), never destroys it.
- **P unowned but byte-identical to what would be installed** →
  *adopt*: record the package as owning it, no rewrite, no error. One
  hash compare, zero risk.

Collision is detected best-effort at plan time (so a collision fails the
plan before any download) and authoritatively, fd-relative, at commit.

This policy assumes a **healthy Peios is fully package-owned** — the
peiso base image is built *from* peipkgs with the package database
seeded at image-build time, so an unowned file is a genuine anomaly, not
the everyday case. This is a dependency on the peiso/image layer.

---

## `/etc` / configuration handling

§7.2.2 would replace `/etc` seed config unconditionally on upgrade,
justified by a reconciler framework that does not yet exist. Until it
does, v1 uses **modified-detection**: on upgrade, compare each `/etc`
file's on-disk hash to the hash recorded at install (peipkg stores
per-file hashes regardless).

- Unmodified → overwritten with the new default (the operator gets fresh
  defaults).
- Modified → the operator's file is kept; the new default is written
  beside it as `<name>.peipkg-new`; one line in the install report.

No seed store, no `config` tooling — hand-editing `/etc` is off the
intended path, so this is a corner-case guardrail, not a feature. It
converges to §7's model: when reconcilers arrive they *claim* `/etc`
paths and peipkg defers those, applying modified-detection only to
unclaimed files — an additive change.

---

## Self-upgrade

Upgrading peipkg with peipkg is not special. Replacing the binary of a
running process is fine on Linux (the kernel keeps the old inode mapped
for the live process). "Recovery" reconciles a transaction that crashed
*between* its atomic steps (file renames vs the SQLite commit), not a
half-written file — and the peipkg binary is just one entry in the
backup map, handled like any other file.

The only wrinkle — a different binary version may run the recovery — is
handled by a **versioned journal**: any peipkg that can read the
journal's schema recovers directly; one that cannot defers to manual
recovery mode. No smoke test, no immutable previous-binary copy — both
considered and rejected as over-engineering.

A peipkg upgrade that *commits successfully* but installs a *bad* binary
is not a recovery case (no incomplete transaction). It is a documented
manual procedure: run the retained backup binary by path —
`/usr/bin/peipkg.peipkg-backup-<txn> revert peipkg` — which performs a
normal transactional downgrade. (peipkg is tested heavily before
release; the non-launching subclass is the most testable bug class and
is caught upstream by build-farm pre-publish checks.)

---

## Side effects

The closed set of three (§4.3.4): `ldconfig`, `depmod`, `man-db`. peipkg
invokes each by a **fixed, hardcoded absolute path** — the set is closed
so there is nothing to configure, and §4.3's allowlist-under-a-
recovery-class-SD apparatus was sized for the privileged-PM threat that
model C removes. `PATH` is never searched (correctness — run the real
tool; and a package must not get code run during a future install). They
run with a minimal fixed environment (`LC_ALL=C`, stdin closed),
deduplicated, once per transaction, **post-commit**. A side-effect
failure is a **reported warning, not a rollback** — they are idempotent
(§4.3.2, self-healing on the next run) and the transaction is already
past the durability boundary.

---

## The package database

SQLite in WAL mode at `/var/lib/peipkg/db.sqlite`. WAL gives Phase 1 and
`query` reads a lockless consistent snapshot of committed state while a
transaction is in flight. Seven tables:

| Table | Holds |
|---|---|
| `meta` | key/value — `schema_version` (skew-aware-recovery anchor), `primary_arch` |
| `package` | one row per installed package — `name` (PK), `version`, `architecture`, `origin_repo`, `installed_at`, `manifest` (verbatim, for the resolver) |
| `package_file` | one row per owned path — `package_name`, `path`, `type`, `hash` (files), `symlink_target` (symlinks). The "DB reflects disk" invariant |
| `repository` | per-repo derived state — `name`, `highest_index_version`, `generated_at_floor`, `last_refresh_at`, trust keys |
| `txn` | every transaction — `id`, `state` (pending/committed/rolled-back), timestamps, `op_summary`, `started_by_version`, `journal_schema_version`. The single `state='pending'` row **is the journal** |
| `txn_op` | per-package operations in a transaction — for `history` and undo |
| `txn_file` | per-file actions — `final_path`, `action`, `staged_path`, `backup_path`. The journal's actionable content and the backup map |

Design points:

- **Collision detection is a DB constraint** — a partial unique index,
  `UNIQUE(path) WHERE type != 'dir'`, structurally enforces "no two
  packages own the same non-directory path."
- **The commit is one SQLite transaction** over these tables — that is
  why SQLite-as-the-durability-boundary works (F2); atomicity is
  SQLite's, not something peipkg builds.
- Repository **state** is here; repository **config** is in
  `/conf/peipkg/*` — that boundary is the LCS-migration seam.

---

## Security model summary

- **Authority** is the caller's KACS token; KACS enforces on every real
  file operation. peipkg adds no authority (model C).
- **Integrity**: packages are signature-verified and hash-verified
  before any payload is staged; the full §3.5.3 verification flow is
  followed; all packages in a transaction are verified before any is
  staged (§7.4.3).
- **Audit**: peipkg emits operation events via the `kmes_emit` syscall
  (KMES accepts events; eventd, the drain, does not exist yet — that is
  fine, emission is a local syscall). No fail-closed / retention-journal
  apparatus is needed. The authoritative audit is the kernel's record of
  the file operations.
- **Footprint integrity**: extraction never follows symlinks, so writes
  land on declared manifest paths or fail.
- **System-critical packages**: a small hardcoded set (peipkg itself,
  core system packages) that `uninstall` refuses without
  `--allow-critical`. A foot-gun guard, not a security boundary.
- **Drop-in directories**: a non-official-repo package whose payload
  writes to the top level of a protected `/etc/*.d/` directory is
  rejected at plan time (§3.4.4.1; v1 uses the spec's fixed list).
- **Single-writer**: one transaction at a time, an exclusive lock with
  conservative stale-lock detection (`kill(pid,0)` + start-time check).

---

## CLI surface

Clean long-form verbs, no cryptic flag-soup.

**Lifecycle** — `install <pkg…>` (also `install ./foo.peipkg`),
`upgrade [<pkg…>]`, `uninstall <pkg…>` (`remove` alias),
`downgrade <pkg> [<version>]`.

**Repositories** — `refresh`, `repo add <url>`, `repo remove <name>`,
`repo list`.

**Inspection** (read-only, lockless) — `list [--available]`,
`search <term>`, `info <pkg>`, `owns <path>`, `files <pkg>`, `history`.

**Recovery / maintenance** — `undo <txn>`, `verify [<pkg>]`, `recover`,
`clean`.

**Global flags** — `--dry-run` (Phase 1 only), `-y`/`--yes` (skip the
gate), `--json` (structured output on read commands — Peios
convention), `--overwrite-unowned`, `--allow-critical`.

`refresh` (metadata) and `upgrade` (packages) are deliberately distinct,
unambiguous verbs — avoiding apt's `update`-vs-`upgrade` wart.

---

## Appendix A — divergences from PSD-009 §7

Deliberate divergences (design decisions):

- **No package-manager principal** (§7.6.1). Model C: peipkg runs as the
  caller. §7.6.1's "trust-equivalent-to-root" principal does not exist.
- **Journal tamper-evidence** (§7.4.5.1). No HMAC keyed to a principal
  (there is none); the journal is SD-protected DB rows, `elex`-hardened
  later.
- **Audit transport** (§7.6.3). `kmes_emit` syscall, not an eventd
  socket; the fail-closed / retention-journal / reachability-probe
  apparatus is dropped as unnecessary for a local syscall.
- **Operator authorisation** (§7.6.6). A plain interactive y/n
  confirmation gate, not signed KACS-validated authorisation tokens.

v1 simplifications (lighter now; heavier §7 form deferred — see
Appendix B):

- Recovery-mode authorisation (§7.5.1.5); trust-anchor multi-source
  cross-checking (§7.6.4); clock-sanity gating (§7.6.5); the
  SD-override policy hook (§3.4.7); the side-effect-tool signed
  allowlist (§4.3.2).

All other §7 threats (rollback/freeze, TOCTOU, verify-before-extract,
single-writer, crash recovery, atomicity) are addressed and converge
with the spec.

## Appendix B — deferred / v1 scope

Out of v1 scope, or pending peer subsystems that do not yet exist:

- **SD overrides** (§3.3.5) — deferred, as on the producer side (no KACS
  userland SD encoder yet). v1 installs files with inherited SDs.
- **Clock-sanity gating** (§7.6.5) — the refresh/trust flow assumes a
  sane clock; the §7.6.5 checks are a later addition.
- **Full operator authorisation** (§7.6.6) — depends on unbuilt KACS
  asymmetric-key and event-co-signing primitives.
- **`/etc` reconciler convergence** — depends on the future reconciler
  framework.
- **`/conf/peipkg/*` → registry migration** — depends on LCS.
- **eventd draining** — `kmes_emit` works today; eventd (the drain and
  store) does not exist yet.
- **`elex` hardening** of the package database — optional, when `elex`
  exists.

These track the cross-spec coordination gaps PSD-009 §7.6 itself
enumerates.
