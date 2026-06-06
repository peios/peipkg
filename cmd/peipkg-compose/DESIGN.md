# peipkg-compose — Design

Status: v1 implemented 2026-05-19. The manifest/lock model and
execution shape are settled. The implementation lives in
`internal/compose/` and `cmd/peipkg-compose/`, with `go test ./...`
green; a few minor open questions and deferred refinements remain at
the end.

Sibling document: the consumer design at `peipkg/DESIGN.md`. This tool
reuses that one's machinery and assumes it as read — section
references (§x.y of PSD-009) carry over unchanged.

## What this is

`peipkg-compose` is the **image-assembly** tool: given a manifest
describing a package set, it produces a populated peipkg *root
directory* — the package payloads laid out at their installed paths,
plus a seeded peipkg state database and repository configuration —
such that the directory is a legitimate peipkg-managed system that can
manage itself once booted.

In one sentence: **given a manifest and a set of repositories, build a
fresh, fully package-owned root from nothing — deterministically and
verifiably, with no live system involved.**

It is the counterpart to `peipkg`. `peipkg` brings a *running*
system's package set to a new state, in place, atomically and
reversibly. `peipkg-compose` builds a *new* root offline, from empty.
They share almost all of their machinery (see "Relationship to
peipkg") and differ only in that one mutates and one assembles.

## What this is not

- **An image builder.** compose produces a *directory tree*. It does
  not make a bootable image: no bootloader, no kernel placement, no
  initramfs, no registry/LCS population, no prelude or hook setup, no
  peinit configuration. An outer tool — a future peiso rewrite — does
  all of that, consuming compose's output as its package stage.
  compose's contract stops at "here is a valid peipkg root."
- **A live-system tool.** compose never touches the host's `/`. It
  writes only inside the output directory. It is safe to run on any
  host, including a non-Peios build host and a foreign architecture.
- **The producer side.** It does not build or sign `.peipkg` files or
  serve repositories — that is `peipkg-build` / `-repo` / `-manager`.
- **Spec surface.** compose introduces no on-wire format. It consumes
  PSD-009 packages and repositories exactly as `peipkg` does. Its only
  new formats — the manifest and the lock — are tool-local build
  artifacts, governed by this document, not by PSD-009.

## Relationship to peipkg

compose lives in the **same Go module** as `peipkg`, at
`cmd/peipkg-compose/`. This is not convenience — it is structural.
compose reuses peipkg's `internal/` packages, and Go's `internal/`
visibility rule forbids importing them across a module boundary. One
module, two binaries.

What compose **reuses**, essentially unchanged:

| `internal/` package | Role in compose |
|---|---|
| `version` | Version algebra. |
| `manifest` | Parsing `.peipkg` manifests. |
| `signature` | Descriptor / index / package verification. |
| `repository` | Descriptor fetch, trust verification, index fetch, freshness gate — driven by manifest-supplied config instead of `/conf/peipkg/*`. |
| `resolver` | The pure resolver, called with an **empty installed-set**. |
| `archive` | `.peipkg` open and verify; `archive.Extract` is a standalone payload-extraction primitive. |
| `db` | The package-database **schema**. compose creates and seeds a fresh DB. |
| `config` | The `.repo` TOML writer — compose emits `.repo` files into the output root. |

What compose **does not** reuse — the live-system transaction engine.
peipkg's three-phase Plan/Stage/Commit, the single-writer lock, the
roll-back journal, backup-by-rename, crash recovery, the `/etc`
modified-detection path, and the post-commit side effects all exist
because peipkg mutates a system that must not break. compose builds
into an empty tree: if a run fails, the output is discarded and the
run repeats. None of that machinery applies.

`internal/install` is **not** reused at all — it is the live-system
transaction engine. Its one piece compose might have wanted, the
payload-extraction primitive, already lives decoupled in
`internal/archive` as `archive.Extract`. So compose composes `archive`
+ `db` + `config` directly and never imports `install`.

`internal/audit` is also unused — compose may run off-Peios, where the
`kmes_emit` syscall does not exist. compose's record is the lock file
and a written build report; the *seeded* DB carries the booted
system's own record (see "The output root").

## The model

compose is a thin orchestration over machinery peipkg already has. A
run is three stages, with the manifest and the lock as the two
human-meaningful artifacts:

```
manifest.toml ──▶ [ Resolve ] ──▶ manifest.lock.toml
                                         │
                       [ Fetch + verify ]│
                                         ▼
                              [ Assemble ] ──▶ output root/
```

**Stage 1 — Resolve.** Turn the manifest's *intent* into a concrete
*closure*. The manifest names top-level packages with version
constraints; the resolver expands that to every transitive dependency
at an exact version. The result is the lock. If a lock already exists
and is current, this stage is skipped and the lock is used directly.

**Stage 2 — Fetch + verify.** Download every `.peipkg` in the closure
(or read it from a local cache / build directory), verify its
signature, and verify its content hash against the lock. As in peipkg,
**every package is verified before any is extracted** (§7.4.3).

**Stage 3 — Assemble.** Extract every verified payload into the output
root; seed the state database; write the repository configuration.

There is **no commit boundary** in peipkg's sense, because the output
root is disposable — there is nothing to roll back to. Atomicity is at
the granularity of the *whole artifact*: see "Atomicity".

### Why the manifest and the lock are two files

The manifest is *intent* — what you asked for. It names top-level
packages, not their dependency closure, and may use version ranges.
Two builds from the same manifest, weeks apart, can produce different
roots: the top-level packages are the same, but transitive
dependencies resolve against whatever the repositories serve at the
time.

The lock is the *closure* — every package, transitive dependencies
included, each pinned to an exact version with a content hash. It is
what makes a build reproducible. A build from a lock needs no live
repository metadata and no resolution; it is a deterministic
function of the lock alone.

A date-stamped manifest filename (`peipkg-manifest-2026-6-1.toml`) is
a trap worth naming explicitly: it *looks* like a reproducibility
artifact and is not one. It records what was asked for, not what was
produced. The lock is the receipt. For an image to genuinely rebuild
byte-for-byte, the lock — not the manifest — is the thing an outer
tool must archive.

The lock is generated, never hand-edited. The manifest is the input.
Keeping them as two files means no tool ever rewrites a file a human
also edits, and the lock can be reviewed as a self-contained diff.

## The manifest

A manifest is TOML. Unlike a `.repo` file — which is deliberately flat
because every key maps to a future registry value — the manifest is a
build-tool input, never registry-bound, so it uses idiomatic TOML
freely: tables and arrays-of-tables.

```toml
# peipkg-compose manifest
schema      = 1
arch        = "x86_64"
source_date = "2026-06-01T00:00:00Z"  # see "Determinism"

# .peipkg files on disk that join the candidate set — for bootstrap
# builds whose packages are not yet in any published repository.
# A top-level key, so it precedes the first [[table]].
local_packages = ["./build/out/*.peipkg"]

[[repository]]
name             = "official"
base_url         = "https://pkgs.peios.org"
priority         = 10
signature_policy = "required"
trust_anchors    = ["ef86709c4b1d8a02e5f3c719d640aa8b7c2e9105f8d3b6470a1c2e9d8b5f3a04"]

[[repository]]
name     = "internal"
base_url = "https://pkg.corp.example"
priority = 20

[[package]]
name    = "base"
version = "*"

[[package]]
name    = "nginx"
version = ">=1.27, <1.28"

[[package]]
name    = "openssh"
version = "9.9.1"
```

- **`[[repository]]`** entries carry the same fields as a `.repo`
  file. compose uses them two ways: to fetch and trust-verify metadata
  during the build, and — written verbatim — as the output root's
  `/conf/peipkg/<name>.repo` files, so the booted system inherits the
  same repositories.
- **`local_packages`** lets `.peipkg` files on the build host join the
  resolver's candidate set, exactly as `peipkg install ./foo.peipkg`
  makes a local file a candidate. This is the bootstrap path: building
  the first Peios image, when packages exist only as build output.
- **`[[package]]`** entries are top-level *wants*, each a name and a
  version constraint. A constraint may be a range or an exact pin —
  both are just constraints to the resolver. An optional
  `repository = "official"` pins where a package is sourced from.
- **`source_date`** fixes every build-time timestamp (see
  "Determinism"). It is the manifest's `SOURCE_DATE_EPOCH`.

## The lock

The lock is the resolved closure: one entry per package, transitive
dependencies included, sorted by name so a lock diff is clean.

```toml
# generated by peipkg-compose — do not hand-edit
schema      = 1
arch        = "x86_64"
source_date = "2026-06-01T00:00:00Z"
manifest    = "peipkg-manifest-2026-6-1.toml"

[[package]]
name         = "base"
version      = "3.2.0"
architecture = "x86_64"
source       = "official"
url          = "https://pkgs.peios.org/pool/base-3.2.0.x86_64.peipkg"
hash         = "sha256:1f3a…"

[[package]]
name         = "nginx"
version      = "1.27.5"
architecture = "x86_64"
source       = "official"
url          = "https://pkgs.peios.org/pool/nginx-1.27.5.x86_64.peipkg"
hash         = "sha256:9c20…"

[[package]]
name         = "zlib"
version      = "1.3.2"
architecture = "x86_64"
source       = "official"
url          = "https://pkgs.peios.org/pool/zlib-1.3.2.x86_64.peipkg"
hash         = "sha256:7be4…"
```

The **content hash is what earns the lock its keep.** A build from the
lock fetches each package by URL and verifies it against the recorded
hash. The trust chain — descriptor signature → index signature →
the name/version/hash mapping — is verified once, at *lock time*,
when the closure is resolved. The hashes the lock records carry that
verified trust forward. A `--locked` build therefore needs no
descriptors and no network beyond fetching the bytes: it gets
integrity from the hash and inherits authenticity from the lock,
which the operator vouched for by reviewing and archiving it.

This is what makes **air-gapped builds** trivial: the lock enumerates
exactly which files are needed and exactly what each must hash to, so
they can be staged into a local directory and the build run with no
repositories reachable at all.

A `source = "local"` entry records a `local_packages` file by path and
hash instead of a URL.

## Command surface

Two verbs.

```
peipkg-compose lock  <manifest> [-o <lock>]
peipkg-compose build <manifest> --out <dir> [--locked] [--update]
```

**`lock`** runs Stage 1 only: resolve the manifest, verify the trust
chain, write the lock. Output defaults to `<manifest-stem>.lock.toml`
(`peipkg-manifest-2026-6-1.toml` → `peipkg-manifest-2026-6-1.lock.toml`
— shared stem, so the pair sorts adjacent; `.toml` stays the terminal
extension so editors and tooling treat it as TOML). This verb exists
so an orchestration layer can pin a closure without building.

**`build`** produces the root. Given a manifest, if a current sibling
lock exists it builds from it; otherwise it resolves, writes the lock,
and builds — the Cargo `build`/`Cargo.lock` behaviour.

- **`--locked`** requires the lock: build from it, never resolve, fail
  if it is missing or stale. This is the CI / orchestration mode.
- **`--update`** ignores any existing lock, re-resolves, rewrites it.

compose runs **unattended** — it has no interactive gate. peipkg's
`proceed?` confirmation and its §7.6.6 elevated-authorisation prompts
(downgrade, foreign `replaces`, low-trust `provides`) have no operator
to answer them here. The substitute: the resolver's
confirmation-required conditions are recorded as **annotations in the
lock**, and reviewing the lock before archiving it *is* the gate. Where
peipkg's elevated-authorisation "fails closed with no terminal,"
compose is always no-terminal — so those conditions must be resolved
at lock-authoring time, by the human who reviews the lock, never at
build time.

Global flag conventions (`--json` on read output, etc.) follow
peipkg's.

## The output root

compose produces, under `--out`:

- **The package payloads** — every file, directory, and symlink in the
  closure, at its manifest path.
- **`var/lib/peipkg/db.sqlite`** — the seeded state database (below).
- **`conf/peipkg/<name>.repo`** — one file per manifest repository, so
  the booted system inherits its repositories and trust anchors.

Nothing else. No `/boot`, no kernel, no registry, no prelude — the
outer tool's responsibility.

### Seeding the database

peipkg's own design *depends* on this step. `peipkg/DESIGN.md` states
the collision/ownership policy "assumes a healthy Peios is fully
package-owned … the base image is built from peipkgs with the package
database seeded at image-build time." **compose is that step.** A
composed root has no unowned files — it starts empty and only compose
writes to it — so every file is package-owned by construction, and
the assumption peipkg's design names is something compose *makes
true*, not something it hopes for.

compose creates a fresh `db.sqlite` with peipkg's schema and seeds it:

- `meta` — `schema_version`, `primary_arch`.
- `package` — one row per package, with the verbatim manifest the
  resolver will later need.
- `package_file` — one row per owned path. The `UNIQUE(path) WHERE
  type != 'dir'` index gives compose **collision detection for free**:
  if the closure has two packages claiming one non-directory path, the
  insert fails and the build is rejected.
- `txn` / `txn_op` / `txn_file` — left **empty**. `peipkg`'s
  transaction-row timestamps come from `time.Now()`, so seeding a
  synthetic transaction would inject a wall-clock time into a
  data-level reproducibility surface. The booted system's first real
  install is its first transaction; `peipkg history` is empty until
  then. A synthetic build-marker transaction can be added later if
  `peipkg` grows an injection point for the timestamp.

compose does **not** seed the `repository` table or the index cache.
Repository trust is *derived* state, and `peipkg refresh` already
bootstraps a configured-but-unrecorded repository by running the full
trust ceremony from its `.repo` anchors. The `.repo` files compose
writes are therefore sufficient: the booted system establishes
repository trust on its first `refresh`, exactly as a freshly-added
repository does. Leaving it out also keeps a `--locked` build's output
identical to a resolved build's — neither depends on descriptor state
that an air-gapped `--locked` build never fetched.

### What compose deliberately does not do

- **No side effects.** peipkg runs `ldconfig` / `depmod` / `man-db`
  post-commit. compose runs none of them — they would run the *build
  host's* tools against a possibly-foreign root. They are deferred to
  first boot or to the outer tool. This is also what makes compose
  safe **cross-architecture**: it executes no package code and runs no
  binaries, so an x86_64 host can compose an aarch64 root.
- **No KACS security descriptors.** SDs are a Peios-kernel concept;
  the build host may not be Peios, and a fresh root has no SDs to
  inherit from. compose writes plain files. SD materialisation belongs
  to image finalisation / first boot — which aligns with peipkg v1
  itself deferring `sd_overrides` (no userland SD encoder yet).
- **No audit emission.** Covered above — the lock is the record.

## Atomicity

The unit of atomicity is the **whole output directory**, not the
individual file. compose assembles into a staging directory that is a
sibling of the requested `--out` path (guaranteeing the same
filesystem), and on success renames it into place. The `--out` path
therefore either does not exist or is a complete root — never a
partial one. A failed or interrupted run leaves the staging directory,
clearly named, for inspection or deletion; it is never mistaken for a
finished root.

This is far simpler than peipkg's per-file journal, and correctly so:
compose has no prior state to preserve and no concurrent reader to
protect, so the single whole-tree rename is all the atomicity the job
needs.

## Determinism

Reproducibility is a first-class goal: the same lock must produce a
byte-identical root. compose is built so that the inputs are all
pinned and nothing wall-clock-dependent leaks in.

- **Resolution** is already deterministic — peipkg's resolver requires
  it (§4.2.6).
- **Versions and content** are pinned by the lock.
- **Timestamps** in the seeded DB (`installed_at`, the synthetic
  transaction's times) come from the manifest's `source_date`, never
  from the wall clock.
- **Extraction** writes payloads verbatim, with file metadata taken
  from the package; compose injects no per-run variation. Extraction
  order does not affect the tree, so payloads may be extracted in
  parallel.

Reproducibility is defined over the **data**, not the container. The
seeded database's rows are fully determined by the lock and
`source_date`; the on-disk `.sqlite` file's page layout and freelist
are not byte-stable across builds, and deliberately are not made so —
chasing a byte-identical container (fixed page size, deterministic
insert order, `VACUUM`) buys nothing the data-level guarantee does not
already give. A consumer comparing two roots compares their package
data, not their `.sqlite` bytes.

## Open questions

1. **Lock provenance.** Should the lock record which descriptor key
   fingerprints were trusted at lock time, for audit and review? Leans
   optional / nice-to-have.
2. **Lock transparency.** Should each lock entry record *why* it is in
   the closure (`required_by`), or stay a flat list? Leans flat for
   v1, with `required_by` a later additive field.

## Deferred / v1 scope

- **SD overrides** — deferred, exactly as on the producer and consumer
  sides; compose writes plain files, SDs are established downstream.
- **Side-effect execution** — never compose's job; first boot or the
  outer tool.
- **Registry-sourced repository config** — compose reads repositories
  from the manifest and writes `.repo` files; when LCS lands and
  peipkg's config moves into the registry, the outer tool owns that
  migration, not compose.
- **Elevated-authorisation annotations in the lock** — the resolver's
  §7.6.6 conditions (a low-trust `provides`, etc.) are currently
  surfaced as warnings on `stderr` during resolve. The intended
  long-form — record them on the lock so the review authorises each
  deliberately, with no-annotation builds failing closed — depends on
  a lock-schema annotation field that v1 does not carry.
- **Parallel package fetch** — v1 fetches sequentially. The fetches are
  independent and trivially parallelisable when build times warrant it.
- **Streaming extraction** — v1 holds each fetched `.peipkg` in memory
  until assemble has consumed it; total memory ≈ total package size.
  A build with many large packages may need to stream payloads through
  a per-package temp file instead.
- **Synthetic build-marker transaction** — left empty in the seeded DB
  because `peipkg`'s transaction timestamps come from `time.Now()`. A
  follow-on can seed one once `peipkg` accepts an injected timestamp.
