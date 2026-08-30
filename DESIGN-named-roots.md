# peipkg — Named Roots & Cross-Root Dependencies

Status: **slices 1–3 + producer side built and tested; slice 4 built and
tested — multi-root resolver, cross-root 2PC executor wired into install,
cross-root recovery (roll-back-all + roll-forward of a torn commit) and
cross-root undo-as-a-unit. The only remaining item is cross-root
autoremove/GC, deferred because there is no single-root autoremove base to
extend yet (2026-06-24).** Converged across a design pass on 2026-06-24;
see "Suggested build order" for the per-slice state. This document is a companion to `DESIGN.md` (the
implemented consumer design) and assumes it; section references of the
form *(DESIGN.md → "X")* cite it. Where this and `DESIGN.md` overlap,
this document extends — it changes no decided mechanic, only generalises
the install **root** from a single bare path into a first-class,
named, composable target.

Spec coordination: two pieces of this touch the **package format**,
which PSD-009 chapters 1–6 own authoritatively (DESIGN.md → "Relationship
to PSD-009") — the manifest `default_root` field and the dependency
placement field. **Both are now landed in PSD-009 v0.22** (the open
draft): `default_root` in §3.3 (with the root-reference grammar in
§3.3.6), the dependency `root` field in §4.1.1, and both reflected in the
repository index (§6.2.4) and the schema appendix (§9b.1). They are
optional fields, so `schema_version` stays **1** (the manifest's
forward-compatible-extension rule, §3.3). In the JSON manifest the
placement field is `root` on a dependency object; the `IN <root>` form is
producer-side recipe sugar (pekit) that lowers to it. Everything else in
this document is chapter-7-class consumer behaviour.

## What this is

Today peipkg installs into a single root chosen by a bare `--root`
path string, defaulting to `/` (DESIGN.md → root threading). This adds:

1. **Named roots** — a root can be registered under a name
   (`initramfs = boot/initramfs`) so `--root initramfs` resolves the
   name instead of repeating a path. Names compose by dotting
   (`initramfs.subroot`).
2. **`default_root`** — a manifest may name the root a *top-level*
   install lands in, so `peipkg install live-boot` can target `initramfs`
   without `--root`.
3. **Cascade upgrade** — `peipkg upgrade` reconciles a root **and** its
   named roots, so the whole multi-root system stays coherent from one
   command.
4. **Cross-root dependencies** — a package's dependency may be placed in
   a *different* root than the depender, so an entire `initramfs` can be
   composed out of ordinary packages through the dependency graph.

The motivating system is Peios's dynamic initramfs: a real root at `/`
and an initramfs image at `boot/initramfs`, built and kept current by the
same package manager that owns the main system. The feature is
generalised beyond two roots deliberately — package management is
foundational substrate; a need found once is over-built so it covers the
needs not yet seen.

## Why this is not a hack

The enabling fact is that peipkg's database is **already fully per-root**
(DESIGN.md → "The package database"): each root carries its own
`<root>/var/state/peipkg/db.sqlite`, journal, staging area, and cache, and
its own `<root>/lcl/conf/peipkg/*` config. A "named root" introduces no new
storage model — it is a name→path indirection plus one small registry
table. The same physical separation is what makes cross-root
dependencies clean rather than dangerous: there is no shared, mutable
global identity to corrupt (see "Identity").

Prior art de-risks the concept. Gentoo/Portage already routes different
*classes* of a package's dependencies to different roots — `BDEPEND` to
the build host `/`, `RDEPEND` to the target `ROOT=` — and has for years,
in production, for image building and cross-compilation. The novel step
here is generalising that fixed two-root (host/target) split into an
**open set of operator-named roots, with per-edge placement, composable
to arbitrary depth.** The concept is proven; the generality is new.

---

## Foundational decisions

### D1 — A root is a path; a *named* root is a registry entry

The unit of installation is unchanged: a filesystem root holding a
self-contained peipkg DB. A **named root** is a row in a per-root
registry table mapping a name to a path *relative to the root that owns
the registry*. Relative storage keeps a whole root tree relocatable.

The registry lives in the **owning root's own database**, not a global
config file. The `/` root's DB is therefore the natural anchor for the
system's roots; making the registry a DB object (not config) is what
lets upgrade cascade and cross-root GC see roots as fact rather than
intent — the same config-vs-state line peipkg already draws
(DESIGN.md → "Configuration vs state").

### D2 — `--root` resolution: path-like is literal, bare-name is a registry lookup, and an unknown name is an error

One rule, fully backward-compatible with every existing invocation:

- The value **contains `/`**, or starts with `/`, `./`, or `../` →
  **literal filesystem path.** Today's behaviour, untouched. `--root /`,
  `--root /mnt/target`, `--root ./build/root` all mean exactly what they
  mean now.
- The value is a **bare dotted identifier** (`initramfs`,
  `initramfs.subroot`) → **named-root reference.** Each segment is a
  registry name; resolution recurses (see D3).
- A bare identifier that **is not registered** is a **hard error** — never
  a silently-created root, never a fallback to a relative path. To target
  a relative path that happens to look like a name, write `./initramfs`.

The last point is the load-bearing safety property. A typo
(`--root initrams`) fails loudly instead of staging an image into a
junk directory named after the typo. It is the same "never auto-create,
never guess" stance peipkg takes elsewhere.

Name grammar: a segment is `[a-z0-9][a-z0-9_-]*`. `.` is reserved as the
nesting separator and may not appear within a segment; `/` may not appear
at all (its presence is precisely what marks a literal path).

### D3 — Nested roots: flat per-root registries, dotted names, recursive resolution

Each root's registry is **flat** — names to relative paths, one level.
Depth comes from chaining flat lookups, so every root self-describes only
its own children:

Resolving `initramfs.subroot`, anchored at `/`:

1. Open `/`'s DB → look up `initramfs` → `boot/initramfs` →
   `/boot/initramfs`.
2. Open `/boot/initramfs`'s DB → look up `subroot` → join → the path.

The `/` root is the implicit anchor for a reference's first segment.
Because resolution is "open that root's DB and ask it," **registration
composes through the same mechanism**: `peipkg root add initramfs
boot/initramfs` writes the current root's registry, and a sub-root is
just `peipkg --root initramfs root add subroot <path>` — `--root
initramfs` already resolves to that root, and `root add` writes *its*
registry. No special-casing for depth.

A resolution cycle (a registry pointing back into an ancestor) is
rejected via a visited-set of resolved absolute paths. A registered root
whose path no longer exists is **dangling**: read paths (resolution for a
query) report it; write paths (install/upgrade targeting it) error, and
cascade upgrade skips it with a warning rather than aborting.

---

## `default_root` — top-level placement only

A manifest gains an optional `DefaultRoot string` field. Its job is
**narrow and singular**: it chooses the target root for a **top-level**
install — `peipkg install X` with no `--root`. Precedence:

1. Explicit `--root <ref>` on the command line — **always wins.**
2. Else the manifest's `default_root`, resolved as a named reference
   (D2/D3) against the current registry. Unregistered → **hard error**
   (never auto-create).
3. Else the current root (`/` by default).

`default_root` does **not** govern where the package goes when it is
pulled in as a *dependency* — that is the dependency edge's concern (see
"Placement"). The two have disjoint jobs and never arbitrate against each
other. This separation is deliberate and was the crux of the design;
"Identity" explains why the alternative (making `default_root`
authoritative for deps too) was rejected.

---

## Cross-root dependencies

**Every verb resolves multi-root.** `install` did from the start;
`uninstall`, `upgrade` and `downgrade` followed once the first package
with a cross-root edge existed in `/` (the edition package, which holds
its initramfs hooks `IN initramfs`). Under the earlier "single-root call
sites unchanged" contract those verbs evaluated such an edge against the
depender's own root — where it was never meant to be — so every removal
in `/` was refused for a dependency that was whole in the initramfs. Now
each verb gathers every reachable root, routes each request (a named
upgrade to the roots holding the package; the rest to the anchor), and
commits as one cross-root transaction. `upgrade --no-recurse` is the
single-root escape hatch. The single-root `Resolve` entry point remains
for callers with no root topology.


The powerful half. A dependency may resolve into a root other than the
depender's, so a root can be **composed through the dependency graph** —
`live-boot-irf` (living in `initramfs`) depending on `peiosutils` pulls
`peiosutils` into the initramfs, no per-package forking required.

### Identity — a package is `(name, root)`

In a multi-root world the identity of an installed package is the pair
**(name, target root)**, not the name alone. `peiosutils@/` and
`peiosutils@/boot/initramfs` are two independent installs, possibly at
**independent versions** — and that is a feature: an initramfs may
legitimately lead or lag the real root. There is no contradiction to
resolve because the two records live in two physically separate
databases; the per-root DB model already makes (name, root) the real
identity. Every reference carries its root (explicitly via `IN`, or
implicitly the depender's), so "is this dependency satisfied?" always
names exactly one DB to consult — satisfaction, version solving, and GC
stay unambiguous.

This is why `default_root` is **not** authoritative for dependency
placement. The rejected model — "a package has one intrinsic home root;
`IN` only asserts it" — quietly destroys the use case: if `peiosutils`'
home is forever `/`, then *nothing* can place it into an initramfs, and
composing a root from stock packages becomes impossible without forking
every package into a `-irf` twin. (name, root) identity is what makes
placement a free choice instead of a property baked into the package.

A package therefore **cannot forbid being placed outside any particular
root.** This is intentional. A package declares what it *is* and what it
*needs*; it never declares filesystem-placement policy. Placement is the
composer's prerogative, not the packager's. No `root_lock` / `pin_root`
field exists — granting packages that degree of filesystem control would
strip exactly the composition flexibility this feature exists to provide.

### Placement — depender's root by default, `IN <root>` to cross

- A dependency lands in the **depender's** root by default. So
  `live-boot-irf` (target `initramfs`) with `Depends: peiosutils` places
  `peiosutils` **into `initramfs`** automatically — deps flow to where
  the thing that needs them lives. This is what makes graph-composed
  roots ergonomic: annotate nothing, and a root's dependency closure
  fills that root.
- **`IN <root>`** on a dependency overrides placement to a named root.
  `Depends: foo IN initramfs` sends `foo` to `initramfs` regardless of
  the depender's root. `<root>` is a named reference resolved as in
  D2/D3 against the anchor registry.

`IN` is the **explicit, auditable opt-in to cross a root boundary.**
Crossing is never silent: a dependency only leaves the depender's root if
its declaration says so. The CLI reinforces this — see "Loud plans."

### The multi-root resolver

The resolver (DESIGN.md → "The resolver") stops being single-root. Its
installed-set becomes a **map keyed by resolved root path**, opening each
target root's DB lazily as the closure routes packages there. The plan it
emits is a list of `(action, package, target-root)` triples rather than
`(action, package)`. Constraint solving is per-(name, target-root):
version floors/conflicts for `foo IN initramfs` are checked against the
`initramfs` DB and the available index for that root; the same name in
two roots is two independent sub-problems, and an across-root version
difference is not a conflict.

Availability and fetch, in v1: a cross-root dependency is resolved
against and fetched from the **anchor root's** repositories — the root
where the operation was invoked. Fetch is anchor-level (uses `/`'s repos
and download cache); **staging and the DB record are target-root-level.**
A composed root such as `initramfs` therefore needs **no repositories of
its own** to receive cross-root dependencies. (A root's *own*,
directly-installed packages still use that root's own repos — strictly
per-root, as the current temporary repo system requires. The repo system
is a placeholder pending registry integration, DESIGN.md →
"Configuration vs state"; this split is not worth special inheritance
machinery now.)

---

## Execution

Two multi-root execution shapes, with a deliberate and important
asymmetry: **a dependency closure is one transaction; a cascade of
independent roots is not.**

### Cross-root install/upgrade — one logical transaction (2PC-shaped)

A single `peipkg install live-boot` may touch two roots, and the result
must be all-or-nothing: `live-boot` present without the `initramfs`
component it needs is a broken boot, not a partial success. True
cross-database atomicity is impossible (N roots = N SQLite durability
boundaries, DESIGN.md → F2), so the existing roll-back-only model is
extended into a **two-phase commit** over the participating roots:

1. **Plan.** Resolve the full multi-root plan (lockless, abortable —
   DESIGN.md → Phase 1).
2. **Acquire** every participating root's single-writer lock, in
   **resolved-absolute-path lexical order** (a total order ⇒ no deadlock
   between concurrent cross-root operations). Release in reverse.
3. **Prepare (vote).** Stage + verify *every* root's payloads
   (DESIGN.md → Phase 2 mechanics: verify-all-before-stage-any, per-file
   hash check, backup-by-rename F3). A root that stages and verifies
   cleanly has "voted to commit."
4. **Commit.** Flip each root's SQLite boundary (DESIGN.md → F2) in path
   order. Each root's `txn` row carries a shared **`cross_root_id`** so
   the commits are recognisable as one logical transaction.
5. **Recover.** A crash in the commit loop leaves some roots committed
   and some prepared-but-pending under one `cross_root_id`. Because every
   root was already staged-and-verified in step 3, recovery **rolls
   forward**: replay the remaining commits to completion. Only if a
   remaining commit *cannot* succeed (e.g. ENOSPC) does recovery fall
   back to **roll-back-all**, reverting the already-committed roots from
   their retained backups (DESIGN.md → F4). `peipkg recover` performs
   this reconciliation, keyed on `cross_root_id`.

The residual non-atomic window is just the commit loop; it is detectable
(the shared id over mixed `state`s) and resolved deterministically. This
is the standard prepare/commit shape — stage-all is the prepare phase in
which each root votes by verifying successfully.

### Cascade upgrade — independent roots, continue-on-error

`peipkg upgrade` reconciles the current root **and**, by default, its
named roots, recursively (current root + its registry + their
registries…). `--no-recurse` confines the operation to the current root.

Unlike a dependency closure, the roots visited by a cascade are
**independent** — each is its own transaction against its own repos, and
a failure in one says nothing about another. So the cascade is
**continue-on-error**: a failed root does not abort the rest; the command
walks every reachable root, then prints a per-root **success / fail /
skip** summary (skip = dangling, D3). Cycles and double-visits are guarded
by a visited-set of resolved absolute paths.

Note the interaction with cross-root deps: a package that lives in
`initramfs` *because a `/`-rooted package pulled it there* is upgraded as
part of **`/`'s** transaction (re-resolving that depender's closure, one
cross-root transaction above), **not** by the cascade's visit to
`initramfs`. The cascade's visit to `initramfs` upgrades only what was
installed into `initramfs` **directly** (top-level `--root initramfs
install …`). The two paths are complementary and do not double-act on the
same package.

### Removal and GC cross the boundary

A cross-root dependency edge is recorded **with its target root** (see
"DB additions"), so reverse-dependency lookup and autoremove/GC follow
the edge into the other root instead of orphaning the dependency.
Removing `live-boot` from `/` can therefore correctly identify and
collect the `initramfs` components it alone kept alive. GC's reverse-dep
scan spans roots — the same multi-root capability the resolver gained.

### Loud plans

Because "install X" mutating a *second* filesystem image is unfamiliar,
the presented plan (DESIGN.md → Boundary A) must make cross-root effects
unmissable: each action is tagged with its target root (`→ initramfs`),
and any plan that touches a root other than the anchor surfaces that
prominently before the confirmation gate. The explicit `IN` requirement
keeps the *graph* honest; loud plans keep the *operator* informed.

---

## CLI surface (additions)

Extends DESIGN.md → "CLI surface"; same clean long-verb style.

**Roots** — a new verb group:

- `root add <name> <path>` — register `<name>`→`<path>` in the current
  root's registry (`<path>` stored relative to it).
- `root remove <name>` — unregister. Files are left in place by default;
  `--purge` deletes the root's tree.
- `root list [--tree]` — list the current root's registry; `--tree`
  recurses through children.
- `root show <name>` — resolve a reference and report its path, status
  (present / dangling), and installed-package count.

**Resolution everywhere** — `--root <ref>` accepts a named reference,
a dotted nested reference, or a literal path (D2), on every command that
takes `--root`.

**Upgrade** — `upgrade` cascades by default; `--no-recurse` confines it
to the current root.

**Recovery** — `recover` additionally reconciles cross-root transactions
by `cross_root_id` (roll-forward, else roll-back-all).

---

## DB additions

Per-root schema gains one table and one column (one new migration,
following the `0003_claims.sql` precedent):

| Object | Holds |
|---|---|
| `named_root` (new table) | the registry — `name` (PK), `path` (relative to this root), `created_at` |
| `txn.cross_root_id` (new column) | nullable; groups the per-root `txn` rows of one cross-root transaction. NULL for ordinary single-root transactions |

The cross-root **dependency edge** is recorded so removal/GC can follow
it. The minimal form is, on each installed package's dependency record,
the **resolved target root** of that dependency (the depender's root, or
the `IN` target). Concretely this is a target-root column on the
per-package dependency rows the resolver already needs for reverse-dep
queries; packages that depend only within their own root carry their own
root there, so single-root behaviour is unchanged.

No change to `package` / `package_file` identity within a root: paths
remain absolute-under-their-root and the
`UNIQUE(path) WHERE type != 'dir'` collision constraint
(DESIGN.md → "The package database") is **per-root**, exactly as the
per-root DB already implies.

---

## Suggested build order

Mirrors how claims went out (manifest → db → engine → CLI), each slice
independently testable:

1. **Registry + resolver front-end.** ✅ **Built (2026-06-24).**
   `named_root` table (migration `0004_named_root.sql`, schema v4) +
   `internal/db/namedroot.go` accessors; the `--root` reference resolver
   (D2/D3) in `internal/cli/root.go` (`resolveRootRef`), wired into `Run`
   in front of the existing bare-path threading (DESIGN.md → root
   threading) with the system anchor `/`; `root add/remove/list/show`
   (`--tree`, `--json`, `--purge`). Pure single-root behaviour is
   unchanged; named roots work for install/upgrade/query against one root
   at a time. *Independently shippable and useful on its own.* Tested:
   `internal/db/namedroot_test.go`, `internal/cli/root_test.go`.
2. **`default_root`.** ✅ **Built (2026-06-24).** Consumer manifest field
   (`internal/manifest`: `DefaultRoot`, `Dependency.Root`, exported
   `ValidateRootRef` for the §3.3.6 grammar) decoded from the manifest and
   the repository index entry (§6.2.4); top-level placement precedence in
   `cmdInstall` (`topLevelTargetRoot`): explicit `--root` wins, else the
   requested packages' single shared `default_root` re-roots the install,
   else the current root; divergent declared roots are rejected. `Run`
   tracks whether `--root` was explicit. Still single-root per operation.
   Tested in `internal/manifest/manifest_test.go`, `internal/cli/root_test.go`.
3. **Cascade upgrade.** ✅ **Built (2026-06-24).** `cmdUpgrade` cascades by
   default (`cascadeUpgrade` + `gatherUpgradeRoots`): current root + named
   roots recursively, visited-set on resolved abs paths, dangling roots
   skipped with a warning, named-package upgrades confined per root,
   continue-on-error with a per-root `N upgraded / N failed / N skipped`
   summary; `--no-recurse` confines to the current root (and the
   no-named-roots fast path is byte-for-byte the old behaviour). N
   independent transactions, no new transaction semantics. Tested in
   `internal/cli/root_test.go`.
4. **Cross-root dependencies.** *Steps 1–2 built (2026-06-24); step 3
   (recovery/GC/undo) pending.* **Step 2 (cross-root 2PC executor, wired
   into install) is done.** The executor (`internal/install`) splits a
   transaction into a prepare phase (fetch, verify, journal, move payloads
   into place — a root's "vote") and a commit phase (the per-root SQLite
   durability boundary); `ExecuteCrossRoot` runs the two phases across
   roots: acquire every participating root's lock in resolved-path order,
   reconcile pending journals, prepare all roots, then commit all in path
   order. A prepare failure rolls every voted root back (system unchanged);
   a commit failure leaves the rest prepared for `peipkg recover` to roll
   forward (already-committed roots stay committed). The journal rows
   share a `cross_root_id` (`BeginCrossRootTxn`); `recoverPending` now
   *refuses* to roll back a cross-root participant in isolation (the guard
   that prevents a torn state — full reconciliation is step 3). CLI: a
   `peipkg install` resolves through `ResolveMultiRoot` (transact gathers
   `refToPath` from the registry + every reachable root's installed set),
   and a plan spanning >1 root commits via `ExecuteCrossRoot` over per-root
   envs that share the anchor's package provider (anchor-level fetch,
   target-root staging); plans are "loud" (each cross-root op tagged `->
   root`, plus a note before the gate). Tests: `internal/install/
   crossroot_test.go` (happy 2-root commit, prepare-failure rolls back
   all, recover-guard) and `internal/cli/e2e_test.go`
   TestCrossRootInstallEndToEnd (repo → live-boot in anchor + peiosutils
   `IN initramfs`, shared cross-root id). **Step 1 (multi-root resolver)**
   is done: `internal/resolver` is now multi-root. Identity is the
   `(root, name)` pair (flat `world` keyed by a `root\x00name` composite,
   each `worldPkg` carries its `root`); `Resolve` keeps its exact
   single-root signature and semantics (the dependency `root` field is
   inert there — single-root has nowhere else to place a dep, so existing
   callers incl. compose are unaffected), and a new `ResolveMultiRoot`
   honours placement: a dep stays in its depender's root by default,
   `routeRoot` sends a named `root` to its resolved path via a
   caller-supplied `refToPath` (an unregistered reference → hard
   rejection). Conflicts/version checks are per-root; plan ordering
   follows edges across roots; `Operation` gained a `Root` field (empty
   for single-root plans). Pure unit tests in
   `internal/resolver/multiroot_test.go` lock the semantics (explicit
   placement, depender-default closure flow, same-name-version-in-two-
   roots-not-a-conflict, per-root satisfaction, independent versions,
   unregistered-root rejection, single-root inertness). ALSO DONE earlier:
   the dependency `root` field flows end to end —
   `manifest.Dependency.Root` is decoded and stored verbatim in the
   package table's manifest blob, so a cross-root edge is already
   *recorded* and a future GC reverse-dep scan can read it; the
   `cross_root_id` transaction-grouping column (migration
   `0005_cross_root_txn.sql`, schema v5, with `idx_txn_cross_root`) is in
   place, nullable and NULL for every single-root transaction. **Step 3 (recovery + undo-as-unit) is done.** `peipkg recover`
   (`cmdRecover` + `install.RecoverCrossRoot`, DB query
   `TxnsByCrossRootID`) discovers a cross-root transaction's participants
   by walking the registry for rows sharing a `cross_root_id`, locks them
   in path order, and reconciles: **no participant committed → roll back
   all** (the common interrupted case — a crash during prepare or before
   the commit loop committed anything); **some committed → torn commit,
   refuse with a precise report** (it cannot un-commit a committed root,
   and roll-forward needs metadata not yet persisted). `peipkg undo` of a
   cross-root transaction reverses every participating root as one new
   cross-root transaction (`undoCrossRoot` + `crossRootInverseRequests`),
   so it never tears the install by undoing only the anchor's half.
   Tested: `internal/install/crossroot_test.go` (recover roll-back-all,
   torn-refuse) and `internal/cli/e2e_test.go` TestCrossRootUndoEndToEnd.

   **Roll-forward is now built (2026-06-24).** The forward commit state
   (package rows + files + claim holders/links) is persisted at prepare
   time as a self-versioned `commit_payload` JSON blob on the txn row
   (migration `0006_commit_payload.sql`, schema v6; `db.SetCommitPayload`/
   `CommitPayload`, kept out of the hot txn queries; written by
   `prepareTxn` only for a cross-root transaction). `RecoverCrossRoot`'s
   torn branch now rolls the pending roots **forward** — `rollForwardTxn`
   replays the payload (`applyCommitPayload`, reproducing
   `applyMetadata`+`applyClaimMetadata`) in one `DB.Tx`, finishes the txn
   committed, discards backups — completing the transaction to match the
   already-committed sibling. The live commit path is unchanged (the
   payload is only replayed in recovery). A pending root with no payload
   (degenerate) is still safely refused. Tested:
   `internal/install/payload_test.go` (round-trip + version rejection,
   replay records state, torn→roll-forward). PENDING (remaining):
   **cross-root autoremove/GC** (follow `IN`-edges into other roots so removing a
   depender collects what it alone kept alive) — deferred because there is
   no single-root autoremove/GC to extend yet; a cross-root install's
   packages in another root currently linger as orphans after a plain
   uninstall (an orphan, not a tear). `peipkg-compose` is
   **not** a blocker — it solves the orthogonal create-fresh-batch problem
   and already shares `internal/resolver`, so it is unaffected and could
   later adopt multi-root resolution for multi-root image builds for free.
   The one remaining open question is history/undo presenting a cross-root
   transaction as a unit (settle during step 3). Decided: recovery rolls
   **forward** (roll-back-all would force retaining every committed root's
   backups across the whole commit loop — more bookkeeping, not less).

   Wiring note for step 2: `transact` must, for a multi-root plan,
   pre-gather the installed set of every reachable root (the anchor plus
   every `refToPath` target) and pass `ResolveMultiRoot` a `refToPath`
   built by walking the registry with dotted names; a routed-to root whose
   installed set is absent would look empty and re-install spuriously.

### Producer side (pack / pekit)

✅ **Built (2026-06-24).** Both fields are produced end to end and
`compose` needed no change. `pack` carries `DefaultRoot` (public +
on-wire `Manifest`, `default_root,omitempty` before `dependencies`) and
`Dependency.Root` (`root,omitempty`), threaded through `convertDeps`;
`pekit` parses `default_root` and the string-or-table dependency form
(see below), validating the root grammar at recipe-parse time, and lowers
both into the `pack` manifest. The one deviation from the plan below: the
per-dependency root is stored internally as a map parallel to the
constraint map (`PackageMeta.DependencyRoots` /
`OptionalDependencyRoots`) rather than restructuring the dependency map's
value type — the *recipe surface* is exactly the specified string-or-table
form, but this keeps constraint templating and layer-merging untouched
and was lower-risk. Tested in `pack/pack_test.go`,
`internal/pekit/claims_test.go`.

The format fields must also be *produced*. `compose` likely needs no
change; the work is in `pack` (serialisation) and `pekit` (recipe →
manifest lowering):

- **pack** — add `DefaultRoot` to the public `Manifest`
  (`pack/pack.go`) and the on-wire `Manifest`
  (`internal/build/manifest/manifest.go`, `json:"default_root,omitempty"`,
  ordered before `dependencies` to preserve normative field order); add
  `Root` to the public and on-wire `Dependency` (`json:"root,omitempty"`),
  threaded through `convertDeps`. The reader
  (`internal/manifest/decode.go`) gains the matching `wireManifest` /
  `wireDependency` fields; the consumer-side `manifest.Dependency`
  (`internal/manifest/manifest.go`) gains `Root` only if the install/DB
  layer tracks per-dep placement (it does — slice 4's GC needs it). Dep
  *derivation* (DeriveELFDeps / DerivePkgConfigDeps) is orthogonal —
  derived deps stay in the depender's root and carry no `root`.
- **pekit** — add `DefaultRoot` to `PackageMeta` and parse `default_root`
  in `parsePackageMeta` (`internal/pekit/config.go`). **Per-dependency
  root uses a structured dep entry** (decided): a dep value is either a
  string (short form → depender's root, the common case, unchanged) or a
  table `{ constraint = "...", root = "..." }` (placement). The plain
  string is the *only* short form and the table is the *only* way to
  place a dep — deliberately no `IN`-string sugar, so there is one
  spelling per intent. Concretely: replace `parseStringMap` **for
  `dependencies` and `optional_dependencies` only** with a string-or-table
  parser (precedent: the `files` parser already accepts string-or-table),
  changing those fields from `map[string]string` to a structured map;
  `conflicts` keeps `parseStringMap` (no cross-root conflict semantics —
  conflicts stay root-local). `root`'s value is validated against the
  root-reference grammar (§3.3.6, named refs only). `packDeps` /
  `writePeipkg` (`internal/pekit/package.go`) thread `root` into
  `pack.Dependency.Root` and set `pack.Manifest.DefaultRoot`.

  ```toml
  [package]
  default_root = "initramfs"            # top-level placement

  [package.dependencies]
  libssl     = ">= 3.0"                 # short form → depender's root
  peiosutils = { constraint = ">= 1.0", root = "initramfs" }   # placed
  ```
- **Fixtures** — golden manifests (`pack/pack_test.go`, build testdata)
  and pekit recipe tests need additions; with the fields `omitempty`,
  existing goldens that set neither are unchanged.

---

## Open questions / deferred

- **Repo availability for composed roots beyond v1.** v1 fetches and
  resolves cross-root deps from the anchor's repos. When registry
  integration replaces the temporary `/lcl/conf/peipkg/*` repo system, revisit
  whether a composed root should be able to draw on its own sources.
- **`peipkg-compose` overlap.** ✅ **Resolved (2026-06-24): compose builds
  multi-root images.** compose and the consumer were confirmed orthogonal
  (build-fresh-batch vs mutate-live-incremental) and already share
  `internal/resolver`, so compose gained multi-root for the cost of the
  resolver swap plus per-root assembly — none of the cross-root 2PC
  machinery, because a composed image's roots nest *under* `OutDir` (e.g.
  `<out>/boot/initramfs`) and the whole tree is still one atomic
  staging→rename. Manifest: a `[[root]]` section (flat name → relative
  path) declares the roots, and each `[[package]]` is evaluated like
  `peipkg install [--root x]` — an optional `root = x` is the explicit
  `--root`, else the package's `default_root`, else the anchor (`OutDir`);
  cross-root `IN` deps route as always. The resolver call became
  `ResolveMultiRoot` (empty installed sets — a fresh build; `refToPath`
  from `[[root]]`); the lock gained a per-package `Root` (schema 3, keyed
  `(name, root)`); `assemble` partitions the fetched set by root, seeds
  each root's own DB, and **seeds the `named_root` registry into the
  anchor** so the booted image resolves `--root <name>` and cascades into
  it. Tested in `internal/compose/` (manifest `[[root]]` decode + reject
  undeclared/escaping; `packageRootKey` precedence; `TestAssembleMultiRoot`
  end to end). Reused `ResolveMultiRoot`, `db.SetNamedRoot`,
  `composeClaims`, `seedDatabase`, `extractPayload`, `materializeClaims`.
- **History/undo across roots.** `undo` of a cross-root transaction is done
  (undo-as-a-unit, above). `peipkg history` presenting a cross-root
  transaction as a single grouped entry (rather than one row per root) is
  a remaining UX nicety; the `cross_root_id` makes it mechanical.
- **Spec revision.** Done — `default_root` (§3.3, §3.3.6) and the
  dependency `root` field (§4.1.1) are landed in PSD-009 v0.22, with the
  index (§6.2.4) and schema appendix (§9b.1) updated. Producer-side `IN`
  recipe sugar lowers to the `root` field.
