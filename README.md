# peipkg

The Peios **consumer-side package manager** — the client tool that
installs, upgrades, removes, and queries packages on a Peios system
(`peipkg install nginx`).

It is the counterpart to the producer side (`peipkg-repo`,
`peipkg-manager`), which serves `.peipkg` files and repositories. The
producer-side *format emitter* lives here too: the public `pack/`
package creates `.peipkg` files for external build tools (it absorbed
the core of the retired `peipkg-build`).

## Status

The six implementation slices are complete. See [`DESIGN.md`](DESIGN.md)
for the architecture and [PSD-009](../learn/specs/psd-009--peipkg/) for
the normative package format and repository protocol.

1. **`internal/db`** — the private SQLite package database
2. **`internal/{version,manifest,signature,archive}`** — the package-format reader
3. **`internal/{config,repository}`** — repository configuration and the repository layer
4. **`internal/resolver`** — dependency resolution
5. **`internal/install`** — the transaction executor (stage / commit / recover)
6. **`internal/cli`** — the command-line surface

The deferred-feature follow-up is complete: the dependency-resolution
refinements, repository handling (archive index, unsigned repositories,
the rollback floor), `/etc` modified-detection and backup retention,
raw local-file install, the secondary CLI verbs (`search`, `verify`,
`clean`, `downgrade`, `undo`), and KMES audit emission.

One item remains deliberately deferred: KACS security-descriptor
application (`sd_overrides`), pending the §3.4 SD-override policy
design. It is recorded in the commit history.

Symlink-safe install-path resolution has landed (PEI-375). Every path
under an installation root is resolved component by component against a
pinned directory descriptor and never through a symbolic link, and the
descriptor — not a re-walked string — is what the commit renames
against. It is built on `openat`/`renameat` with `O_NOFOLLOW` rather
than `openat2` with `RESOLVE_NO_SYMLINKS`, so it needs no ABI beyond
what has been there for a decade; `openat2` would fold the walk into
one syscall and add `RESOLVE_BENEATH`, and remains available as later
hardening.

## Layout

- `cmd/peipkg/` — the command entrypoint
- `compose/` — the public root-composition API for image builders
- `pack/` — the public .peipkg-creation API for build tools
- `internal/` — the implementation packages listed above, plus
  `internal/build/` (the producer-side emitter behind `pack/`)

## Building

CGO-free, static, Linux/amd64:

    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./...
