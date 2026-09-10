# peipkg

The Peios **consumer-side package manager** — the client tool that
installs, upgrades, removes, and queries packages on a Peios system
(`peipkg install nginx`).

The same source tree also provides two deliberately separate tools:
`peipkg-compose` assembles fresh package roots for image builders, while
`peipkg-repo` publishes and verifies static repositories. The producer-side
*format emitter* lives here too: the public `pack/` package creates `.peipkg`
files for external build tools (it absorbed the core of the retired
`peipkg-build`).

## Status

See [`DESIGN.md`](DESIGN.md) for the implementation architecture and the
[Peipkg manual](../learn/peios.product/3--advanced-peios.antho/300--trms.shelf/500--peipkg.book/)
for the maintained package-manager and repository contract.

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
- `cmd/peipkg-compose/` — the offline image/root-composition entrypoint
- `cmd/peipkg-repo/` — the repository publication and verification entrypoint
- `compose/` — the public root-composition API for image builders
- `repopub/` — the public DB-free repository publication API
- `pack/` — the public .peipkg-creation API for build tools
- `internal/` — the implementation packages listed above, plus
  `internal/build/` (the producer-side emitter behind `pack/`)

## Packages

Peios releases the three command-line roles independently:

- `dev.peios.peipkg` — the live-system package consumer;
- `dev.peios.peipkg-compose` — the offline package-root composer; and
- `dev.peios.peipkg-repo` — the repository publisher and verifier.

They share one source release and test suite, but installing a repository host
does not pull in the live package database or the image composer. Conventional
per-binary debuginfo packages, shared debug sources, corresponding source, and
the licence notices for the exact linked Go module closure are published with
the runtime packages.

## Building

CGO-free PIE with no `DT_NEEDED` dependencies (the Peios ABI loader is still
required), Linux/amd64:

    go test ./...
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/peipkg ./cmd/peipkg-compose ./cmd/peipkg-repo
