# peipkg

The Peios **consumer-side package manager** — the client tool that
installs, upgrades, removes, and queries packages on a Peios system
(`peipkg install nginx`).

It is the counterpart to the producer side (`peipkg-build`,
`peipkg-repo`, `peipkg-manager`), which builds and serves `.peipkg`
files and repositories.

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

Some refinements are deliberately deferred — KMES audit emission, KACS
security-descriptor application, `/etc` modified-detection, and a few
secondary commands; these are noted in the commit history and the
design doc.

## Layout

- `cmd/peipkg/` — the command entrypoint
- `internal/` — the implementation packages listed above

## Building

CGO-free, static, Linux/amd64:

    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./...
