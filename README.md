# peipkg

The Peios **consumer-side package manager** — the client tool that
installs, upgrades, removes, and queries packages on a Peios system
(`peipkg install nginx`).

It is the counterpart to the producer side (`peipkg-build`,
`peipkg-repo`, `peipkg-manager`), which builds and serves `.peipkg`
files and repositories.

## Status

In implementation. See [`DESIGN.md`](DESIGN.md) for the full
architecture, and [PSD-009](../learn/specs/psd-009--peipkg/) for the
normative package format and repository protocol.

Built in slices:

1. **Package database** — `internal/db` *(in progress)*
2. Format reader
3. Configuration + repository layer
4. Resolver
5. Execution (plan / stage / commit)
6. Command-line surface

## Layout

- `cmd/peipkg/` — the command entrypoint
- `internal/db/` — the private SQLite package database

## Building

CGO-free, static, Linux/amd64:

    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./...
