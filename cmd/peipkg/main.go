// Command peipkg is the Peios consumer-side package manager: it
// installs, upgrades, removes, and queries packages on a Peios system.
//
// See DESIGN.md for the architecture. The command-line surface lives in
// internal/cli; this entrypoint only hands the arguments to it.
package main

import (
	"os"

	"github.com/peios/peipkg/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
