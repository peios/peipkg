// Command peipkg is the Peios consumer-side package manager: it
// installs, upgrades, removes, and queries packages on a Peios system.
//
// See DESIGN.md for the architecture. The command-line surface is the
// final implementation slice; this entrypoint is a placeholder until
// then.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "peipkg: not yet implemented")
	os.Exit(1)
}
