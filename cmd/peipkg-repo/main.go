// Command peipkg-repo publishes a peipkg repository: it turns a
// directory of .peipkg files into the signed state a consumer adds and
// refreshes from (PSD-009 §6).
//
// Three verbs:
//
//	peipkg-repo init    <dir> --name NAME --key KEY [--description D] [--url-template T]
//	peipkg-repo publish <dir> [PACKAGE|DIR ...] --key KEY [--rebuild] [--allow-unsigned]
//	peipkg-repo verify  <dir> [--quick]
//
// There is no daemon and no state of its own: the directory it produces
// IS the repository, and deploying it is a copy. See internal/repopub.
//
// # Shape of the command line
//
// The state directory is a positional argument and is mutated in place.
// An earlier design took --in and --out and permitted them to be equal;
// that made the ordinary case (publish into my repository) the one
// requiring two flags to say the same path twice, and the exotic case
// (produce a copy) the default. A repository has an identity, and that
// identity is where it lives.
//
// Package files are positional too, so a shell glob works and nothing
// has to be staged into a blessed directory first.
package main

import (
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/peios/peipkg/internal/repopub"
	"github.com/peios/peipkg/internal/signature"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run dispatches a verb and returns the process exit code. Splitting it
// from main lets tests drive it without an os.Exit.
func run(args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return 2
	}
	switch verb, rest := args[0], args[1:]; verb {
	case "init":
		return report(cmdInit(rest))
	case "publish":
		return report(cmdPublish(rest))
	case "verify":
		return cmdVerify(rest)
	case "-h", "--help", "help":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "peipkg-repo: unknown command %q\n", verb)
		usage(os.Stderr)
		return 2
	}
}

// report turns an error into an exit code. errUsage is the one error
// that means "you typed it wrong" rather than "it did not work", and
// earns the conventional 2.
func report(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errUsage):
		return 2
	default:
		fmt.Fprintf(os.Stderr, "peipkg-repo: %v\n", err)
		return 1
	}
}

var errUsage = errors.New("usage")

func usage(w *os.File) {
	fmt.Fprint(w, `usage:
  peipkg-repo init    <dir> --name NAME --key KEY [--description TEXT] [--url-template TMPL] [--timestamp TS]
  peipkg-repo publish <dir> [PACKAGE|DIR ...] --key KEY [--timestamp TS] [--url-template TMPL]
                            [--allow-unsigned] [--rebuild]
  peipkg-repo verify  <dir> [--quick]

The directory is the repository: every file in it is served verbatim
under <repo-base>, so deploying is a copy.
`)
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	name := fs.String("name", "", "repository name, recorded in repo.json (required)")
	description := fs.String("description", "", "one-line human-readable description")
	keyPath := fs.String("key", "", "Ed25519 signing key: PKCS#8 PEM or a raw 32-byte seed (required)")
	template := fs.String("url-template", "",
		"package URL template; placeholders {name} {version} {arch} {filename}")
	stamp := fs.String("timestamp", "", "RFC 3339 UTC generation time (default: now)")
	dir, err := parseWithDir(fs, args, "init")
	if err != nil {
		return err
	}
	if *name == "" || *keyPath == "" {
		return fmt.Errorf("%w: init needs --name and --key", errUsage)
	}
	key, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	at, err := parseTimestamp(*stamp)
	if err != nil {
		return err
	}
	if err := repopub.Init(dir, repopub.InitOptions{
		Name:        *name,
		Description: *description,
		Key:         key,
		URLTemplate: *template,
		GeneratedAt: at,
	}); err != nil {
		return err
	}
	fmt.Printf("initialised repository %q at %s\n", *name, dir)
	fmt.Printf("  trust anchor: %s\n",
		groupFingerprint(signature.Fingerprint(key.Public().(ed25519.PublicKey))))
	fmt.Printf("\nDistribute that fingerprint out of band: a consumer supplies it when adding\n" +
		"the repository, and it is the only thing standing between them and a substituted\n" +
		"descriptor (PSD-009 §6.5.2).\n")
	return nil
}

func cmdPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	keyPath := fs.String("key", "", "Ed25519 signing key (required)")
	stamp := fs.String("timestamp", "", "RFC 3339 UTC generation time (default: now)")
	template := fs.String("url-template", "", "override the repository's stored URL template")
	allowUnsigned := fs.Bool("allow-unsigned", false,
		"publish packages that carry no signature")
	rebuild := fs.Bool("rebuild", false,
		"discard the recorded archive and rebuild it from package files on disk")
	dir, rest, err := parseWithDirAndRest(fs, args, "publish")
	if err != nil {
		return err
	}
	if *keyPath == "" {
		return fmt.Errorf("%w: publish needs --key", errUsage)
	}
	key, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	at, err := parseTimestamp(*stamp)
	if err != nil {
		return err
	}
	result, err := repopub.Publish(dir, repopub.PublishOptions{
		Key:           key,
		Paths:         rest,
		GeneratedAt:   at,
		URLTemplate:   *template,
		AllowUnsigned: *allowUnsigned,
		Rebuild:       *rebuild,
	})
	if err != nil {
		return err
	}
	for _, e := range result.Added {
		fmt.Printf("published %s %s (%s)\n", e.Name, e.Version, e.Architecture)
	}
	fmt.Printf("index_version %d — %d package(s) active, %d archived\n",
		result.IndexVersion, result.ActiveCount, result.ArchiveCount)
	return nil
}

func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	quick := fs.Bool("quick", false, "skip re-hashing package files; check presence and size only")
	dir, err := parseWithDir(fs, args, "verify")
	if err != nil {
		return report(err)
	}
	rep, err := repopub.Verify(dir, repopub.VerifyOptions{Quick: *quick})
	if err != nil {
		return report(err)
	}
	fmt.Printf("%s — index_version %d, %d active, %d archived\n",
		rep.RepoName, rep.IndexVersion, rep.ActiveCount, rep.ArchiveCount)
	if rep.OK() {
		fmt.Println("no problems found")
		return 0
	}
	for _, p := range rep.Problems {
		fmt.Fprintf(os.Stderr, "peipkg-repo: %s\n", p)
	}
	// A damaged repository is a failure, not a report: verify is meant
	// to be usable as a deployment gate, and a gate that exits zero on
	// findings is not a gate.
	return 1
}

// --- shared flag plumbing -----------------------------------------------

// parseWithDir parses flags around a single leading positional
// directory. The directory comes first so the command reads as an
// instruction to a place — `publish ./repo x.peipkg` — rather than a
// bag of flags.
func parseWithDir(fs *flag.FlagSet, args []string, verb string) (string, error) {
	dir, rest, err := parseWithDirAndRest(fs, args, verb)
	if err != nil {
		return "", err
	}
	if len(rest) > 0 {
		return "", fmt.Errorf("%w: %s takes one directory, got %d extra argument(s)",
			errUsage, verb, len(rest))
	}
	return dir, nil
}

func parseWithDirAndRest(fs *flag.FlagSet, args []string, verb string) (string, []string, error) {
	fs.SetOutput(os.Stderr)
	// Flags may appear before or after the positionals, which flag does
	// not do on its own: it stops at the first non-flag. Partitioning up
	// front means `publish ./repo *.peipkg --key k` works, and that is
	// the order a person actually types.
	var positional, flags []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			// A bool flag takes no value; everything else consumes the
			// next argument unless it was given as --flag=value.
			if !strings.Contains(a, "=") && !isBoolFlag(fs, a) && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positional = append(positional, a)
	}
	if err := fs.Parse(flags); err != nil {
		return "", nil, fmt.Errorf("%w: %s", errUsage, err)
	}
	if len(positional) == 0 {
		return "", nil, fmt.Errorf("%w: %s needs a repository directory", errUsage, verb)
	}
	return positional[0], positional[1:], nil
}

func isBoolFlag(fs *flag.FlagSet, arg string) bool {
	name := strings.TrimLeft(arg, "-")
	f := fs.Lookup(name)
	if f == nil {
		return false
	}
	bf, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && bf.IsBoolFlag()
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading signing key: %w", err)
	}
	return signature.ParsePrivateKey(raw)
}

// parseTimestamp reads an RFC 3339 UTC timestamp, defaulting to now.
//
// The flag exists for reproducible publishes and for tests; it is not
// required, because a repository's generated_at means "when this
// revision was made" and the honest answer is almost always now.
func parseTimestamp(s string) (time.Time, error) {
	if s == "" {
		return time.Now().UTC(), nil
	}
	if !strings.HasSuffix(s, "Z") {
		return time.Time{}, fmt.Errorf("%w: timestamp %q must be UTC (end with Z)", errUsage, s)
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: timestamp %q: %v", errUsage, s, err)
	}
	return t.UTC(), nil
}

// groupFingerprint renders a fingerprint in four-character groups, the
// form §6.5.2 requires when a fingerprint is shown for a human to
// compare against one they hold. Printing it here means the operator
// distributing the anchor and the consumer confirming it are looking at
// the same shape.
func groupFingerprint(fp string) string {
	var b strings.Builder
	for i := 0; i < len(fp); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		end := min(i+4, len(fp))
		b.WriteString(fp[i:end])
	}
	return b.String()
}
