// Package repopub publishes a peipkg repository: it turns a directory
// of .peipkg files into the signed on-disk state a consumer can add and
// refresh from (PSD-009 §6).
//
// The state directory IS the repository. Every file in it is served
// verbatim at the corresponding path under <repo-base>, so publishing
// to a static host — object storage, a CDN origin, a directory on an
// ISO — is a copy, not a deployment. There is no daemon, no database
// and no server-side logic; the only thing that makes the directory a
// repository rather than a pile of files is that its indexes are signed
// and internally consistent, which is exactly what this package
// maintains.
//
// The counterpart lives in internal/repository, which reads what this
// writes. The two share their wire structs deliberately (see
// repository/encode.go): a publisher and a client with independent
// definitions of repo.json is the one failure this design cannot
// tolerate, because it produces a repository that verifies for its
// author and nobody else.
package repopub

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/peios/peipkg/internal/repository"
	"github.com/peios/peipkg/internal/signature"
)

// The conventional layout (§6.4.2). These are the paths this publisher
// writes; a repository MAY serve its indexes from other URLs by saying
// so in the descriptor, but there is no reason to and every reason not
// to — a consumer that knows only <repo-base> must find repo.json at
// the conventional path, and everything else is reachable from there.
const (
	descriptorFile   = "repo.json"
	activeIndexFile  = "index/active.json"
	archiveIndexFile = "index/archive.json"
	keysDir          = "keys"
	packagesDir      = "p"

	// signatureSuffix is appended to a signed document's path to locate
	// its detached signature (§6.1.6).
	signatureSuffix = ".sig"

	// configFile holds publisher-side state that is not part of the
	// served contract: the URL template, and the fact that this
	// directory is a repository at all.
	//
	// It is written into the state directory rather than kept beside it
	// because the directory is the unit an operator moves, backs up and
	// copies onto a medium; configuration that lived outside it would be
	// lost by exactly the operations that are supposed to preserve a
	// repository. Serving it is harmless — it holds no secret, and a
	// consumer neither looks for it nor would understand it.
	configFile = ".peipkg-repo.json"
)

// defaultURLTemplate is the §6.4.3 conventional package path. The
// placeholders are substituted per [expandURLTemplate].
const defaultURLTemplate = "/p/{name}/{version}/{filename}"

// configSchemaVersion versions configFile independently of anything the
// spec defines, because it is ours.
const configSchemaVersion = 1

// Config is the publisher-side state in configFile.
type Config struct {
	SchemaVersion int    `json:"schema_version"`
	URLTemplate   string `json:"url_template"`
}

// State is an opened repository state: the parsed contents of a state
// directory, ready to be published into.
type State struct {
	// Dir is the state directory — the local stand-in for <repo-base>.
	Dir        string
	Config     Config
	Descriptor repository.Descriptor
	Active     repository.Index
	Archive    repository.Index
}

// ErrNotRepository reports that a directory is not a repository state.
var ErrNotRepository = errors.New("peipkg/repopub: not a repository state directory")

// Open reads the state at dir.
//
// Every document is decoded through internal/repository — the same code
// a consumer uses — so a state this tool cannot open is one no consumer
// could have used either. Reading through the client's own decoder is
// the cheapest available guarantee that a publish never builds on a
// state that has silently drifted out of spec.
func Open(dir string) (*State, error) {
	cfgRaw, err := os.ReadFile(filepath.Join(dir, configFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNotRepository, dir)
		}
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
		return nil, fmt.Errorf("peipkg/repopub: reading %s: %w", configFile, err)
	}
	if cfg.SchemaVersion != configSchemaVersion {
		return nil, fmt.Errorf(
			"peipkg/repopub: %s has schema_version %d, want %d",
			configFile, cfg.SchemaVersion, configSchemaVersion)
	}
	if cfg.URLTemplate == "" {
		cfg.URLTemplate = defaultURLTemplate
	}

	st := &State{Dir: dir, Config: cfg}

	raw, err := os.ReadFile(filepath.Join(dir, descriptorFile))
	if err != nil {
		return nil, fmt.Errorf("peipkg/repopub: reading %s: %w", descriptorFile, err)
	}
	if st.Descriptor, err = repository.DecodeDescriptor(raw); err != nil {
		return nil, fmt.Errorf("peipkg/repopub: %s: %w", descriptorFile, err)
	}

	if st.Active, err = st.readIndex(activeIndexFile, repository.IndexActive); err != nil {
		return nil, err
	}
	if st.Archive, err = st.readIndex(archiveIndexFile, repository.IndexArchive); err != nil {
		return nil, err
	}
	return st, nil
}

func (s *State) readIndex(rel string, want repository.IndexKind) (repository.Index, error) {
	raw, err := os.ReadFile(filepath.Join(s.Dir, rel))
	if err != nil {
		return repository.Index{}, fmt.Errorf("peipkg/repopub: reading %s: %w", rel, err)
	}
	idx, err := repository.DecodeIndex(raw)
	if err != nil {
		return repository.Index{}, fmt.Errorf("peipkg/repopub: %s: %w", rel, err)
	}
	if idx.Kind != want {
		return repository.Index{}, fmt.Errorf(
			"peipkg/repopub: %s declares kind %q, want %q", rel, idx.Kind, want)
	}
	if idx.RepoName != s.Descriptor.RepoName {
		return repository.Index{}, fmt.Errorf(
			"peipkg/repopub: %s names repository %q but the descriptor says %q",
			rel, idx.RepoName, s.Descriptor.RepoName)
	}
	return idx, nil
}

// InitOptions configures [Init].
type InitOptions struct {
	Name        string
	Description string
	// Key signs the initial descriptor and the two empty indexes, and its
	// public half becomes the repository's first trust anchor.
	Key ed25519.PrivateKey
	// URLTemplate is the package URL template for entries added by later
	// publishes; empty means [defaultURLTemplate].
	URLTemplate string
	// GeneratedAt stamps the initial indexes.
	GeneratedAt time.Time
}

// Init creates an empty repository state at dir.
//
// The result is a complete, valid, signed repository advertising no
// packages — not a partial one waiting for a first publish. That
// distinction matters operationally: an operator can stand up the
// hosting, point a consumer at it and confirm the trust ceremony works
// before any package exists to get wrong.
//
// dir must be empty or absent. Re-initialising an existing repository
// would mint a fresh index_version 1, which every consumer that had
// already seen a higher version would reject as a rollback for the rest
// of that repository's life (§6.2.3) — an unrecoverable state, so it is
// refused rather than confirmed.
func Init(dir string, opts InitOptions) error {
	if opts.Name == "" {
		return fmt.Errorf("peipkg/repopub: a repository name is required")
	}
	if opts.GeneratedAt.IsZero() {
		return fmt.Errorf("peipkg/repopub: a generation timestamp is required")
	}
	if err := requireEmptyDir(dir); err != nil {
		return err
	}
	pub, err := publicKeyOf(opts.Key)
	if err != nil {
		return err
	}
	fingerprint := signature.Fingerprint(pub)

	template := opts.URLTemplate
	if template == "" {
		template = defaultURLTemplate
	}
	if err := validateURLTemplate(template); err != nil {
		return err
	}

	desc := repository.Descriptor{
		RepoName:    opts.Name,
		Description: opts.Description,
		Keys: []repository.DescriptorKey{{
			Fingerprint: fingerprint,
			URL:         "/" + path.Join(keysDir, fingerprint+".pub"),
			Status:      repository.KeyActive,
		}},
		ActiveIndex: repository.IndexPointer{
			URL:          "/" + activeIndexFile,
			SignatureURL: "/" + activeIndexFile + signatureSuffix,
		},
		ArchiveIndex: repository.IndexPointer{
			URL:          "/" + archiveIndexFile,
			SignatureURL: "/" + archiveIndexFile + signatureSuffix,
		},
	}

	// index_version starts at 1, not 0: §6.2.3 requires a positive
	// integer, and a consumer's recorded floor starts at zero, so a
	// zeroth index would be rejected by the very first refresh.
	empty := func(kind repository.IndexKind) repository.Index {
		return repository.Index{
			RepoName:     opts.Name,
			Kind:         kind,
			IndexVersion: 1,
			GeneratedAt:  opts.GeneratedAt,
		}
	}

	w := newWriteSet(dir)
	if err := w.addSignedDescriptor(desc, opts.Key); err != nil {
		return err
	}
	if err := w.addSignedIndex(activeIndexFile, empty(repository.IndexActive), opts.Key); err != nil {
		return err
	}
	if err := w.addSignedIndex(archiveIndexFile, empty(repository.IndexArchive), opts.Key); err != nil {
		return err
	}
	pubPEM, err := signature.EncodePublicKey(pub)
	if err != nil {
		return err
	}
	w.add(path.Join(keysDir, fingerprint+".pub"), pubPEM)

	cfg, err := json.MarshalIndent(
		Config{SchemaVersion: configSchemaVersion, URLTemplate: template}, "", "  ")
	if err != nil {
		return err
	}
	w.add(configFile, append(cfg, '\n'))

	return w.commit()
}

// requireEmptyDir refuses a directory that already holds anything.
func requireEmptyDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf(
			"peipkg/repopub: %s is not empty; publish into an existing repository rather than re-initialising it",
			dir)
	}
	return nil
}

func publicKeyOf(priv ed25519.PrivateKey) (ed25519.PublicKey, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("peipkg/repopub: a signing key is required")
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("peipkg/repopub: signing key does not yield an Ed25519 public key")
	}
	return pub, nil
}

// --- URL templates ------------------------------------------------------

// expandURLTemplate substitutes the §6.4.3 placeholders.
func expandURLTemplate(tmpl, name, version, arch string) string {
	filename := fmt.Sprintf("%s_%s_%s.peipkg", name, version, arch)
	return strings.NewReplacer(
		"{name}", name,
		"{version}", version,
		"{arch}", arch,
		"{filename}", filename,
	).Replace(tmpl)
}

// validateURLTemplate rejects a template that cannot distinguish two
// packages.
//
// Without {version} — or {filename}, which contains it — every version
// of a package would be advertised at one URL, so publishing 1.1 would
// make 1.0 unfetchable. §6.3.1 requires a repository to keep every
// version it has ever advertised fetchable indefinitely, and a template
// that collides is a promise the operator cannot keep. Catching it here
// costs one check; catching it later means a repository whose archive
// index is a list of lies.
func validateURLTemplate(tmpl string) error {
	if tmpl == "" {
		return fmt.Errorf("peipkg/repopub: url template must not be empty")
	}
	if !strings.Contains(tmpl, "{name}") && !strings.Contains(tmpl, "{filename}") {
		return fmt.Errorf(
			"peipkg/repopub: url template %q contains neither {name} nor {filename}, "+
				"so every package would share one URL", tmpl)
	}
	if !strings.Contains(tmpl, "{version}") && !strings.Contains(tmpl, "{filename}") {
		return fmt.Errorf(
			"peipkg/repopub: url template %q contains neither {version} nor {filename}, "+
				"so every version of a package would share one URL and retention (§6.3.1) "+
				"could not be honoured", tmpl)
	}
	return nil
}

// isRepoRelative reports whether a URL names a location inside the
// repository — in which case this publisher is responsible for placing
// the package file there. An absolute URL means the operator hosts
// package files elsewhere (a releases page, a separate bucket) and the
// index merely points at them.
func isRepoRelative(u string) bool {
	return strings.HasPrefix(u, "/")
}

// --- writing ------------------------------------------------------------

// writeSet stages a set of files and commits them together.
//
// Every file is written to a temporary sibling and renamed into place,
// so no reader ever observes a half-written document. The renames
// themselves are not one atomic operation — no filesystem offers that
// across several files — so commit orders them to make a torn publish
// as harmless as it can be: content first, then the archive index, then
// the active index, then the descriptor. A consumer following the chain
// from repo.json therefore never reaches a pointer whose target is
// older than the document that referred it, and packages are in place
// before any index advertises them.
type writeSet struct {
	dir   string
	files []stagedFile
	err   error
}

type stagedFile struct {
	rel  string
	data []byte
	// src, when set, names a file to copy instead of writing data.
	src string
}

func newWriteSet(dir string) *writeSet { return &writeSet{dir: dir} }

func (w *writeSet) add(rel string, data []byte) {
	w.files = append(w.files, stagedFile{rel: rel, data: data})
}

func (w *writeSet) addFileCopy(rel, src string) {
	w.files = append(w.files, stagedFile{rel: rel, src: src})
}

// addSigned stages a document and its detached signature together.
// The two are never staged apart: an index whose signature was not
// written is unusable, and a signature without its index is worse than
// either missing, so they are one unit of work.
func (w *writeSet) addSigned(rel string, data []byte, key ed25519.PrivateKey) error {
	w.add(rel, data)
	sig, err := detachedSignature(data, key)
	if err != nil {
		return err
	}
	w.add(rel+signatureSuffix, sig)
	return nil
}

// addSignedDescriptor encodes and stages repo.json with its signature.
func (w *writeSet) addSignedDescriptor(d repository.Descriptor, key ed25519.PrivateKey) error {
	data, err := repository.EncodeDescriptor(d)
	if err != nil {
		return err
	}
	return w.addSigned(descriptorFile, data, key)
}

// addSignedIndex encodes and stages an index with its signature.
func (w *writeSet) addSignedIndex(rel string, idx repository.Index, key ed25519.PrivateKey) error {
	data, err := repository.EncodeIndex(idx)
	if err != nil {
		return err
	}
	return w.addSigned(rel, data, key)
}

// detachedSignature builds the .sig envelope over a document's exact
// bytes (§6.1.6): the signature is over the SHA-256 digest, not over
// the document, which is the same indirection package signing uses so
// one verifier covers both.
func detachedSignature(document []byte, key ed25519.PrivateKey) ([]byte, error) {
	digest := sha256.Sum256(document)
	env, err := signature.Sign(key, digest[:])
	if err != nil {
		return nil, err
	}
	return env.Encode()
}

// commit writes every staged file and renames it into place.
func (w *writeSet) commit() error {
	if w.err != nil {
		return w.err
	}
	temps := make([]string, len(w.files))
	// Stage everything before renaming anything: a failure while writing
	// leaves the previous state untouched, because nothing has been
	// renamed over it yet.
	for i, f := range w.files {
		dest := filepath.Join(w.dir, filepath.FromSlash(f.rel))
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			w.cleanup(temps)
			return err
		}
		tmp, err := w.stage(dest, f)
		if err != nil {
			w.cleanup(temps)
			return err
		}
		temps[i] = tmp
	}
	for i, f := range w.files {
		dest := filepath.Join(w.dir, filepath.FromSlash(f.rel))
		if err := os.Rename(temps[i], dest); err != nil {
			// Renames already done stand. Reporting the failure is all
			// that is left; the ordering above is what keeps a partial
			// commit readable.
			w.cleanup(temps[i+1:])
			return fmt.Errorf("peipkg/repopub: publishing %s: %w", f.rel, err)
		}
	}
	return nil
}

func (w *writeSet) stage(dest string, f stagedFile) (string, error) {
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".peipkg-repo-*")
	if err != nil {
		return "", err
	}
	defer tmp.Close()

	if f.src != "" {
		src, err := os.Open(f.src)
		if err != nil {
			os.Remove(tmp.Name())
			return "", err
		}
		defer src.Close()
		if _, err := io.Copy(tmp, src); err != nil {
			os.Remove(tmp.Name())
			return "", err
		}
	} else if _, err := tmp.Write(f.data); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	// Durability before visibility: a rename that lands before the
	// content reaches disk is exactly how a crash produces an empty file
	// where a signed index should be.
	if err := tmp.Sync(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

func (w *writeSet) cleanup(temps []string) {
	for _, t := range temps {
		if t != "" {
			os.Remove(t)
		}
	}
}

// hashFile returns the lowercase-hex SHA-256 of a file's contents and
// its size — the two properties §6.2.3 requires an index entry to carry
// about the .peipkg itself, as distinct from its manifest.
func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
