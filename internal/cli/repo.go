package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/peios/peipkg/internal/audit"
	"github.com/peios/peipkg/internal/config"
	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/repository"
)

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// configProvider returns the repository-configuration provider.
func (app *App) configProvider() *config.DirProvider {
	return config.NewDirProvider(app.paths.configDir)
}

// repoClient builds the repository client.
func (app *App) repoClient(store *db.DB) *repository.Client {
	return repository.NewClient(repository.NewHTTPFetcher(), store, app.paths.cacheDir)
}

// warnUnsigned emits the §6.5.3 per-operation warning when a repository
// is operated in unsigned mode — added with the `optional` policy and
// no trust anchors, so its metadata and packages go unverified.
func (app *App) warnUnsigned(cfg config.RepoConfig) {
	if repository.UnsignedMode(cfg) {
		fmt.Fprintf(app.errOut, "peipkg: warning: repository %q is unsigned — its metadata "+
			"and packages are not cryptographically verified (§6.5.3)\n", cfg.Name)
	}
}

// cmdRepo dispatches the repo subcommands.
func cmdRepo(app *App, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("repo: a subcommand is required (add, list, remove)")
	}
	switch sub, rest := args[0], args[1:]; sub {
	case "add":
		return cmdRepoAdd(app, rest)
	case "list":
		return cmdRepoList(app, rest)
	case "remove":
		return cmdRepoRemove(app, rest)
	default:
		return fmt.Errorf("repo: unknown subcommand %q", sub)
	}
}

// cmdRepoAdd configures a repository and performs the trust ceremony:
// fetching its descriptor and verifying it against the operator-
// supplied trust anchors (§6.5.2).
func cmdRepoAdd(app *App, args []string) error {
	fs := flags("repo add")
	priority := fs.Int("priority", 50, "resolution priority — a lower number wins")
	policy := fs.String("policy", "required", "signature policy: required or optional")
	insecure := fs.Bool("insecure", false, "permit an http base URL")
	minIndex := fs.Int64("min-index-version", 0,
		"out-of-band minimum acceptable index_version (§6.2.3)")
	maxAge := fs.Int("max-trusted-age-days", 0,
		"maximum trusted age in days before operations demand a refresh (0 = default 30, §6.5.4)")
	var anchors stringList
	fs.Var(&anchors, "anchor", "a trusted signing-key fingerprint (repeatable)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}

	var cfg config.RepoConfig
	switch len(pos) {
	case 1:
		// The configured form: `repo add <name>` performs the trust
		// ceremony for a repository whose .repo file is already present.
		//
		// This is how an image ships a repository. peipkg deliberately
		// does NOT trust a configured repository on sight — a .repo file
		// with anchors still has no recorded trust state, and every
		// operation skips it with a warning until the ceremony has run
		// (§6.5.2 makes the trust decision the user's, not the
		// consumer's default). But an image that baked in the config and
		// the anchors together HAS made that decision, through what
		// §6.5.2 calls a configured channel, and it needs some way to
		// say so without an operator retyping a 64-character fingerprint
		// that is already sitting on disk.
		//
		// It is still an explicit act. Nothing here happens by itself.
		cfg, err = configuredRepo(app, pos[0])
		if err != nil {
			return err
		}
	case 2:
		cfg = config.RepoConfig{
			Name:                   pos[0],
			BaseURL:                pos[1],
			Priority:               *priority,
			SignaturePolicy:        config.SignaturePolicy(*policy),
			TrustAnchors:           anchors,
			AllowInsecureTransport: *insecure,
			MinIndexVersion:        *minIndex,
			MaxTrustedAgeDays:      *maxAge,
		}
	default:
		return fmt.Errorf("repo add: usage: repo add <name> <base-url> --anchor <fingerprint>\n" +
			"                  repo add <name>   (for a repository already configured on this system)")
	}

	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	provider := app.configProvider()
	preconfigured := len(pos) == 1
	if !preconfigured {
		if err := provider.Put(cfg); err != nil {
			return err
		}
	}
	if err := app.repoClient(store).Add(ctx, cfg); err != nil {
		// The trust ceremony failed; back out the configuration file so
		// a half-added repository is not left behind.
		//
		// Only when this command wrote it. In the configured form the
		// .repo file came from somewhere else — an image, an operator,
		// a configuration manager — and deleting another party's file
		// because a ceremony failed would turn a retryable failure
		// (medium not mounted yet, repository not published) into lost
		// configuration.
		if !preconfigured {
			_ = provider.Remove(cfg.Name)
		}
		return err
	}
	app.printf("added repository %q\n", cfg.Name)
	app.warnUnsigned(cfg)
	app.emit(audit.Event{Type: audit.TypeRepoAdd, Outcome: audit.OutcomeSuccess,
		Repo: cfg.Name, Detail: cfg.BaseURL})
	return nil
}

// cmdRepoList prints the configured repositories.
func cmdRepoList(app *App, args []string) error {
	fs := flags("repo list")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	repos, err := app.configProvider().Repositories()
	if err != nil {
		return err
	}
	if *asJSON {
		type view struct {
			Name, BaseURL, Policy string
			Priority              int
		}
		views := make([]view, len(repos))
		for i, r := range repos {
			views[i] = view{r.Name, r.BaseURL, string(r.SignaturePolicy), r.Priority}
		}
		return app.emitJSON(views)
	}
	if len(repos) == 0 {
		app.printf("no repositories configured\n")
		return nil
	}
	for _, r := range repos {
		app.printf("%s  %s  priority=%d  %s\n", r.Name, r.BaseURL, r.Priority, r.SignaturePolicy)
	}
	return nil
}

// cmdRepoRemove removes a repository's configuration and recorded state.
// Packages installed from it remain installed (§6.5.6).
func cmdRepoRemove(app *App, args []string) error {
	fs := flags("repo remove")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("repo remove: exactly one repository name is required")
	}
	name := pos[0]

	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	if err := app.configProvider().Remove(name); err != nil {
		return err
	}
	if err := store.DeleteRepository(ctx, name); err != nil {
		return err
	}
	app.printf("removed repository %q\n", name)
	app.emit(audit.Event{Type: audit.TypeRepoRemove, Outcome: audit.OutcomeSuccess, Repo: name})
	return nil
}

// cmdRefresh refreshes the metadata of the configured repositories. A
// failure of one repository does not block the others (§6.5.4).
func cmdRefresh(app *App, args []string) error {
	fs := flags("refresh")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	repos, err := app.configProvider().Repositories()
	if err != nil {
		return err
	}
	only := map[string]bool{}
	for _, name := range pos {
		only[name] = true
	}

	client := app.repoClient(store)
	failures := 0
	refreshed := 0
	for _, cfg := range repos {
		if len(only) > 0 && !only[cfg.Name] {
			continue
		}
		// A repository with no recorded state is being synced for the
		// first time, which is the trust-add procedure.
		_, known, err := store.GetRepository(ctx, cfg.Name)
		if err != nil {
			return err
		}
		op := client.Refresh
		if !known {
			op = client.Add
		}
		if err := op(ctx, cfg); err != nil {
			fmt.Fprintf(app.errOut, "peipkg: refreshing %q failed: %v\n", cfg.Name, err)
			failures++
			continue
		}
		app.printf("refreshed %q\n", cfg.Name)
		app.warnUnsigned(cfg)
		refreshed++
	}
	if refreshed == 0 && failures == 0 {
		app.printf("no repositories to refresh\n")
	}
	outcome := audit.OutcomeSuccess
	if failures > 0 {
		outcome = audit.OutcomeRejection
	}
	app.emit(audit.Event{Type: audit.TypeRefresh, Outcome: outcome,
		Detail: fmt.Sprintf("%d refreshed, %d failed", refreshed, failures)})
	if failures > 0 {
		return fmt.Errorf("%d repository refresh(es) failed", failures)
	}
	return nil
}

// configuredRepo loads a repository's existing .repo configuration for
// the `repo add <name>` form, reporting a usable error when there is
// none.
func configuredRepo(app *App, name string) (config.RepoConfig, error) {
	cfg, found, err := app.configProvider().Repository(name)
	if err != nil {
		return config.RepoConfig{}, err
	}
	if !found {
		return config.RepoConfig{}, fmt.Errorf(
			"repo add: no repository named %q is configured; give its base URL and "+
				"trust anchors to add one", name)
	}
	// Without an anchor there is nothing to verify the descriptor
	// against, so the ceremony would either fail confusingly or fall
	// through to the unsigned path. Say which is missing instead.
	if len(cfg.TrustAnchors) == 0 && cfg.SignaturePolicy != config.PolicyOptional {
		return config.RepoConfig{}, fmt.Errorf(
			"repo add: %q is configured with no trust_anchors, so its descriptor "+
				"cannot be verified against anything", name)
	}
	return cfg, nil
}
