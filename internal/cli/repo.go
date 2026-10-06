package cli

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

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
	maxStale := fs.Int("max-index-staleness-days", 0,
		"maximum age of the index's own generated_at before operations demand a refresh "+
			"(0 = default 90, §5.34)")
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
			MaxIndexStalenessDays:  *maxStale,
		}
	default:
		return fmt.Errorf("repo add: usage: repo add <name> <base-url> --anchor <fingerprint>\n" +
			"                  repo add <name>   (for a repository already configured on this system)")
	}

	// Every add is recorded from here on, failed or not: the ceremony
	// decides whose packages the system will install.
	previous, err := app.addRepository(cfg, len(pos) == 1)
	ev := audit.New(audit.TypeRepositoryAdded).
		Str(audit.FieldRepositoryName, cfg.Name).
		Str(audit.FieldRepositoryURL, cfg.BaseURL)
	app.emit(withOutcome(ev, err))
	if err != nil {
		return err
	}
	// §7.6.3.1: a trust-policy or transport-flag change is recorded, one
	// record per setting. Re-adding an existing repository with a
	// weakened policy otherwise produced an audit trail identical to a
	// routine add, and trust-policy history could not be reconstructed
	// from the event stream at all.
	for _, c := range trustPolicyChanges(previous, cfg) {
		app.emit(c.event(cfg.Name))
	}
	return nil
}

// addRepository writes a repository's configuration, when this command
// supplied it, and performs the trust ceremony. It returns the
// configuration the repository had before, nil when it had none.
func (app *App) addRepository(cfg config.RepoConfig, preconfigured bool) (*config.RepoConfig, error) {
	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return nil, err
	}
	defer store.Close()

	provider := app.configProvider()

	// Capture what was configured before this command overwrites it, for
	// the peipkg.repository.reconfigured records.
	var previous *config.RepoConfig
	if prior, found, err := provider.Repository(cfg.Name); err == nil && found {
		previous = &prior
	}

	if !preconfigured {
		if err := provider.Put(cfg); err != nil {
			return previous, err
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
		return previous, err
	}
	app.printf("added repository %q\n", cfg.Name)
	app.warnUnsigned(cfg)
	return previous, nil
}

// settingChange is one trust-relevant setting a repository add changed:
// signature_policy as text, every other setting as a number.
type settingChange struct {
	name                 string
	text, textPrevious   string
	value, valuePrevious uint64
	numeric              bool
}

// event is the change's peipkg.repository.reconfigured record.
func (c settingChange) event(repo string) audit.Event {
	ev := audit.New(audit.TypeRepositoryReconfigured).
		Str(audit.FieldRepositoryName, repo).
		Str(audit.FieldConfigName, c.name)
	if c.numeric {
		return ev.Uint(audit.FieldConfigValue, c.value).
			Uint(audit.FieldConfigValuePrevious, c.valuePrevious)
	}
	return ev.Str(audit.FieldConfigText, c.text).
		Str(audit.FieldConfigTextPrevious, c.textPrevious)
}

// trustPolicyChanges lists how the trust-relevant settings of an
// existing repository differ from the ones just configured, by the names
// the repository file gives them. It returns nothing when nothing
// changed, and for a repository that did not previously exist: a first
// add is already covered by peipkg.repository.added.
//
// A number is recorded as written, so 0 for a setting left at its
// default; allow_insecure_transport is 1 or 0; trust_anchors is how many
// anchors are configured, so swapping one anchor for another records a
// change between equal counts.
//
// This only sees a change made through the flags of `repo add <name>
// <url>`. The configured form reads the .repo file for both sides, so an
// operator who edits that file directly and re-runs the ceremony leaves
// nothing here to compare; detecting that would need peipkg to record the
// previously-trusted policy of its own accord.
func trustPolicyChanges(previous *config.RepoConfig, next config.RepoConfig) []settingChange {
	if previous == nil {
		return nil
	}
	var changes []settingChange
	number := func(name string, from, to int64) {
		if from != to {
			changes = append(changes, settingChange{name: name, numeric: true,
				value: nonNegative(to), valuePrevious: nonNegative(from)})
		}
	}
	if previous.SignaturePolicy != next.SignaturePolicy {
		changes = append(changes, settingChange{name: "signature_policy",
			text: string(next.SignaturePolicy), textPrevious: string(previous.SignaturePolicy)})
	}
	number("allow_insecure_transport", boolNumber(previous.AllowInsecureTransport),
		boolNumber(next.AllowInsecureTransport))
	number("max_trusted_age_days", int64(previous.MaxTrustedAgeDays), int64(next.MaxTrustedAgeDays))
	number("min_index_version", previous.MinIndexVersion, next.MinIndexVersion)
	number("max_index_staleness_days", int64(previous.MaxIndexStalenessDays),
		int64(next.MaxIndexStalenessDays))
	if !slices.Equal(previous.TrustAnchors, next.TrustAnchors) {
		changes = append(changes, settingChange{name: "trust_anchors", numeric: true,
			value: uint64(len(next.TrustAnchors)), valuePrevious: uint64(len(previous.TrustAnchors))})
	}
	return changes
}

func boolNumber(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// nonNegative clamps a setting configuration validation already keeps
// non-negative.
func nonNegative(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
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
		return app.repoListJSON(repos)
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

// repoListJSON emits the configured repositories with their trust state:
// whether the trust ceremony has run, when the repository last refreshed,
// how old its metadata is, whether either is past its maximum, and how
// many packages its cached index offers.
func (app *App) repoListJSON(repos []config.RepoConfig) error {
	type view struct {
		Name                   string   `json:"name"`
		BaseURL                string   `json:"base_url"`
		Priority               int      `json:"priority"`
		SignaturePolicy        string   `json:"signature_policy"`
		TrustAnchors           []string `json:"trust_anchors"`
		AllowInsecureTransport bool     `json:"allow_insecure_transport"`
		Trusted                bool     `json:"trusted"`
		LastRefresh            string   `json:"last_refresh,omitempty"`
		IndexGenerated         string   `json:"index_generated,omitempty"`
		Stale                  bool     `json:"stale"`
		Packages               int      `json:"packages"`
	}
	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()
	client := app.repoClient(store)
	now := time.Now()

	views := make([]view, 0, len(repos))
	for _, r := range repos {
		v := view{Name: r.Name, BaseURL: r.BaseURL, Priority: r.Priority,
			SignaturePolicy: string(r.SignaturePolicy), TrustAnchors: r.TrustAnchors,
			AllowInsecureTransport: r.AllowInsecureTransport}
		if v.TrustAnchors == nil {
			v.TrustAnchors = []string{}
		}
		row, found, err := store.GetRepository(ctx, r.Name)
		if err != nil {
			return err
		}
		if found {
			v.Trusted = true
			if !row.LastRefreshAt.IsZero() {
				v.LastRefresh = row.LastRefreshAt.UTC().Format(time.RFC3339)
			}
			if row.GeneratedAtFloor != 0 {
				v.IndexGenerated = time.Unix(row.GeneratedAtFloor, 0).UTC().Format(time.RFC3339)
			}
			_, ageStale, err := client.TrustAge(ctx, r, now)
			if err != nil {
				return err
			}
			_, indexStale, err := client.IndexStaleness(ctx, r, now)
			if err != nil {
				return err
			}
			v.Stale = ageStale || indexStale
			if idx, err := client.ActiveIndex(ctx, r.Name); err == nil {
				v.Packages = len(idx.Packages)
			}
		}
		views = append(views, v)
	}
	return app.emitJSON(views)
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

	err = app.removeRepository(name)
	ev := audit.New(audit.TypeRepositoryRemoved).Str(audit.FieldRepositoryName, name)
	if err != nil {
		app.emit(ev.Failed("", err.Error()))
		return err
	}
	app.emit(ev.Succeeded())
	app.printf("removed repository %q\n", name)
	return nil
}

// removeRepository removes a repository's configuration and its recorded
// trust state.
func (app *App) removeRepository(name string) error {
	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	if err := app.configProvider().Remove(name); err != nil {
		return err
	}
	return store.DeleteRepository(ctx, name)
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
	app.emit(audit.New(audit.TypeRepositoryRefreshed).
		Uint(audit.FieldOperationSucceeded, uint64(refreshed)).
		Uint(audit.FieldOperationFailed, uint64(failures)).
		Bool(audit.FieldOutcomeSuccess, failures == 0))
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
