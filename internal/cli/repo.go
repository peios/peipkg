package cli

import (
	"context"
	"fmt"
	"strings"

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
	var anchors stringList
	fs.Var(&anchors, "anchor", "a trusted signing-key fingerprint (repeatable)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("repo add: usage: repo add <name> <base-url> --anchor <fingerprint>")
	}
	cfg := config.RepoConfig{
		Name:                   pos[0],
		BaseURL:                pos[1],
		Priority:               *priority,
		SignaturePolicy:        config.SignaturePolicy(*policy),
		TrustAnchors:           anchors,
		AllowInsecureTransport: *insecure,
		MinIndexVersion:        *minIndex,
	}

	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	provider := app.configProvider()
	if err := provider.Put(cfg); err != nil {
		return err
	}
	if err := app.repoClient(store).Add(ctx, cfg); err != nil {
		// The trust ceremony failed; back out the configuration file so
		// a half-added repository is not left behind.
		_ = provider.Remove(cfg.Name)
		return err
	}
	app.printf("added repository %q\n", cfg.Name)
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
		refreshed++
	}
	if refreshed == 0 && failures == 0 {
		app.printf("no repositories to refresh\n")
	}
	if failures > 0 {
		return fmt.Errorf("%d repository refresh(es) failed", failures)
	}
	return nil
}
