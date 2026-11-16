package asname

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/flyingllama87/asname/internal/sources"
)

// UpdateOptions specifies which databases to download or refresh.
type UpdateOptions struct {
	// DataDir is where files will be written. If empty, uses $ASNAME_DIR, else ~/.asname.
	DataDir string

	// Specific databases to update. If all flags are false, updates core databases: ASN, Names, and Country.
	All      bool
	ASN      bool
	Names    bool
	Country  bool
	City     bool
	Netblock bool
	// Geofeed fetches the networks' own RFC 8805 geofeeds, which the
	// netblock database's registry ranges point to; it needs that database.
	Geofeed  bool
	Category bool
	// Reputation builds the public blocklist database. It is built after
	// the ASN database, whose routes attribute listed addresses to ASNs.
	Reputation bool

	// IPv6 controls whether an ASN update imports IPv6 routes as well as
	// IPv4. FeatureAuto, the default, keeps whatever the last update did,
	// which is IPv4 only until an update enables IPv6.
	IPv6 FeatureState

	// Paths allows overriding specific database file locations. A path left
	// empty comes from its ASNAME_* environment variable, else from DataDir.
	Paths CustomPaths

	// ContactEmail identifies the caller to bgp.tools when updating the
	// category database. If empty, $ASNAME_CONTACT_EMAIL is used, then any
	// address saved by the CLI. With none, the bgp.tools operator tags are
	// skipped; an update never prompts for one.
	ContactEmail string

	// Log receives download progress and warnings. Nil discards them.
	Log io.Writer
}

// Update downloads every selected database, however recent the copy on disk.
// A database that cannot be rebuilt keeps its existing file and the rest are
// still attempted; the error then names each failure. ctx bounds the
// downloads: cancelling it abandons the one in progress (a partial download is
// kept and resumed by the next update) and stops before the next database.
func Update(ctx context.Context, opts UpdateOptions) error {
	_, err := runUpdate(ctx, opts, func(updateStep) bool { return true })
	return err
}

// UpdateStale refreshes only the selected databases that are missing or, when
// maxAge is positive, older than maxAge. A maxAge of zero or less only fills in
// missing files. It returns the paths it rewrote, in update order, including
// when some other database failed.
func UpdateStale(ctx context.Context, opts UpdateOptions, maxAge time.Duration) ([]string, error) {
	return runUpdate(ctx, opts, func(s updateStep) bool { return sources.Stale(s.path, maxAge) })
}

// UpdateIncomplete rebuilds only the selected databases whose last update
// failed or could not read one of its sources (a registry dump cut off
// mid-download, say), plus any missing core database. Downloads that did
// succeed are reused from the cache for 24 hours, so a retry soon after
// fetches only what failed. It returns the paths it rewrote.
func UpdateIncomplete(ctx context.Context, opts UpdateOptions) ([]string, error) {
	rec := sources.LoadUpdateRecord(resolveConfig(opts.DataDir, opts.Paths).UpdateRecordPath)
	return runUpdate(ctx, opts, func(s updateStep) bool {
		if rec[s.key].Incomplete() {
			return true
		}
		switch s.key {
		case sources.KeyASN, sources.KeyNames, sources.KeyCountry:
			return sources.Stale(s.path, 0)
		}
		return false
	})
}

// Incomplete reports, for each database whose last update failed or left a
// source out, the sources it could not read. A database that failed outright
// lists the error instead.
func Incomplete(dataDir string) map[string][]string {
	out := map[string][]string{}
	rec := sources.LoadUpdateRecord(resolveConfig(dataDir, CustomPaths{}).UpdateRecordPath)
	for _, key := range rec.Incomplete() {
		if o := rec[key]; o.Error != "" {
			out[key] = []string{o.Error}
		} else {
			out[key] = o.Failed
		}
	}
	return out
}

// updateStep is one database: where it lives and how to rebuild it.
type updateStep struct {
	key  string
	name string
	path string
	run  func(context.Context, sources.Config) error
}

// runUpdate rebuilds each selected database for which want reports true.
func runUpdate(ctx context.Context, opts UpdateOptions, want func(updateStep) bool) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg := resolveConfig(opts.DataDir, opts.Paths)
	switch opts.IPv6 {
	case FeatureEnabled:
		cfg.IPv6 = true
	case FeatureDisabled:
		cfg.IPv6 = false
	}
	ctx = sources.WithLog(ctx, opts.Log)

	all := opts.All
	asn, names, country := opts.ASN || all, opts.Names || all, opts.Country || all
	if !all && !opts.ASN && !opts.Names && !opts.Country && !opts.City && !opts.Netblock && !opts.Geofeed && !opts.Category && !opts.Reputation {
		asn, names, country = true, true, true
	}

	var steps []updateStep
	if asn {
		steps = append(steps, updateStep{sources.KeyASN, "ASN", cfg.DBPath, func(ctx context.Context, cfg sources.Config) error {
			return sources.UpdateDatabase(ctx, cfg, "")
		}})
	}
	if names {
		steps = append(steps, updateStep{sources.KeyNames, "names", cfg.NamesPath, sources.UpdateNames})
	}
	if country {
		steps = append(steps, updateStep{sources.KeyCountry, "country", cfg.CountryPath, sources.UpdateCountryDB})
	}
	if opts.City || all {
		steps = append(steps, updateStep{sources.KeyCity, "city", cfg.CityPath, sources.UpdateCityDB})
	}
	if opts.Netblock || all {
		steps = append(steps, updateStep{sources.KeyNetblock, "netblock", cfg.NetblockPath, sources.UpdateNetblockDB})
	}
	if opts.Geofeed || all {
		steps = append(steps, updateStep{sources.KeyGeofeed, "geofeed", cfg.GeofeedPath, sources.UpdateGeofeedDB})
	}
	if opts.Category || all {
		steps = append(steps, updateStep{sources.KeyCategory, "category", cfg.CategoryPath, func(ctx context.Context, cfg sources.Config) error {
			return sources.UpdateCategoryDB(ctx, cfg, libraryContact(cfg, contactEmail(opts.ContactEmail), opts.Log))
		}})
	}

	if opts.Reputation || all {
		steps = append(steps, updateStep{sources.KeyReputation, "reputation", cfg.ReputationPath, sources.UpdateReputationDB})
	}

	// A database that fails keeps its previous file and does not stop the
	// others: they come from different hosts, and one throttled registry is
	// no reason to leave the rest stale. Cancellation stops everything.
	var refreshed []string
	var errs []error
	for _, s := range steps {
		if !want(s) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return refreshed, err
		}
		if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
			errs = append(errs, fmt.Errorf("creating data directory for %s: %w", s.path, err))
			continue
		}
		if err := s.run(ctx, cfg); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return refreshed, ctxErr
			}
			errs = append(errs, fmt.Errorf("updating %s database: %w", s.name, err))
			continue
		}
		refreshed = append(refreshed, s.path)
	}
	return refreshed, errors.Join(errs...)
}

// libraryContact returns a bgp.tools contact source that never prompts: a
// library has no terminal of its own, so a missing address skips the tags.
func libraryContact(cfg sources.Config, email string, log io.Writer) *sources.ContactAsker {
	a := sources.NewContactAsker(cfg.ContactPath, email)
	a.Terminal = false
	a.Out = log
	if a.Out == nil {
		a.Out = io.Discard
	}
	return a
}
