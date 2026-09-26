package asname

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/flyingllama87/asname/internal/sources"
)

// UpdateOptions specifies which databases to download or refresh.
type UpdateOptions struct {
	// DataDir is where files will be written. If empty, uses default ~/.asname or $ASNAME_DIR.
	DataDir string

	// Specific databases to update. If all flags are false, updates core databases: ASN, Names, and Country.
	All      bool
	ASN      bool
	Names    bool
	Country  bool
	City     bool
	Netblock bool
	Category bool

	// Paths allows overriding specific database file locations.
	Paths CustomPaths

	// ContactEmail is required when updating category operator tags from bgp.tools.
	ContactEmail string
}

// Update downloads or updates databases according to the provided options.
func Update(ctx context.Context, opts UpdateOptions) error {
	dir := opts.DataDir
	if dir == "" {
		dir = sources.DefaultDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating data directory %s: %w", dir, err)
	}

	cfg := sources.Config{
		DBPath:       opts.Paths.DBPath,
		NamesPath:    opts.Paths.NamesPath,
		CountryPath:  opts.Paths.CountryPath,
		CityPath:     opts.Paths.CityPath,
		NetblockPath: opts.Paths.NetblockPath,
		CategoryPath: opts.Paths.CategoryPath,
		PrefixPath:   opts.Paths.PrefixPath,
		ConsentPath:  opts.Paths.ConsentPath,
		ContactPath:  opts.Paths.ContactPath,
		CachePath:    opts.Paths.CachePath,
	}

	if cfg.DBPath == "" {
		cfg.DBPath = filepath.Join(dir, sources.DBFilename)
	}
	if cfg.NamesPath == "" {
		cfg.NamesPath = filepath.Join(dir, sources.NamesFilename)
	}
	if cfg.CountryPath == "" {
		cfg.CountryPath = filepath.Join(dir, sources.CountryFilename)
	}
	if cfg.CityPath == "" {
		cfg.CityPath = filepath.Join(dir, sources.CityFilename)
	}
	if cfg.NetblockPath == "" {
		cfg.NetblockPath = filepath.Join(dir, sources.NetblockFilename)
	}
	if cfg.CategoryPath == "" {
		cfg.CategoryPath = filepath.Join(dir, sources.CategoryFilename)
	}
	if cfg.PrefixPath == "" {
		cfg.PrefixPath = filepath.Join(dir, sources.PrefixFilename)
	}
	if cfg.ConsentPath == "" {
		cfg.ConsentPath = filepath.Join(dir, sources.WhoisConsentFilename)
	}
	if cfg.ContactPath == "" {
		cfg.ContactPath = filepath.Join(dir, sources.ContactFilename)
	}
	if cfg.CachePath == "" {
		cfg.CachePath = filepath.Join(dir, sources.CacheDirName)
	}

	updateAll := opts.All
	updateASN := opts.ASN || updateAll
	updateNames := opts.Names || updateAll
	updateCountry := opts.Country || updateAll
	updateCity := opts.City || updateAll
	updateNetblock := opts.Netblock || updateAll
	updateCategory := opts.Category || updateAll

	// If no specific flag was selected, update core: ASN, Names, Country
	if !opts.All && !opts.ASN && !opts.Names && !opts.Country && !opts.City && !opts.Netblock && !opts.Category {
		updateASN = true
		updateNames = true
		updateCountry = true
	}

	if updateASN {
		if err := sources.UpdateDatabase(cfg, ""); err != nil {
			return fmt.Errorf("updating ASN database: %w", err)
		}
	}
	if updateNames {
		if err := sources.UpdateNames(cfg); err != nil {
			return fmt.Errorf("updating names database: %w", err)
		}
	}
	if updateCountry {
		if err := sources.UpdateCountryDB(cfg); err != nil {
			return fmt.Errorf("updating country database: %w", err)
		}
	}
	if updateCity {
		if err := sources.UpdateCityDB(cfg); err != nil {
			return fmt.Errorf("updating city database: %w", err)
		}
	}
	if updateNetblock {
		if err := sources.UpdateNetblockDB(cfg); err != nil {
			return fmt.Errorf("updating netblock database: %w", err)
		}
	}
	if updateCategory {
		contact := sources.NewContactAsker(cfg.ContactPath, opts.ContactEmail)
		if err := sources.UpdateCategoryDB(cfg, contact); err != nil {
			return fmt.Errorf("updating category database: %w", err)
		}
	}
	return nil
}
