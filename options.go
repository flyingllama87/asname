package asname

import (
	"path/filepath"
	"time"

	"github.com/flyingllama87/asname/internal/sources"
)

// FeatureState controls whether optional databases are loaded.
type FeatureState int

const (
	// FeatureAuto automatically loads the database if its file is present on disk.
	FeatureAuto FeatureState = iota
	// FeatureEnabled forces loading the database.
	FeatureEnabled
	// FeatureDisabled prevents loading the database even if present on disk.
	FeatureDisabled
)

// WhoisMode controls online whois fallbacks for addresses not in the offline database.
type WhoisMode int

const (
	// WhoisNever disables online whois queries (default for library usage).
	WhoisNever WhoisMode = iota
	// WhoisAsk prompts the user on stdin/stderr (used mainly in interactive CLI).
	WhoisAsk
	// WhoisAlways allows online whois queries without prompting.
	WhoisAlways
)

// CustomPaths allows explicitly specifying custom file paths for databases.
type CustomPaths struct {
	DBPath       string
	NamesPath    string
	CountryPath  string
	CityPath     string
	NetblockPath string
	CategoryPath string
	PrefixPath   string
	ConsentPath  string
	ContactPath  string
	CachePath    string
}

// Options configures the asname Client.
type Options struct {
	// DataDir is the directory where local database files reside.
	// If empty, defaults to $ASNAME_DIR or ~/.asname.
	DataDir string

	// Paths allows setting individual database file locations.
	Paths CustomPaths

	// Feature states for optional databases.
	City     FeatureState
	Netblock FeatureState
	Category FeatureState

	// EnableReverseDNS resolves PTR records for IP addresses during Lookup.
	// Defaults to false for maximum lookup speed.
	EnableReverseDNS bool

	// Whois controls online whois lookups for unassigned/unnamed netblocks.
	// Defaults to WhoisNever for library usage to avoid blocking network I/O.
	Whois WhoisMode

	// AutoUpdate refreshes data files older than this duration upon client initialization.
	// Defaults to 0 (disabled), so New() returns quickly without network calls.
	AutoUpdate time.Duration

	// ContactEmail is used to identify queries when fetching bgp.tools operator tags.
	ContactEmail string
}

// DefaultOptions returns the standard options:
// - DataDir: ~/.asname (or $ASNAME_DIR)
// - City/Netblock/Category: FeatureAuto (loaded if present on disk)
// - EnableReverseDNS: false
// - Whois: WhoisNever
// - AutoUpdate: 0 (disabled)
func DefaultOptions() Options {
	return Options{
		DataDir: sources.DefaultDir(),
		City:     FeatureAuto,
		Netblock: FeatureAuto,
		Category: FeatureAuto,
		Whois:    WhoisNever,
	}
}

// Option configures an Options value.
type Option func(*Options)

// WithDataDir sets the root data directory.
func WithDataDir(dir string) Option {
	return func(o *Options) {
		o.DataDir = dir
	}
}

// WithCity controls whether the DB-IP Lite city database is loaded.
func WithCity(enable bool) Option {
	return func(o *Options) {
		if enable {
			o.City = FeatureEnabled
		} else {
			o.City = FeatureDisabled
		}
	}
}

// WithNetblock controls whether the registry netblock database is loaded.
func WithNetblock(enable bool) Option {
	return func(o *Options) {
		if enable {
			o.Netblock = FeatureEnabled
		} else {
			o.Netblock = FeatureDisabled
		}
	}
}

// WithCategory controls whether the network category database is loaded.
func WithCategory(enable bool) Option {
	return func(o *Options) {
		if enable {
			o.Category = FeatureEnabled
		} else {
			o.Category = FeatureDisabled
		}
	}
}

// WithReverseDNS enables or disables reverse DNS PTR lookups during target queries.
func WithReverseDNS(enable bool) Option {
	return func(o *Options) {
		o.EnableReverseDNS = enable
	}
}

// WithWhois sets the whois fallback policy.
func WithWhois(mode WhoisMode) Option {
	return func(o *Options) {
		o.Whois = mode
	}
}

// WithAutoUpdate sets the maximum age for database freshness check on New().
// If any database is older than maxAge, it will be refreshed during New().
func WithAutoUpdate(maxAge time.Duration) Option {
	return func(o *Options) {
		o.AutoUpdate = maxAge
	}
}

// WithContactEmail sets the contact email for bgp.tools API queries.
func WithContactEmail(email string) Option {
	return func(o *Options) {
		o.ContactEmail = email
	}
}

// WithCustomPaths configures explicit custom database paths.
func WithCustomPaths(paths CustomPaths) Option {
	return func(o *Options) {
		o.Paths = paths
	}
}

func (o *Options) toSourcesConfig() sources.Config {
	dir := o.DataDir
	if dir == "" {
		dir = sources.DefaultDir()
	}

	c := sources.Config{
		DBPath:       o.Paths.DBPath,
		NamesPath:    o.Paths.NamesPath,
		CountryPath:  o.Paths.CountryPath,
		CityPath:     o.Paths.CityPath,
		NetblockPath: o.Paths.NetblockPath,
		CategoryPath: o.Paths.CategoryPath,
		PrefixPath:   o.Paths.PrefixPath,
		ConsentPath:  o.Paths.ConsentPath,
		ContactPath:  o.Paths.ContactPath,
		CachePath:    o.Paths.CachePath,
	}

	if c.DBPath == "" {
		c.DBPath = filepath.Join(dir, sources.DBFilename)
	}
	if c.NamesPath == "" {
		c.NamesPath = filepath.Join(dir, sources.NamesFilename)
	}
	if c.CountryPath == "" {
		c.CountryPath = filepath.Join(dir, sources.CountryFilename)
	}
	if c.CityPath == "" {
		c.CityPath = filepath.Join(dir, sources.CityFilename)
	}
	if c.NetblockPath == "" {
		c.NetblockPath = filepath.Join(dir, sources.NetblockFilename)
	}
	if c.CategoryPath == "" {
		c.CategoryPath = filepath.Join(dir, sources.CategoryFilename)
	}
	if c.PrefixPath == "" {
		c.PrefixPath = filepath.Join(dir, sources.PrefixFilename)
	}
	if c.ConsentPath == "" {
		c.ConsentPath = filepath.Join(dir, sources.WhoisConsentFilename)
	}
	if c.ContactPath == "" {
		c.ContactPath = filepath.Join(dir, sources.ContactFilename)
	}
	if c.CachePath == "" {
		c.CachePath = filepath.Join(dir, sources.CacheDirName)
	}
	return c
}
