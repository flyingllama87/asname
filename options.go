package asname

import (
	"io"
	"os"
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

	// Paths allows setting individual database file locations. A path left
	// empty comes from its environment variable (ASNAME_DB, ASNAME_NAMES,
	// ASNAME_COUNTRY, ASNAME_CITY, ASNAME_NETBLOCK, ASNAME_CATEGORY,
	// ASNAME_PREFIXES), the same ones the asname CLI reads, and otherwise
	// from DataDir.
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

	// OnlinePrefixes lets LookupASN fetch an ASN's announced prefixes from an
	// online service when the local prefix database (built by an ASN update)
	// does not cover it. Defaults to false, so lookups stay offline.
	OnlinePrefixes bool

	// AutoUpdate refreshes data files older than this duration upon client initialization.
	// Defaults to 0 (disabled), so New() returns quickly without network calls.
	AutoUpdate time.Duration

	// ContactEmail is used to identify queries when fetching bgp.tools operator tags.
	// If empty, $ASNAME_CONTACT_EMAIL is used.
	ContactEmail string

	// Log receives warnings (an optional database that failed to open, a
	// failed whois query) and AutoUpdate's download progress. Nil discards
	// them; the library never writes to stderr on its own.
	Log io.Writer
}

// DefaultOptions returns the standard options:
// - DataDir: $ASNAME_DIR, else ~/.asname
// - City/Netblock/Category: FeatureAuto (loaded if present on disk)
// - EnableReverseDNS: false
// - Whois: WhoisNever
// - OnlinePrefixes: false
// - AutoUpdate: 0 (disabled)
func DefaultOptions() Options {
	return Options{
		DataDir:  dataDir(""),
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

// WithOnlinePrefixes controls whether LookupASN may query an online service
// for announced prefixes the local prefix database lacks. Off by default.
func WithOnlinePrefixes(enable bool) Option {
	return func(o *Options) {
		o.OnlinePrefixes = enable
	}
}

// WithLog sends warnings and AutoUpdate progress to w. Without it they are discarded.
func WithLog(w io.Writer) Option {
	return func(o *Options) {
		o.Log = w
	}
}

// WithCustomPaths configures explicit custom database paths.
func WithCustomPaths(paths CustomPaths) Option {
	return func(o *Options) {
		o.Paths = paths
	}
}

func (o *Options) toSourcesConfig() sources.Config {
	return resolveConfig(o.DataDir, o.Paths)
}

// dataDir returns dir, else $ASNAME_DIR, else ~/.asname.
func dataDir(dir string) string {
	if dir != "" {
		return dir
	}
	if env := os.Getenv(sources.DirEnvVar); env != "" {
		return env
	}
	return sources.DefaultDir()
}

// contactEmail returns email, else $ASNAME_CONTACT_EMAIL.
func contactEmail(email string) string {
	if email != "" {
		return email
	}
	return os.Getenv(sources.ContactEnvVar)
}

// resolveConfig picks each database's location: the explicit path, else its
// ASNAME_* environment variable, else its standard filename under dir. This is
// the precedence the CLI gives its flags, so a library caller and `asname` read
// the same files. The consent, contact and cache files and the IPv6 marker
// have no variable of their own and always live under dir. IPv6 routes are
// imported by an ASN update when an earlier update opted into them.
func resolveConfig(dir string, p CustomPaths) sources.Config {
	dir = dataDir(dir)
	pick := func(explicit, env, name string) string {
		if explicit != "" {
			return explicit
		}
		if env != "" {
			if v := os.Getenv(env); v != "" {
				return v
			}
		}
		return filepath.Join(dir, name)
	}
	cfg := sources.Config{
		DBPath:       pick(p.DBPath, sources.DBEnvVar, sources.DBFilename),
		NamesPath:    pick(p.NamesPath, sources.NamesEnvVar, sources.NamesFilename),
		CountryPath:  pick(p.CountryPath, sources.CountryEnvVar, sources.CountryFilename),
		CityPath:     pick(p.CityPath, sources.CityEnvVar, sources.CityFilename),
		NetblockPath: pick(p.NetblockPath, sources.NetblockEnvVar, sources.NetblockFilename),
		CategoryPath: pick(p.CategoryPath, sources.CategoryEnvVar, sources.CategoryFilename),
		PrefixPath:   pick(p.PrefixPath, sources.PrefixEnvVar, sources.PrefixFilename),
		ConsentPath:  pick(p.ConsentPath, "", sources.WhoisConsentFilename),
		ContactPath:  pick(p.ContactPath, "", sources.ContactFilename),
		CachePath:    pick(p.CachePath, "", sources.CacheDirName),

		PrefixConsentPath: pick("", "", sources.OnlinePrefixConsentFilename),
		IPv6Path:          pick("", "", sources.IPv6MarkerFilename),
	}
	cfg.IPv6 = sources.IPv6RoutesEnabled(cfg)
	return cfg
}
