package sources

import (
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/flyingllama87/asname/pkg/database"
)

const (
	ripeASNames  = "https://ftp.ripe.net/ripe/asnames/asn.txt"
	dbipCityDump = "https://download.db-ip.com/free/dbip-city-lite-%s.mmdb.gz"
)

// ribSource is one archive of MRT RIB dumps. Each holds a monthly directory of
// dated files, so the newest file is found by listing the directory for the
// current month and falling back to the previous one.
type ribSource struct {
	name     string
	listing  string         // directory URL, with the month as "2006.01"
	filename *regexp.Regexp // dump filenames within that directory
	size     string         // approximate download size, for the operator
}

// ribSources are tried in order until one yields a database. RouteViews is the
// smallest download and is tried first; the RIPE RIS collectors are a separate
// operator on separate infrastructure, so an outage at one does not stop the
// other. rrc04 is comparable in size to RouteViews, and rrc00 is RIS' multi-hop
// collector, the most complete and the largest.
var ribSources = []ribSource{
	{
		name:     "RouteViews route-views2",
		listing:  "http://archive.routeviews.org/bgpdata/%s/RIBS/",
		filename: regexp.MustCompile(`rib\.[0-9]{8}\.[0-9]{4}\.bz2`),
		size:     "~75MB",
	},
	{
		name:     "RIPE RIS rrc04",
		listing:  "https://data.ris.ripe.net/rrc04/%s/",
		filename: regexp.MustCompile(`bview\.[0-9]{8}\.[0-9]{4}\.gz`),
		size:     "~70MB",
	},
	{
		name:     "RIPE RIS rrc00",
		listing:  "https://data.ris.ripe.net/rrc00/%s/",
		filename: regexp.MustCompile(`bview\.[0-9]{8}\.[0-9]{4}\.gz`),
		size:     "~400MB",
	},
}

// decompress wraps r according to the dump's file extension.
func decompress(url string, r io.Reader) (io.Reader, error) {
	if strings.HasSuffix(url, ".gz") {
		return gzip.NewReader(r)
	}
	return bzip2.NewReader(r), nil
}

// AutoUpdate refreshes any data file that is missing or older than maxAge.
func AutoUpdate(cfg Config, maxAge time.Duration, city, netblock, category bool, contact *ContactAsker) error {
	if stale(cfg.DBPath, maxAge) {
		fmt.Fprintln(os.Stderr, "asname: refreshing ASN database...")
		if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o755); err != nil {
			return err
		}
		if err := UpdateDatabase(cfg, ""); err != nil {
			return err
		}
	}
	if stale(cfg.NamesPath, maxAge) {
		fmt.Fprintln(os.Stderr, "asname: refreshing name database...")
		if err := os.MkdirAll(filepath.Dir(cfg.NamesPath), 0o755); err != nil {
			return err
		}
		if err := UpdateNames(cfg); err != nil {
			return err
		}
	}
	if stale(cfg.CountryPath, maxAge) {
		fmt.Fprintln(os.Stderr, "asname: refreshing country database...")
		if err := os.MkdirAll(filepath.Dir(cfg.CountryPath), 0o755); err != nil {
			return err
		}
		if err := UpdateCountryDB(cfg); err != nil {
			return err
		}
	}
	if city && stale(cfg.CityPath, maxAge) {
		fmt.Fprintln(os.Stderr, "asname: refreshing city database...")
		if err := os.MkdirAll(filepath.Dir(cfg.CityPath), 0o755); err != nil {
			return err
		}
		if err := UpdateCityDB(cfg); err != nil {
			return err
		}
	}
	if netblock && stale(cfg.NetblockPath, maxAge) {
		fmt.Fprintln(os.Stderr, "asname: refreshing netblock database...")
		if err := os.MkdirAll(filepath.Dir(cfg.NetblockPath), 0o755); err != nil {
			return err
		}
		if err := UpdateNetblockDB(cfg); err != nil {
			return err
		}
	}
	if category && stale(cfg.CategoryPath, maxAge) {
		fmt.Fprintln(os.Stderr, "asname: refreshing category database...")
		if err := os.MkdirAll(filepath.Dir(cfg.CategoryPath), 0o755); err != nil {
			return err
		}
		if err := UpdateCategoryDB(cfg, contact); err != nil {
			return err
		}
	}
	return nil
}

func stale(path string, maxAge time.Duration) bool {
	info, err := os.Stat(path)
	if err != nil {
		return true
	}
	if maxAge <= 0 {
		return false
	}
	return time.Since(info.ModTime()) > maxAge
}

// UpdateDatabase downloads an MRT RIB dump, converts it to binary and replaces
// cfg.DBPath. With no ribURL given it works through ribSources in order, moving
// on to the next archive whenever one cannot be listed, downloaded or parsed.
func UpdateDatabase(cfg Config, ribURL string) error {
	cache := cfg.CacheDir()

	if ribURL != "" {
		return buildFromRIB(cfg, cache, ribURL)
	}

	var failures []string
	for i, src := range ribSources {
		if i > 0 {
			fmt.Fprintf(os.Stderr, "asname: falling back to %s%s\n", src.name, parenthesise(src.size))
		}
		url, err := latestRIBURL(cache, src)
		if err != nil {
			fmt.Fprintf(os.Stderr, "asname: %s: %v\n", src.name, err)
			failures = append(failures, fmt.Sprintf("%s: %v", src.name, err))
			continue
		}
		if err := buildFromRIB(cfg, cache, url); err != nil {
			fmt.Fprintf(os.Stderr, "asname: %s: %v\n", src.name, err)
			failures = append(failures, fmt.Sprintf("%s: %v", src.name, err))
			continue
		}
		return nil
	}
	return fmt.Errorf("every RIB archive failed: %s", strings.Join(failures, "; "))
}

func parenthesise(s string) string {
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}

// buildFromRIB imports one MRT dump and replaces cfg.DBPath with the result.
func buildFromRIB(cfg Config, cache, ribURL string) error {
	f, err := openCached(cache, ribURL, "")
	if err != nil {
		return err
	}
	defer f.Close()

	r, err := decompress(ribURL, bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		dropCached(cache, ribURL)
		return fmt.Errorf("decompressing %s: %v", ribURL, err)
	}

	builder := database.NewBuilder()
	prefixBuilder := NewPrefixDBBuilder()
	builder.SetMappingHook(func(prefix *net.IPNet, asn uint32) {
		prefixBuilder.Add(asn, prefix)
	})
	skipped, err := builder.ImportMRT(r)
	if err != nil {
		// The file downloaded in full but will not parse, so do not keep it.
		dropCached(cache, ribURL)
		return fmt.Errorf("importing MRT: %v", err)
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "asname: skipped %d MRT records this decoder does not understand\n", skipped)
	}
	builder.SetFillFactor(OptimizationFillFactor)
	db, err := builder.Build()
	if err != nil {
		return fmt.Errorf("building database: %v", err)
	}
	data, err := db.MarshalBinary()
	if err != nil {
		return err
	}
	if err := WriteFileAtomic(cfg.DBPath, data); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "asname: wrote %s (%d bytes)\n", cfg.DBPath, len(data))

	if cfg.PrefixPath != "" {
		if n, err := prefixBuilder.Write(cfg.PrefixPath); err != nil {
			fmt.Fprintf(os.Stderr, "asname: warning: failed to write prefix database: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "asname: wrote %s (%d bytes)\n", cfg.PrefixPath, n)
		}
	}
	return nil
}

// UpdateNames downloads the RIPE asn.txt list and writes it to cfg.NamesPath.
func UpdateNames(cfg Config) error {
	src, err := openCached(cfg.CacheDir(), ripeASNames, "")
	if err != nil {
		return err
	}
	defer src.Close()

	tmp, err := os.CreateTemp(filepath.Dir(cfg.NamesPath), ".asn_db.*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	count, err := WriteNamesFromRIPE(src, tmp)
	if err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, cfg.NamesPath); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "asname: wrote %s (%d AS names)\n", cfg.NamesPath, count)
	return nil
}

// UpdateCityDB downloads the DB-IP Lite city database and decompresses it into cfg.CityPath.
func UpdateCityDB(cfg Config) error {
	cache := cfg.CacheDir()
	now := time.Now().UTC()
	var lastErr error
	for _, month := range []time.Time{now, now.AddDate(0, -1, 0)} {
		url := fmt.Sprintf(dbipCityDump, month.Format("2006-01"))
		f, err := openCached(cache, url, "")
		if err != nil {
			lastErr = err
			continue
		}

		gz, err := gzip.NewReader(bufio.NewReaderSize(f, 1<<20))
		if err != nil {
			f.Close()
			dropCached(cache, url)
			return fmt.Errorf("decompressing %s: %v", url, err)
		}
		n, err := StreamFileAtomic(cfg.CityPath, gz)
		gz.Close()
		f.Close()
		if err != nil {
			dropCached(cache, url)
			return err
		}
		fmt.Fprintf(os.Stderr, "asname: wrote %s (%d bytes)\n", cfg.CityPath, n)
		return nil
	}
	return fmt.Errorf("no city database found on db-ip.com: %v", lastErr)
}

// latestRIBURL resolves the newest dump in src. The directory listing is cached
// alongside the dumps, so a retry after a failed download resolves to the same
// dump and reuses what was already fetched.
func latestRIBURL(cache string, src ribSource) (string, error) {
	now := time.Now().UTC()
	var lastErr error
	for _, month := range []time.Time{now, now.AddDate(0, -1, 0)} {
		dir := fmt.Sprintf(src.listing, month.Format("2006.01"))
		path, err := fetchCached(cache, dir, "")
		if err != nil {
			lastErr = err
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			lastErr = err
			continue
		}
		matches := src.filename.FindAllString(string(body), -1)
		if len(matches) == 0 {
			lastErr = fmt.Errorf("no dump listed in %s", dir)
			continue
		}
		return dir + matches[len(matches)-1], nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no dump found")
	}
	return "", lastErr
}
