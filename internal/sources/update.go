package sources

import (
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"context"
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

	// ipv6 is a companion archive for the IPv6 routes this one lacks, read
	// alongside it when IPv6 is enabled. It is nil for an archive whose dumps
	// already carry both address families.
	ipv6 *ribSource
}

// IPv6MarkerFilename marks, by existing, that the ASN database was built with
// IPv6 routes, so later updates keep importing them.
const IPv6MarkerFilename = "ipv6-routes"

// IPv6RoutesEnabled reports whether an earlier update opted into IPv6 routes.
func IPv6RoutesEnabled(cfg Config) bool {
	if cfg.IPv6Path == "" {
		return false
	}
	_, err := os.Stat(cfg.IPv6Path)
	return err == nil
}

// setIPv6Marker records whether the database just written holds IPv6 routes.
func setIPv6Marker(cfg Config) error {
	if cfg.IPv6Path == "" {
		return nil
	}
	if cfg.IPv6 {
		return os.WriteFile(cfg.IPv6Path, []byte("IPv6 routes are imported by `asname update`; run `asname update --no-ipv6` to stop.\n"), 0o644)
	}
	if err := os.Remove(cfg.IPv6Path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ribSources are tried in order until one yields a database. RouteViews is the
// smallest download and is tried first; the RIPE RIS collectors are a separate
// operator on separate infrastructure, so an outage at one does not stop the
// other. rrc04 is comparable in size to RouteViews, and rrc00 is RIS' multi-hop
// collector, the most complete and the largest.
//
// route-views2 collects IPv4 only, so with IPv6 enabled route-views6 is read
// with it. The RIS dumps carry both families; with IPv6 disabled their IPv6
// routes are dropped on import.
var ribSources = []ribSource{
	{
		name:     "RouteViews route-views2",
		listing:  "http://archive.routeviews.org/bgpdata/%s/RIBS/",
		filename: regexp.MustCompile(`rib\.[0-9]{8}\.[0-9]{4}\.bz2`),
		size:     "~75MB",
		ipv6: &ribSource{
			name:     "RouteViews route-views6",
			listing:  "http://archive.routeviews.org/route-views6/bgpdata/%s/RIBS/",
			filename: regexp.MustCompile(`rib\.[0-9]{8}\.[0-9]{4}\.bz2`),
			size:     "~25MB",
		},
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
func AutoUpdate(ctx context.Context, cfg Config, maxAge time.Duration, city, netblock, category bool, contact *ContactAsker) error {
	if Stale(cfg.DBPath, maxAge) {
		logf(ctx, "asname: refreshing ASN database...\n")
		if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o755); err != nil {
			return err
		}
		if err := UpdateDatabase(ctx, cfg, ""); err != nil {
			return err
		}
	}
	if Stale(cfg.NamesPath, maxAge) {
		logf(ctx, "asname: refreshing name database...\n")
		if err := os.MkdirAll(filepath.Dir(cfg.NamesPath), 0o755); err != nil {
			return err
		}
		if err := UpdateNames(ctx, cfg); err != nil {
			return err
		}
	}
	if Stale(cfg.CountryPath, maxAge) {
		logf(ctx, "asname: refreshing country database...\n")
		if err := os.MkdirAll(filepath.Dir(cfg.CountryPath), 0o755); err != nil {
			return err
		}
		if err := UpdateCountryDB(ctx, cfg); err != nil {
			return err
		}
	}
	if city && Stale(cfg.CityPath, maxAge) {
		logf(ctx, "asname: refreshing city database...\n")
		if err := os.MkdirAll(filepath.Dir(cfg.CityPath), 0o755); err != nil {
			return err
		}
		if err := UpdateCityDB(ctx, cfg); err != nil {
			return err
		}
	}
	if netblock && Stale(cfg.NetblockPath, maxAge) {
		logf(ctx, "asname: refreshing netblock database...\n")
		if err := os.MkdirAll(filepath.Dir(cfg.NetblockPath), 0o755); err != nil {
			return err
		}
		if err := UpdateNetblockDB(ctx, cfg); err != nil {
			return err
		}
	}
	if category && Stale(cfg.CategoryPath, maxAge) {
		logf(ctx, "asname: refreshing category database...\n")
		if err := os.MkdirAll(filepath.Dir(cfg.CategoryPath), 0o755); err != nil {
			return err
		}
		if err := UpdateCategoryDB(ctx, cfg, contact); err != nil {
			return err
		}
	}
	return nil
}

// Stale reports whether path is missing or, when maxAge is positive, older
// than maxAge. A maxAge of zero or less only reports missing files.
func Stale(path string, maxAge time.Duration) bool {
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
// IPv6 routes are imported only when cfg.IPv6 is set.
func UpdateDatabase(ctx context.Context, cfg Config, ribURL string) error {
	cache := cfg.CacheDir()

	if ribURL != "" {
		return buildFromRIB(ctx, cfg, cache, ribURL)
	}

	var failures []string
	for i, src := range ribSources {
		if i > 0 {
			logf(ctx, "asname: falling back to %s%s\n", src.name, parenthesise(src.size))
		}
		urls, err := latestRIBURLs(ctx, cache, src, cfg.IPv6)
		if err != nil {
			logf(ctx, "asname: %s: %v\n", src.name, err)
			failures = append(failures, fmt.Sprintf("%s: %v", src.name, err))
			continue
		}
		if err := buildFromRIB(ctx, cfg, cache, urls...); err != nil {
			logf(ctx, "asname: %s: %v\n", src.name, err)
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

// latestRIBURLs resolves the newest dump in src and, when ipv6 is set and src
// has an IPv6 companion archive, the newest dump there too.
func latestRIBURLs(ctx context.Context, cache string, src ribSource, ipv6 bool) ([]string, error) {
	url, err := latestRIBURL(ctx, cache, src)
	if err != nil {
		return nil, err
	}
	urls := []string{url}
	if ipv6 && src.ipv6 != nil {
		logf(ctx, "asname: also reading IPv6 routes from %s%s\n", src.ipv6.name, parenthesise(src.ipv6.size))
		v6, err := latestRIBURL(ctx, cache, *src.ipv6)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", src.ipv6.name, err)
		}
		urls = append(urls, v6)
	}
	return urls, nil
}

// buildFromRIB imports MRT dumps into one database and replaces cfg.DBPath
// with the result.
func buildFromRIB(ctx context.Context, cfg Config, cache string, ribURLs ...string) error {
	builder := database.NewBuilder()
	builder.SetIPv4Only(!cfg.IPv6)
	prefixBuilder := NewPrefixDBBuilder()
	builder.SetMappingHook(func(prefix *net.IPNet, asn uint32) {
		prefixBuilder.Add(asn, prefix)
	})
	for _, ribURL := range ribURLs {
		if err := importRIB(ctx, builder, cache, ribURL); err != nil {
			return err
		}
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
	logf(ctx, "asname: wrote %s (%d bytes)\n", cfg.DBPath, len(data))

	if cfg.PrefixPath != "" {
		if n, err := prefixBuilder.Write(cfg.PrefixPath); err != nil {
			logf(ctx, "asname: warning: failed to write prefix database: %v\n", err)
		} else {
			logf(ctx, "asname: wrote %s (%d bytes)\n", cfg.PrefixPath, n)
		}
	}
	if err := setIPv6Marker(cfg); err != nil {
		logf(ctx, "asname: warning: failed to record the IPv6 setting: %v\n", err)
	}
	return nil
}

// mrtImporter is the database builder, whose type is not exported.
type mrtImporter interface {
	ImportMRT(io.Reader) (int, error)
}

// importRIB reads one MRT dump into builder.
func importRIB(ctx context.Context, builder mrtImporter, cache, ribURL string) error {
	f, err := openCached(ctx, cache, ribURL, "")
	if err != nil {
		return err
	}
	defer f.Close()

	r, err := decompress(ribURL, bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		dropCached(cache, ribURL)
		return fmt.Errorf("decompressing %s: %v", ribURL, err)
	}
	skipped, err := builder.ImportMRT(r)
	if err != nil {
		// The file downloaded in full but will not parse, so do not keep it.
		dropCached(cache, ribURL)
		return fmt.Errorf("importing MRT: %v", err)
	}
	if skipped > 0 {
		logf(ctx, "asname: skipped %d MRT records this decoder does not understand\n", skipped)
	}
	return nil
}

// UpdateNames downloads the RIPE asn.txt list and writes it to cfg.NamesPath.
func UpdateNames(ctx context.Context, cfg Config) error {
	src, err := openCached(ctx, cfg.CacheDir(), ripeASNames, "")
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
	logf(ctx, "asname: wrote %s (%d AS names)\n", cfg.NamesPath, count)
	return nil
}

// UpdateCityDB downloads the DB-IP Lite city database and decompresses it into cfg.CityPath.
func UpdateCityDB(ctx context.Context, cfg Config) error {
	cache := cfg.CacheDir()
	now := time.Now().UTC()
	var lastErr error
	for _, month := range []time.Time{now, now.AddDate(0, -1, 0)} {
		url := fmt.Sprintf(dbipCityDump, month.Format("2006-01"))
		f, err := openCached(ctx, cache, url, "")
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
		logf(ctx, "asname: wrote %s (%d bytes)\n", cfg.CityPath, n)
		return nil
	}
	return fmt.Errorf("no city database found on db-ip.com: %v", lastErr)
}

// latestRIBURL resolves the newest dump in src. The directory listing is cached
// alongside the dumps, so a retry after a failed download resolves to the same
// dump and reuses what was already fetched.
func latestRIBURL(ctx context.Context, cache string, src ribSource) (string, error) {
	now := time.Now().UTC()
	var lastErr error
	for _, month := range []time.Time{now, now.AddDate(0, -1, 0)} {
		dir := fmt.Sprintf(src.listing, month.Format("2006.01"))
		path, err := fetchCached(ctx, cache, dir, "")
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
