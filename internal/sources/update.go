package sources

import (
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/flyingllama87/asname/pkg/database"
)

const (
	routeViewsBase = "http://archive.routeviews.org/bgpdata"
	ripeASNames    = "https://ftp.ripe.net/ripe/asnames/asn.txt"
	dbipCityDump   = "https://download.db-ip.com/free/dbip-city-lite-%s.mmdb.gz"
)

var ribFilenameRE = regexp.MustCompile(`rib\.[0-9]{8}\.[0-9]{4}\.bz2`)

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

// UpdateDatabase downloads an MRT RIB dump, converts it to binary and replaces cfg.DBPath.
func UpdateDatabase(cfg Config, ribURL string) error {
	if ribURL == "" {
		var err error
		ribURL, err = latestRIBURL()
		if err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "asname: downloading RIB %s\n", ribURL)

	resp, err := httpGet(ribURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	builder := database.NewBuilder()
	if err := builder.ImportMRT(bzip2.NewReader(resp.Body)); err != nil {
		return fmt.Errorf("importing MRT: %v", err)
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
	return nil
}

// UpdateNames downloads the RIPE asn.txt list and writes it to cfg.NamesPath.
func UpdateNames(cfg Config) error {
	fmt.Fprintf(os.Stderr, "asname: downloading names %s\n", ripeASNames)
	resp, err := httpGet(ripeASNames)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	tmp, err := os.CreateTemp(filepath.Dir(cfg.NamesPath), ".asn_db.*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	count, err := WriteNamesFromRIPE(resp.Body, tmp)
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
	now := time.Now().UTC()
	var lastErr error
	for _, month := range []time.Time{now, now.AddDate(0, -1, 0)} {
		url := fmt.Sprintf(dbipCityDump, month.Format("2006-01"))
		resp, err := httpGet(url)
		if err != nil {
			lastErr = err
			continue
		}
		fmt.Fprintf(os.Stderr, "asname: downloading city database %s\n", url)

		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			resp.Body.Close()
			return fmt.Errorf("decompressing %s: %v", url, err)
		}
		n, err := StreamFileAtomic(cfg.CityPath, gz)
		gz.Close()
		resp.Body.Close()
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "asname: wrote %s (%d bytes)\n", cfg.CityPath, n)
		return nil
	}
	return fmt.Errorf("no city database found on db-ip.com: %v", lastErr)
}

func latestRIBURL() (string, error) {
	now := time.Now().UTC()
	for _, month := range []time.Time{now, now.AddDate(0, -1, 0)} {
		dir := fmt.Sprintf("%s/%s/RIBS/", routeViewsBase, month.Format("2006.01"))
		resp, err := httpGet(dir)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		matches := ribFilenameRE.FindAllString(string(body), -1)
		if len(matches) == 0 {
			continue
		}
		return dir + matches[len(matches)-1], nil
	}
	return "", fmt.Errorf("no RIB dump found on routeviews")
}
