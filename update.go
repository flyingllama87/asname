package main

import (
	"compress/bzip2"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/urfave/cli/v2"

	"asname/pkg/database"
)

const (
	// routeViewsBase hosts the MRT RIB dumps used for the IP->ASN mapping.
	routeViewsBase = "http://archive.routeviews.org/bgpdata"
	// ripeASNames is the canonical ASN->name list maintained by RIPE.
	ripeASNames = "https://ftp.ripe.net/ripe/asnames/asn.txt"

	// optimizationFillFactor mirrors asnlookup-utils' default optimization
	// level 5 (see optimizationLevelToFillFactor).
	optimizationFillFactor = float32(9-5) * 0.125
)

var ribFilenameRE = regexp.MustCompile(`rib\.[0-9]{8}\.[0-9]{4}\.bz2`)

var updateCommand = &cli.Command{
	Name:  "update",
	Usage: "download fresh ASN, name and country databases",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "db-only",
			Usage: "only refresh the IP->ASN database",
		},
		&cli.BoolFlag{
			Name:  "names-only",
			Usage: "only refresh the ASN->name database",
		},
		&cli.BoolFlag{
			Name:  "country-only",
			Usage: "only refresh the IP->country database",
		},
		&cli.StringFlag{
			Name:  "rib-url",
			Usage: "download the RIB MRT dump from this `URL` instead of routeviews",
		},
	},
	Action: updateAction,
}

func updateAction(ctx *cli.Context) error {
	cfg := newConfig(ctx)
	for _, dir := range []string{cfg.dbPath, cfg.namesPath, cfg.countryPath} {
		if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
			return err
		}
	}

	// With no "*-only" flag every database is refreshed; otherwise only the
	// selected ones are (and "*-only" flags may be combined).
	dbOnly := ctx.Bool("db-only")
	namesOnly := ctx.Bool("names-only")
	countryOnly := ctx.Bool("country-only")
	all := !dbOnly && !namesOnly && !countryOnly

	if all || dbOnly {
		if err := updateDatabase(cfg, ctx.String("rib-url")); err != nil {
			return fmt.Errorf("updating ASN database: %v", err)
		}
	}
	if all || namesOnly {
		if err := updateNames(cfg); err != nil {
			return fmt.Errorf("updating name database: %v", err)
		}
	}
	if all || countryOnly {
		if err := updateCountryDB(cfg); err != nil {
			return fmt.Errorf("updating country database: %v", err)
		}
	}
	return nil
}

// autoUpdate refreshes any data file that is missing or older than maxAge.
// A maxAge of 0 only fills in missing files.
func autoUpdate(cfg config, maxAge time.Duration) error {
	if stale(cfg.dbPath, maxAge) {
		fmt.Fprintln(os.Stderr, "asname: refreshing ASN database...")
		if err := os.MkdirAll(filepath.Dir(cfg.dbPath), 0o755); err != nil {
			return err
		}
		if err := updateDatabase(cfg, ""); err != nil {
			return err
		}
	}
	if stale(cfg.namesPath, maxAge) {
		fmt.Fprintln(os.Stderr, "asname: refreshing name database...")
		if err := os.MkdirAll(filepath.Dir(cfg.namesPath), 0o755); err != nil {
			return err
		}
		if err := updateNames(cfg); err != nil {
			return err
		}
	}
	if stale(cfg.countryPath, maxAge) {
		fmt.Fprintln(os.Stderr, "asname: refreshing country database...")
		if err := os.MkdirAll(filepath.Dir(cfg.countryPath), 0o755); err != nil {
			return err
		}
		if err := updateCountryDB(cfg); err != nil {
			return err
		}
	}
	return nil
}

// stale reports whether path is missing, or (when maxAge > 0) older than maxAge.
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

// updateDatabase downloads an MRT RIB dump, converts it to asnlookup's binary
// format and atomically replaces cfg.dbPath.
func updateDatabase(cfg config, ribURL string) error {
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
	builder.SetFillFactor(optimizationFillFactor)
	db, err := builder.Build()
	if err != nil {
		return fmt.Errorf("building database: %v", err)
	}
	data, err := db.MarshalBinary()
	if err != nil {
		return err
	}
	if err := writeFileAtomic(cfg.dbPath, data); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "asname: wrote %s (%d bytes)\n", cfg.dbPath, len(data))
	return nil
}

// updateNames downloads the RIPE asn.txt list and writes it to cfg.namesPath
// in the legacy "AS<number> <name>" layout.
func updateNames(cfg config) error {
	fmt.Fprintf(os.Stderr, "asname: downloading names %s\n", ripeASNames)
	resp, err := httpGet(ripeASNames)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	tmp, err := os.CreateTemp(filepath.Dir(cfg.namesPath), ".asn_db.*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	count, err := writeNamesFromRIPE(resp.Body, tmp)
	if err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, cfg.namesPath); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "asname: wrote %s (%d AS names)\n", cfg.namesPath, count)
	return nil
}

// latestRIBURL discovers the most recent RIB dump on routeviews, falling back
// to the previous month near month boundaries.
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

func httpGet(url string) (*http.Response, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return resp, nil
}

// writeFileAtomic writes data to a temp file in the destination directory and
// renames it into place, so readers never observe a half-written database.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
