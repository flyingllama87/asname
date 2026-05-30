// Command asname resolves an IP address to its Autonomous System number, the
// AS owner's name and the geographic country, mirroring the `asname` zsh
// helper but as a single self-contained, offline Go binary.
//
// It is fully self-contained (aside from its data files and no cgo): an
// LC-trie database for the IP->ASN mapping, a RIPE asn.txt derived file for the
// ASN->name mapping and a second LC-trie built from the RIRs' delegation
// statistics for the IP->country mapping. All of the data files can be
// refreshed with `asname update`, and lookups auto-refresh stale data unless
// disabled.
package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/urfave/cli/v2"

		"asname/pkg/database"
)

const (
	dirEnvVar      = "ASNAME_DIR"
	dbEnvVar       = "ASNAME_DB"
	namesEnvVar    = "ASNAME_NAMES"
	defaultMaxAge  = 30 * 24 * time.Hour
	dbFilename     = "asname.db"
	namesFilename  = "asn_db.txt"
	defaultDirName = ".asname"
)

func main() {
	app := &cli.App{
		Name:      "asname",
		Usage:     "look up the ASN, AS name and country of an IP address",
		ArgsUsage: "<IP>",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "dir",
				Aliases: []string{"d"},
				EnvVars: []string{dirEnvVar},
				Value:   defaultDir(),
				Usage:   "data `directory` holding the ASN database and name file",
			},
			&cli.StringFlag{
				Name:    "db",
				EnvVars: []string{dbEnvVar},
				Usage:   "asnlookup database `file` (default: <dir>/" + dbFilename + ")",
			},
			&cli.StringFlag{
				Name:    "names",
				EnvVars: []string{namesEnvVar},
				Usage:   "ASN->name mapping `file` (default: <dir>/" + namesFilename + ")",
			},
			&cli.StringFlag{
				Name:    "country",
				EnvVars: []string{countryEnvVar},
				Usage:   "IP->country database `file` (default: <dir>/" + countryFilename + ")",
			},
			&cli.DurationFlag{
				Name:  "max-age",
				Value: defaultMaxAge,
				Usage: "auto-refresh data older than this `duration` (0 disables)",
			},
			&cli.BoolFlag{
				Name:  "no-update",
				Usage: "never auto-refresh data before a lookup",
			},
		},
		Commands: []*cli.Command{
			updateCommand,
			versionCommand,
		},
		Action: lookupAction,
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "asname:", err)
		os.Exit(1)
	}
}

// config bundles the resolved file locations for a run.
type config struct {
	dbPath      string
	namesPath   string
	countryPath string
}

func newConfig(ctx *cli.Context) config {
	dir := ctx.String("dir")
	c := config{
		dbPath:      ctx.String("db"),
		namesPath:   ctx.String("names"),
		countryPath: ctx.String("country"),
	}
	if c.dbPath == "" {
		c.dbPath = filepath.Join(dir, dbFilename)
	}
	if c.namesPath == "" {
		c.namesPath = filepath.Join(dir, namesFilename)
	}
	if c.countryPath == "" {
		c.countryPath = filepath.Join(dir, countryFilename)
	}
	return c
}

func defaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return defaultDirName
	}
	return filepath.Join(home, defaultDirName)
}

func lookupAction(ctx *cli.Context) error {
	if ctx.NArg() != 1 {
		cli.ShowAppHelp(ctx)
		return fmt.Errorf("exactly one IP argument is required")
	}

	ip := net.ParseIP(ctx.Args().First())
	if ip == nil {
		return fmt.Errorf("invalid IP address: %q", ctx.Args().First())
	}

	cfg := newConfig(ctx)

	// Auto-refresh stale or missing data unless the user opted out.
	if !ctx.Bool("no-update") {
		if err := autoUpdate(cfg, ctx.Duration("max-age")); err != nil {
			fmt.Fprintln(os.Stderr, "asname: auto-update failed:", err)
		}
	}

	dbFile, err := os.Open(cfg.dbPath)
	if err != nil {
		return fmt.Errorf("opening ASN database (run `asname update`): %v", err)
	}
	defer dbFile.Close()
	db, err := database.NewFromDump(dbFile)
	if err != nil {
		return fmt.Errorf("parsing ASN database: %v", err)
	}

	names, err := loadNames(cfg.namesPath)
	if err != nil {
		return fmt.Errorf("loading name database (run `asname update`): %v", err)
	}

	asn := ""
	name := "Unknown"
	as, err := db.Lookup(ip)
	switch err {
	case nil:
		asn = fmt.Sprintf("AS%d", as.Number)
		if n, ok := names[as.Number]; ok {
			name = n
		}
	case database.ErrNotFound:
		asn = "N/A"
	default:
		return fmt.Errorf("lookup failed: %v", err)
	}

	country := "Unknown"
	if cdb, err := loadCountryDB(cfg.countryPath); err != nil {
		fmt.Fprintln(os.Stderr, "asname: country database unavailable (run `asname update`):", err)
	} else if c := lookupCountry(cdb, ip); c != "" {
		country = c
	}

	fmt.Printf("IP: %s → ASN: %s → Name: %s → Country: %s\n",
		ip, asn, name, country)
	return nil
}

var versionCommand = &cli.Command{
	Name:  "version",
	Usage: "print version information and exit",
	Action: func(_ *cli.Context) error {
		fmt.Printf("asname v%s\n", "0.1.1")
		return nil
	},
}
