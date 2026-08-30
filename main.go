// Command asname resolves an IP address, hostname or URL to its Autonomous
// System number, the AS owner's name and the geographic country. The argument
// can also be a file holding a list of entries to look up.
//
// Lookups are answered offline, from three data files: an LC-trie database for
// the IP->ASN mapping, a RIPE asn.txt derived file for the ASN->name mapping
// and a second LC-trie built from the RIRs' delegation statistics for the
// IP->country mapping. All of them can be refreshed with `asname update`, and
// lookups auto-refresh stale data unless disabled.
//
// City lookups are optional and add a fourth, much larger file, so they are
// only enabled once the user asks with --city. See city.go. Registry netblock
// lookups are optional for the same reason and add a fifth; see netblock.go.
//
// The one exception to answering offline is the whois fallback, for the
// addresses no offline netblock database can cover. It is asked about before
// any query is made; see whois.go.
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/urfave/cli/v2"

	"github.com/flyingllama87/asname/pkg/database"
)

const (
	dirEnvVar      = "ASNAME_DIR"
	dbEnvVar       = "ASNAME_DB"
	namesEnvVar    = "ASNAME_NAMES"
	defaultMaxAge  = 30 * 24 * time.Hour
	dbFilename     = "asname.db"
	namesFilename  = "asn_db.txt"
	defaultDirName = ".asname"
	rdnsTimeout    = 5 * time.Second
	dnsTimeout     = 5 * time.Second

	uniformHostWidth     = 40
	uniformIPWidth       = 39
	uniformASNWidth      = 12
	uniformNameWidth     = 60
	uniformCountryWidth  = 24
	uniformCityWidth     = 34
	uniformNetblockWidth = 48
	uniformCategoryWidth = 30
)

func main() {
	app := &cli.App{
		Name:      "asname",
		Usage:     "look up the ASN, AS name and country of an IP address, hostname or URL",
		ArgsUsage: "<IP|hostname|URL|file>",
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
			&cli.StringFlag{
				Name:    "city-db",
				EnvVars: []string{cityEnvVar},
				Usage:   "IP->city database `file` (default: <dir>/" + cityFilename + ")",
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
			&cli.BoolFlag{
				Name:    "reverse-dns",
				Aliases: []string{"r"},
				Usage:   "also query reverse DNS and include PTR names in the output",
			},
			&cli.BoolFlag{
				Name:    "uniform",
				Aliases: []string{"u"},
				Usage:   "print lookup output as aligned fields",
			},
			&cli.BoolFlag{
				Name:    "pretty",
				Aliases: []string{"p"},
				Usage:   "display output in a multi-line formatted card layout with generous whitespace",
			},
			&cli.BoolFlag{
				Name:  "color",
				Usage: "force ANSI colored output even when stdout is piped",
			},
			&cli.BoolFlag{
				Name:  "no-color",
				Usage: "suppress ANSI colored output (also respects NO_COLOR env var)",
			},
			&cli.BoolFlag{
				Name:    "json",
				Aliases: []string{"j"},
				Usage:   "output lookup results as JSON lines (JSONL)",
			},
			&cli.BoolFlag{
				Name:    "stream",
				Aliases: []string{"s"},
				Usage:   "stream and resolve targets line-by-line from stdin in real-time",
			},
			&cli.BoolFlag{
				Name:  "rest",
				Usage: "run in foreground as an HTTP REST API server",
			},
			&cli.StringFlag{
				Name:    "listen",
				Aliases: []string{"l"},
				EnvVars: []string{"ASNAME_LISTEN"},
				Value:   "127.0.0.1:8086",
				Usage:   "network address and port to bind for the REST API server",
			},
			&cli.BoolFlag{
				Name:  "cors",
				Usage: "enable permissive CORS headers on the REST API server",
			},
			&cli.BoolFlag{
				Name:    "city",
				Aliases: []string{"c"},
				Usage:   "include the city, downloading the city database (~125MB) if absent; once present it is used without this flag",
			},
			&cli.BoolFlag{
				Name:  "no-city",
				Usage: "omit the city even when the city database is present",
			},
			&cli.StringFlag{
				Name:    "netblock-db",
				EnvVars: []string{netblockEnvVar},
				Usage:   "IP->netblock database `file` (default: <dir>/" + netblockFilename + ")",
			},
			&cli.BoolFlag{
				Name:    "netblock",
				Aliases: []string{"n"},
				Usage:   "include the registry netblock and its owner, building the database (~300MB of downloads) if absent; once present it is used without this flag",
			},
			&cli.BoolFlag{
				Name:  "no-netblock",
				Usage: "omit the netblock even when the netblock database is present",
			},
			&cli.BoolFlag{
				Name:  "whois",
				Usage: "look up addresses the offline netblock database cannot name (ARIN and LACNIC) over whois, without asking",
			},
			&cli.BoolFlag{
				Name:  "no-whois",
				Usage: "never query whois, and do not ask",
			},
			&cli.StringFlag{
				Name:    "category-db",
				EnvVars: []string{categoryEnvVar},
				Usage:   "IP->category database `file` (default: <dir>/" + categoryFilename + ")",
			},
			&cli.BoolFlag{
				Name:    "category",
				Aliases: []string{"C"},
				Usage:   "include what kind of network it is (cloud, CDN, hosting, ISP...), building the database if absent; once present it is used without this flag",
			},
			&cli.BoolFlag{
				Name:  "no-category",
				Usage: "omit the category even when the category database is present",
			},
			&cli.StringFlag{
				Name:    "contact-email",
				EnvVars: []string{contactEnvVar},
				Usage:   "`address` to identify with when fetching bgp.tools' operator tags",
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
	dbPath       string
	namesPath    string
	countryPath  string
	cityPath     string
	netblockPath string
	categoryPath string
	consentPath  string
	contactPath  string
}

func newConfig(ctx *cli.Context) config {
	dir := ctx.String("dir")
	c := config{
		dbPath:       ctx.String("db"),
		namesPath:    ctx.String("names"),
		countryPath:  ctx.String("country"),
		cityPath:     ctx.String("city-db"),
		netblockPath: ctx.String("netblock-db"),
		categoryPath: ctx.String("category-db"),
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
	if c.cityPath == "" {
		c.cityPath = filepath.Join(dir, cityFilename)
	}
	if c.netblockPath == "" {
		c.netblockPath = filepath.Join(dir, netblockFilename)
	}
	if c.categoryPath == "" {
		c.categoryPath = filepath.Join(dir, categoryFilename)
	}
	c.consentPath = filepath.Join(dir, whoisConsentFilename)
	c.contactPath = filepath.Join(dir, contactFilename)
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
	outputFlags := 0
	if ctx.Bool("pretty") {
		outputFlags++
	}
	if ctx.Bool("json") {
		outputFlags++
	}
	if ctx.Bool("uniform") {
		outputFlags++
	}
	if outputFlags > 1 {
		return fmt.Errorf("--pretty, --json and --uniform are mutually exclusive")
	}

	if ctx.Bool("rest") && ctx.Bool("stream") {
		return fmt.Errorf("--rest and --stream are mutually exclusive")
	}

	isStream := ctx.Bool("stream") || (ctx.NArg() == 1 && ctx.Args().First() == "-")
	isREST := ctx.Bool("rest")

	if !isStream && !isREST && ctx.NArg() != 1 {
		cli.ShowAppHelp(ctx)
		return fmt.Errorf("exactly one IP address, hostname, URL or file argument is required")
	}

	cfg := newConfig(ctx)

	// --city opts in once, by fetching the database; from then on its presence
	// on disk is enough to keep the city in the output.
	wantCity := !ctx.Bool("no-city") && (ctx.Bool("city") || cityDBPresent(cfg.cityPath))
	wantNetblock := !ctx.Bool("no-netblock") && (ctx.Bool("netblock") || netblockDBPresent(cfg.netblockPath))

	// The whois fallback fills the holes the offline database has, so --whois
	// on its own is enough to report netblocks without building it at all.
	whois := whoisAsk
	switch {
	case ctx.Bool("no-whois") || ctx.Bool("no-netblock"):
		whois = whoisNever
	case ctx.Bool("whois"):
		whois = whoisAlways
	}
	showNetblock := wantNetblock || whois == whoisAlways
	wantCategory := !ctx.Bool("no-category") && (ctx.Bool("category") || categoryDBPresent(cfg.categoryPath))

	// Auto-refresh stale or missing data unless the user opted out.
	if !ctx.Bool("no-update") {
		contact := newContactAsker(cfg.contactPath, ctx.String("contact-email"))
		if err := autoUpdate(cfg, ctx.Duration("max-age"), wantCity, wantNetblock, wantCategory, contact); err != nil {
			fmt.Fprintln(os.Stderr, "asname: auto-update failed:", err)
		}
	}

	eng, err := newEngine(cfg, wantCity, wantNetblock, showNetblock, wantCategory, whois)
	if err != nil {
		return err
	}
	defer eng.close()

	if isREST {
		server := newRESTServer(eng, ctx.String("listen"), ctx.Bool("cors"), ctx.Bool("reverse-dns"))
		return server.start(context.Background())
	}

	if isStream {
		format := formatDefault
		switch {
		case ctx.Bool("json"):
			format = formatJSON
		case ctx.Bool("pretty"):
			format = formatPretty
		case ctx.Bool("uniform"):
			format = formatUniform
		}

		useColor := shouldColorize(os.Stdout, ctx.Bool("color"), ctx.Bool("no-color"))
		opts := streamOptions{
			format:     format,
			reverseDNS: ctx.Bool("reverse-dns"),
			useColor:   useColor,
		}

		var r io.Reader = os.Stdin
		if ctx.NArg() == 1 && ctx.Args().First() != "-" {
			f, err := os.Open(ctx.Args().First())
			if err != nil {
				return err
			}
			defer f.Close()
			r = f
		}

		return runStream(context.Background(), r, os.Stdout, eng, opts)
	}

	targets, err := parseTargets(ctx.Args().First())
	if err != nil {
		return err
	}

	resolveTargets(context.Background(), targets)

	// A hostname can expand to several addresses, so one entry can produce
	// several output lines. A failing entry only aborts the run when it is the
	// only one; in a batch the rest of the file is still worth printing.
	results := make([]lookupResult, 0, len(targets))
	showHost := false
	failures := 0
	for _, t := range targets {
		found, err := eng.lookupTarget(t)
		if err != nil {
			if len(targets) == 1 {
				return err
			}
			fmt.Fprintf(os.Stderr, "asname: %s: %v\n", t.raw, err)
			failures++
			continue
		}
		if t.host != "" {
			showHost = true
		}
		results = append(results, found...)
	}

	if ctx.Bool("reverse-dns") {
		resolveReverseDNS(context.Background(), results)
	}

	out := bufio.NewWriter(os.Stdout)
	uniform := ctx.Bool("uniform")
	isJSON := ctx.Bool("json")
	isPretty := ctx.Bool("pretty")
	useColor := shouldColorize(os.Stdout, ctx.Bool("color"), ctx.Bool("no-color"))

	for i, res := range results {
		if isJSON {
			line, err := formatJSONLookupOutput(res)
			if err != nil {
				return err
			}
			fmt.Fprint(out, line)
		} else if isPretty {
			fmt.Fprint(out, formatPrettyLookupOutput(res, i, len(results), useColor))
		} else {
			fmt.Fprint(out, formatLookupOutput(res, uniform, showHost))
		}
	}
	if err := out.Flush(); err != nil {
		return err
	}

	if failures > 0 {
		return fmt.Errorf("%d of %d entries could not be looked up", failures, len(targets))
	}
	return nil
}

// engine holds the databases for the run so that a batch of lookups parses
// them once.
type engine struct {
	db         database.Database
	names      map[uint32]string
	countryDB  database.Database
	cityDB     *maxminddb.Reader
	netblockDB *netblockDB
	// showNetblock is separate from netblockDB being open, since --whois can
	// report netblocks with no offline database at all.
	showNetblock bool
	whois        *whoisAsker
	categoryDB   *categoryDB
}

func newEngine(cfg config, wantCity, wantNetblock, showNetblock, wantCategory bool, whois whoisMode) (*engine, error) {
	dbFile, err := os.Open(cfg.dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening ASN database (run `asname update`): %v", err)
	}
	defer dbFile.Close()
	db, err := database.NewFromDump(dbFile)
	if err != nil {
		return nil, fmt.Errorf("parsing ASN database: %v", err)
	}

	names, err := loadNames(cfg.namesPath)
	if err != nil {
		return nil, fmt.Errorf("loading name database (run `asname update`): %v", err)
	}

	// A missing country database degrades the output rather than failing it.
	countryDB, err := loadCountryDB(cfg.countryPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "asname: country database unavailable (run `asname update`):", err)
		countryDB = nil
	}

	var cityDB *maxminddb.Reader
	if wantCity {
		if cityDB, err = loadCityDB(cfg.cityPath); err != nil {
			fmt.Fprintln(os.Stderr, "asname: city database unavailable (run `asname update --city-only`):", err)
			cityDB = nil
		}
	}

	var nbDB *netblockDB
	if wantNetblock {
		if nbDB, err = openNetblockDB(cfg.netblockPath); err != nil {
			fmt.Fprintln(os.Stderr, "asname: netblock database unavailable (run `asname update --netblock-only`):", err)
			nbDB = nil
		}
	}

	var catDB *categoryDB
	if wantCategory {
		if catDB, err = openCategoryDB(cfg.categoryPath); err != nil {
			fmt.Fprintln(os.Stderr, "asname: category database unavailable (run `asname update --category-only`):", err)
			catDB = nil
		}
	}

	return &engine{
		db: db, names: names, countryDB: countryDB, cityDB: cityDB, netblockDB: nbDB,
		showNetblock: showNetblock,
		whois:        newWhoisAsker(cfg.consentPath, whois),
		categoryDB:   catDB,
	}, nil
}

// close releases the city and netblock databases, which unlike the tries are
// read from disk rather than parsed up front.
func (e *engine) close() {
	if e.cityDB != nil {
		e.cityDB.Close()
	}
	e.netblockDB.Close()
}

func (e *engine) lookupTarget(t target) ([]lookupResult, error) {
	if t.err != nil {
		return nil, t.err
	}
	results := make([]lookupResult, 0, len(t.ips))
	for _, ip := range t.ips {
		res, err := e.lookup(ip)
		if err != nil {
			return nil, err
		}
		res.target = t.raw
		res.host = t.host
		results = append(results, res)
	}
	return results, nil
}

func (e *engine) lookup(ip net.IP) (lookupResult, error) {
	res := lookupResult{ip: ip, name: "Unknown", country: "Unknown"}

	// The tries index the raw bytes of the address, and are built from the
	// 16-byte form that net.ParseIP returns. The resolver hands back 4-byte
	// slices for IPv4, which would otherwise walk the IPv6 side of the trie
	// and never match.
	ip = ip.To16()
	if ip == nil {
		return lookupResult{}, fmt.Errorf("invalid IP address: %v", res.ip)
	}

	var asn uint32
	haveASN := false
	as, err := e.db.Lookup(ip)
	switch err {
	case nil:
		asn, haveASN = as.Number, true
		res.asn = fmt.Sprintf("AS%d", as.Number)
		if n, ok := e.names[as.Number]; ok {
			res.name = n
		}
	case database.ErrNotFound:
		res.asn = "N/A"
	default:
		return lookupResult{}, fmt.Errorf("lookup failed: %v", err)
	}

	if e.countryDB != nil {
		if c := lookupCountry(e.countryDB, ip); c != "" {
			res.country = c
		}
	}

	if e.cityDB != nil {
		res.city = "Unknown"
		if c := lookupCity(e.cityDB, ip); c != "" {
			res.city = c
		}
	}

	if e.showNetblock {
		res.netblock = "Unknown"
		var nb netblockInfo
		if e.netblockDB != nil {
			var err error
			if nb, err = e.netblockDB.Lookup(ip); err != nil {
				return lookupResult{}, fmt.Errorf("netblock lookup failed: %v", err)
			}
		}
		// Only an address some registry has actually delegated is worth asking
		// a registry about, which keeps the question off reserved and
		// unallocated space.
		if nb.empty() && res.country != "Unknown" && e.whois.allowed(res.ip) {
			online, err := lookupWhoisNetblock(res.ip)
			if err != nil {
				fmt.Fprintf(os.Stderr, "asname: whois lookup for %s failed: %v\n", res.ip, err)
			} else if !online.empty() {
				nb = online
				res.netblockLive = true
			}
		}
		if !nb.empty() {
			res.netblock = nb.String()
		}
	}

	if e.categoryDB != nil {
		res.category = "Unknown"
		if c := e.categoryDB.Lookup(ip, asn, haveASN); c != "" {
			res.category = c
		}
	}

	return res, nil
}

// lookupResult is everything known about a single address.
type lookupResult struct {
	target   string // the original target input (e.g. "https://...", "8.8.8.8")
	host     string // the hostname it came from, empty for a literal IP
	ip       net.IP
	asn      string
	name     string
	country  string
	city     string // empty when the city database is not in use
	netblock string // empty when netblocks are not being reported
	// netblockLive marks a netblock that came from a live whois query rather
	// than the offline database, since that answer is not reproducible offline.
	netblockLive bool
	category     string // empty when the category database is not in use
	rdns         string
}

// resolveReverseDNS annotates every result with its PTR names, in parallel
// since a batch would otherwise pay the query latency once per address.
func resolveReverseDNS(ctx context.Context, results []lookupResult) {
	sem := make(chan struct{}, maxResolveWorkers)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(res *lookupResult) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			rdnsCtx, cancel := context.WithTimeout(ctx, rdnsTimeout)
			defer cancel()

			res.rdns = "N/A"
			if names, err := lookupReverseDNS(rdnsCtx, res.ip); err == nil && names != "" {
				res.rdns = names
			}
		}(&results[i])
	}
	wg.Wait()
}

func lookupReverseDNS(ctx context.Context, ip net.IP) (string, error) {
	names, err := net.DefaultResolver.LookupAddr(ctx, ip.String())
	if err != nil {
		return "", err
	}
	if len(names) == 0 {
		return "", nil
	}

	return formatReverseDNSNames(names), nil
}

func formatReverseDNSNames(names []string) string {
	normalized := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSuffix(name, ".")
		if name != "" {
			normalized = append(normalized, name)
		}
	}
	sort.Strings(normalized)

	return strings.Join(normalized, ", ")
}

// version is stamped in at build time by the Makefile via
// -ldflags "-X main.version=...". The default marks a build made without it.
var version = "dev"

var versionCommand = &cli.Command{
	Name:  "version",
	Usage: "print version information and exit",
	Action: func(_ *cli.Context) error {
		fmt.Printf("asname v%s\n", version)
		return nil
	},
}
