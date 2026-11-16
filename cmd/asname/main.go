package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/flyingllama87/asname/internal/engine"
	"github.com/flyingllama87/asname/internal/format"
	"github.com/flyingllama87/asname/internal/rest"
	"github.com/flyingllama87/asname/internal/sources"
	"github.com/flyingllama87/asname/internal/stream"
)

var version = "dev"

func main() {
	sources.Version = version
	loadEnvFile(envFilePath(), os.Stderr)

	cli.RootCommandHelpTemplate = `NAME:
   {{.Name}}{{if .Usage}} - {{.Usage}}{{end}}

USAGE:
   {{if .UsageText}}{{.UsageText}}{{else}}{{.FullName}} {{if .VisibleFlags}}[options]{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments...]{{end}}{{end}}{{if .VisibleCommands}}

COMMANDS:{{range .VisibleCategories}}{{if .Name}}
   {{.Name}}:{{range .VisibleCommands}}
     {{join .Names ", "}}{{"\t"}}{{.Usage}}{{end}}{{else}}{{range .VisibleCommands}}
   {{join .Names ", "}}{{"\t"}}{{.Usage}}{{end}}{{end}}{{end}}{{end}}{{if .VisibleFlags}}

OUTPUT FORMATTING:
   --pretty, -p                   display output in a multi-line formatted card layout with generous whitespace
   --json, -j                     output lookup results as JSON lines (JSONL)
   --csv                          output results as CSV, with a header row
   --uniform, -u                  print lookup output as aligned fields
   --color                        force ANSI colored output even when stdout is piped
   --no-color                     suppress ANSI colored output (also respects NO_COLOR env var)

EXECUTION MODES:
   --stream, -s                   stream and resolve targets line-by-line from stdin in real-time
   --rest                         run in foreground as an HTTP REST API server
   --listen value, -l value       network address and port to bind for the REST API server (default: "127.0.0.1:8086") [$ASNAME_LISTEN]
   --cors                         enable permissive CORS headers on the REST API server
   --web-dir directory            serve the web UI from this directory (built with ` + "`make web`" + `) at / on the REST API server [$ASNAME_WEB_DIR]
   --allow-updates                let the REST API server update its databases (POST /v1/update, used by the web UI), and refresh stale ones while it runs [$ASNAME_ALLOW_UPDATES]

OPTIONAL LOOKUPS & METADATA:
   --reverse-dns, -r              also query reverse DNS and include PTR names in the output
   --city, -c                     include the city, downloading the city database (~125MB) if absent; once present it is used without this flag
   --no-city                      omit the city even when the city database is present
   --netblock, -n                 include the registry netblock and its owner, building the database (~350MB of downloads) if absent; once present it is used without this flag
   --no-netblock                  omit the netblock even when the netblock database is present
   --whois                        look up addresses the offline netblock database cannot name (ARIN and LACNIC) online, over RDAP or else whois, without asking [$ASNAME_WHOIS]
   --no-whois                     never query RDAP or whois, and do not ask
   --online-prefixes              ask RIPEstat for the prefixes of an ASN the offline prefix database lacks, without asking [$ASNAME_ONLINE_PREFIXES]
   --no-online-prefixes           never ask RIPEstat for prefixes, and do not ask
   --category, -C                 include what kind of network it is (cloud, CDN, hosting, ISP...), building the database if absent; once present it is used without this flag
   --no-category                  omit the category even when the category database is present
   --reputation, -R               include which public blocklists (Spamhaus DROP and ASN-DROP, IPsum, FireHOL) name the address and its ASN, building the database if absent; once present it is used without this flag, including by search
   --no-reputation                omit reputation even when the reputation database is present

SEARCH:
   --org query, -O query          search AS names and registry netblocks by organization name or netname
   --limit value                  maximum number of ASNs, and of netblocks, to display (default: unlimited)
   --asns-only                    only search AS names
   --netblocks-only               only search registry netblocks
   --fuzzy                        also find names that match ignoring spaces and punctuation, or word by word in any order; best matches first
   --ips-only                     only print matching CIDRs, one per line
   --in country                   only ASNs registered in country (AU, or Australia) and netblocks placed there
   --v6                           also include IPv6 (search is IPv4 only unless this or --v6-only)

ADDRESS FAMILY (lookups, country and city; search is IPv4 unless --v6 or --v6-only):
   --v4-only                      only show IPv4 addresses, prefixes and blocks
   --v6-only                      only show IPv6 addresses, prefixes and blocks

DATA FILES & AUTO-UPDATE:
   --dir directory, -d directory  data directory holding the databases (default: "/home/mj12/.asname") [$ASNAME_DIR]
   --db file                      asnlookup database file (default: <dir>/asname.db) [$ASNAME_DB]
   --names file                   ASN->name mapping file (default: <dir>/asn_db.txt) [$ASNAME_NAMES]
   --country file, --country-db file  IP->country database file (default: <dir>/country.db) [$ASNAME_COUNTRY]
   --city-db file                 IP->city database file (default: <dir>/city.mmdb) [$ASNAME_CITY]
   --netblock-db file             IP->netblock database file (default: <dir>/netblock.db) [$ASNAME_NETBLOCK]
   --category-db file             IP->category database file (default: <dir>/category.db) [$ASNAME_CATEGORY]
   --reputation-db file           IP->reputation database file (default: <dir>/reputation.db) [$ASNAME_REPUTATION]
   --prefix-db file               ASN->prefix database file (default: <dir>/prefixes.db) [$ASNAME_PREFIXES]
   --max-age duration             auto-refresh data older than this duration (0 disables); without it, the age saved in the web UI, or 30 days (default: 720h0m0s) [$ASNAME_MAX_AGE]
   --no-update                    never auto-refresh data before a lookup
   --contact-email address        address to identify with when fetching bgp.tools' operator tags [$ASNAME_CONTACT_EMAIL]
   --help, -h                     show help{{end}}
`

	if err := newApp().Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "asname:", err)
		os.Exit(1)
	}
}

// newApp builds the command line app. Actions write results to the root
// command's Writer and warnings to its ErrWriter, which default to stdout and
// stderr. Flags are persistent unless marked Local, so the ones every command
// shares, such as --v4-only and --dir, work before or after a subcommand and
// its arguments.
func newApp() *cli.Command {
	return &cli.Command{
		Name:            "asname",
		HideHelpCommand: true,
		Usage:           "look up the ASN, AS name, country and prefixes of an IP address, hostname, URL or ASN; or search AS names and netblocks by organization",
		ArgsUsage:       "<IP|hostname|URL|ASN|file>",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "pretty",
				Aliases: []string{"p"},
				Usage:   "display lookup and search results as multi-line cards (the default); for country and city, a card with block counts",
			},
			&cli.BoolFlag{
				Name:    "oneline",
				Aliases: []string{"o"},
				Usage:   "print each lookup or search result on one line instead of as a card",
			},
			&cli.BoolFlag{
				Name:    "json",
				Aliases: []string{"j"},
				Usage:   "output lookup results as JSON lines (JSONL)",
			},
			&cli.BoolFlag{
				Name:  "csv",
				Usage: "output results as CSV, with a header row",
			},
			&cli.BoolFlag{
				Name:    "uniform",
				Aliases: []string{"u"},
				Usage:   "print lookup output as aligned fields",
				Local:   true,
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
				Name:    "stream",
				Aliases: []string{"s"},
				Usage:   "stream and resolve targets line-by-line from stdin in real-time",
				Local:   true,
			},
			&cli.BoolFlag{
				Name:  "rest",
				Usage: "run in foreground as an HTTP REST API server",
				Local: true,
			},
			&cli.StringFlag{
				Name:    "listen",
				Aliases: []string{"l"},
				Sources: cli.EnvVars("ASNAME_LISTEN"),
				Value:   "127.0.0.1:8086",
				Usage:   "network address and port to bind for the REST API server",
				Local:   true,
			},
			&cli.BoolFlag{
				Name:  "cors",
				Usage: "enable permissive CORS headers on the REST API server",
				Local: true,
			},
			&cli.StringFlag{
				Name:    "web-dir",
				Sources: cli.EnvVars("ASNAME_WEB_DIR"),
				Usage:   "serve the web UI from this `directory` (built with `make web`) at / on the REST API server",
				Local:   true,
			},
			&cli.BoolFlag{
				Name:    "allow-updates",
				Sources: cli.EnvVars("ASNAME_ALLOW_UPDATES"),
				Usage:   "let the REST API server update its databases (POST /v1/update, used by the web UI), and refresh stale ones while it runs",
				Local:   true,
			},
			&cli.BoolFlag{
				Name:    "reverse-dns",
				Aliases: []string{"r"},
				Usage:   "also query reverse DNS and include PTR names in the output",
				Local:   true,
			},
			&cli.BoolFlag{
				Name:    "city",
				Aliases: []string{"c"},
				Usage:   "include the city, downloading the city database (~125MB) if absent; once present it is used without this flag",
				Local:   true,
			},
			&cli.BoolFlag{
				Name:  "no-city",
				Usage: "omit the city even when the city database is present",
				Local: true,
			},
			&cli.BoolFlag{
				Name:    "netblock",
				Aliases: []string{"n"},
				Usage:   "include the registry netblock and its owner, building the database (~350MB of downloads) if absent; once present it is used without this flag",
				Local:   true,
			},
			&cli.BoolFlag{
				Name:  "no-netblock",
				Usage: "omit the netblock even when the netblock database is present",
				Local: true,
			},
			&cli.BoolFlag{
				Name:    "whois",
				Sources: cli.EnvVars("ASNAME_WHOIS"),
				Usage:   "look up addresses the offline netblock database cannot name (ARIN and LACNIC) online, over RDAP or else whois, without asking",
				Local:   true,
			},
			&cli.BoolFlag{
				Name:  "no-whois",
				Usage: "never query RDAP or whois, and do not ask",
				Local: true,
			},
			&cli.BoolFlag{
				Name:    "online-prefixes",
				Sources: cli.EnvVars("ASNAME_ONLINE_PREFIXES"),
				Usage:   "ask RIPEstat for the prefixes of an ASN the offline prefix database lacks, without asking",
				Local:   true,
			},
			&cli.BoolFlag{
				Name:  "no-online-prefixes",
				Usage: "never ask RIPEstat for prefixes, and do not ask",
				Local: true,
			},
			&cli.BoolFlag{
				Name:    "category",
				Aliases: []string{"C"},
				Usage:   "include what kind of network it is (cloud, CDN, hosting, ISP...), building the database if absent; once present it is used without this flag",
				Local:   true,
			},
			&cli.BoolFlag{
				Name:  "no-category",
				Usage: "omit the category even when the category database is present",
				Local: true,
			},
			&cli.BoolFlag{
				Name:    "reputation",
				Aliases: []string{"R"},
				Usage:   "include which public blocklists (Spamhaus DROP and ASN-DROP, IPsum, FireHOL) name the address and its ASN, building the database if absent; once present it is used without this flag, including by search",
			},
			&cli.BoolFlag{
				Name:  "no-reputation",
				Usage: "omit reputation even when the reputation database is present",
			},
			&cli.BoolFlag{
				Name:  "geofeed",
				Usage: "include where the network's own geofeed (RFC 8805) places the address, building the database if absent (needs the netblock database); once present it is used without this flag",
			},
			&cli.BoolFlag{
				Name:  "no-geofeed",
				Usage: "omit the geofeed location even when the geofeed database is present",
			},
			&cli.StringFlag{
				Name:    "org",
				Aliases: []string{"O"},
				Usage:   "search AS names and registry netblocks by organization name or netname",
				Local:   true,
			},
			&cli.IntFlag{
				Name:        "limit",
				Usage:       "maximum number of ASNs, and of netblocks, to display",
				DefaultText: "unlimited",
				Local:       true,
			},
			&cli.BoolFlag{
				Name:  "asns-only",
				Usage: "only search AS names",
				Local: true,
			},
			&cli.BoolFlag{
				Name:  "fuzzy",
				Usage: "also find names that match ignoring spaces and punctuation, or word by word in any order (company suffixes left out, abbreviations such as Univ expanded); best matches first",
				Local: true,
			},
			&cli.BoolFlag{
				Name:  "netblocks-only",
				Usage: "only search registry netblocks",
				Local: true,
			},
			&cli.BoolFlag{
				Name:  "ips-only",
				Usage: "only print matching CIDRs, one per line",
				Local: true,
			},
			&cli.StringFlag{
				Name:  "in",
				Usage: "only ASNs registered in `country` (a code such as AU, or a name) and netblocks the country database places there",
				Local: true,
			},
			&cli.BoolFlag{
				Name:  "v6",
				Usage: "also include IPv6 (search is IPv4 only unless this or --v6-only)",
				Local: true,
			},
			&cli.BoolFlag{
				Name:  "v4-only",
				Usage: "only show IPv4 addresses, prefixes and blocks",
			},
			&cli.BoolFlag{
				Name:  "v6-only",
				Usage: "only show IPv6 addresses, prefixes and blocks",
			},
			&cli.StringFlag{
				Name:    "dir",
				Aliases: []string{"d"},
				Sources: cli.EnvVars(sources.DirEnvVar),
				Value:   sources.DefaultDir(),
				Usage:   "data `directory` holding the databases",
			},
			&cli.StringFlag{
				Name:    "db",
				Sources: cli.EnvVars(sources.DBEnvVar),
				Usage:   "asnlookup database `file` (default: <dir>/" + sources.DBFilename + ")",
			},
			&cli.StringFlag{
				Name:    "names",
				Sources: cli.EnvVars(sources.NamesEnvVar),
				Usage:   "ASN->name mapping `file` (default: <dir>/" + sources.NamesFilename + ")",
			},
			&cli.StringFlag{
				Name:    "country",
				Aliases: []string{"country-db"},
				Sources: cli.EnvVars(sources.CountryEnvVar),
				Usage:   "IP->country database `file` (default: <dir>/" + sources.CountryFilename + ")",
			},
			&cli.StringFlag{
				Name:    "city-db",
				Sources: cli.EnvVars(sources.CityEnvVar),
				Usage:   "IP->city database `file` (default: <dir>/" + sources.CityFilename + ")",
			},
			&cli.StringFlag{
				Name:    "netblock-db",
				Sources: cli.EnvVars(sources.NetblockEnvVar),
				Usage:   "IP->netblock database `file` (default: <dir>/" + sources.NetblockFilename + ")",
			},
			&cli.StringFlag{
				Name:    "geofeed-db",
				Sources: cli.EnvVars(sources.GeofeedEnvVar),
				Usage:   "IP->geofeed database `file` (default: <dir>/" + sources.GeofeedFilename + ")",
			},
			&cli.StringFlag{
				Name:    "category-db",
				Sources: cli.EnvVars(sources.CategoryEnvVar),
				Usage:   "IP->category database `file` (default: <dir>/" + sources.CategoryFilename + ")",
			},
			&cli.StringFlag{
				Name:    "reputation-db",
				Sources: cli.EnvVars(sources.ReputationEnvVar),
				Usage:   "IP->reputation database `file` (default: <dir>/" + sources.ReputationFilename + ")",
			},
			&cli.StringFlag{
				Name:    "prefix-db",
				Sources: cli.EnvVars(sources.PrefixEnvVar),
				Usage:   "ASN->prefix database `file` (default: <dir>/" + sources.PrefixFilename + ")",
			},
			&cli.DurationFlag{
				Name:    "max-age",
				Value:   sources.DefaultMaxAge,
				Sources: cli.EnvVars("ASNAME_MAX_AGE"),
				Usage:   "auto-refresh data older than this `duration` (0 disables); without it, the age saved in the web UI, or 30 days",
				Local:   true,
			},
			&cli.BoolFlag{
				Name:  "no-update",
				Usage: "never auto-refresh data before a lookup",
				Local: true,
			},
			&cli.StringFlag{
				Name:    "contact-email",
				Sources: cli.EnvVars(sources.ContactEnvVar),
				Usage:   "`address` to identify with when fetching bgp.tools' operator tags",
			},
		},
		Commands: []*cli.Command{
			searchCommand(),
			countryCommand(),
			exploreCommand(),
			cityCommand(),
			updateCommand(),
			versionCommand(),
		},
		Action: lookupAction,
	}
}

// shouldColorize reports whether output written to cmd.Root().Writer is colored.
func shouldColorize(cmd *cli.Command) bool {
	f, _ := cmd.Root().Writer.(*os.File)
	return format.ShouldColorize(f, cmd.Bool("color"), cmd.Bool("no-color"))
}

func newConfig(cmd *cli.Command) sources.Config {
	dir := cmd.String("dir")
	c := sources.Config{
		DBPath:       cmd.String("db"),
		NamesPath:    cmd.String("names"),
		CountryPath:  cmd.String("country"),
		CityPath:     cmd.String("city-db"),
		NetblockPath: cmd.String("netblock-db"),
		CategoryPath: cmd.String("category-db"),

		ReputationPath: cmd.String("reputation-db"),
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
	c.MaxMindCityPath = os.Getenv(sources.MaxMindCityEnvVar)
	if c.MaxMindCityPath == "" {
		c.MaxMindCityPath = filepath.Join(dir, sources.MaxMindCityFilename)
	}
	if c.NetblockPath == "" {
		c.NetblockPath = filepath.Join(dir, sources.NetblockFilename)
	}
	if c.CategoryPath == "" {
		c.CategoryPath = filepath.Join(dir, sources.CategoryFilename)
	}
	c.GeofeedPath = cmd.String("geofeed-db")
	if c.GeofeedPath == "" {
		c.GeofeedPath = filepath.Join(dir, sources.GeofeedFilename)
	}
	if anyBool(cmd, "no-geofeed") {
		c.GeofeedPath = ""
	}
	if c.ReputationPath == "" {
		c.ReputationPath = filepath.Join(dir, sources.ReputationFilename)
	}
	c.PrefixPath = cmd.String("prefix-db")
	if c.PrefixPath == "" {
		c.PrefixPath = filepath.Join(dir, sources.PrefixFilename)
	}
	c.CachePath = filepath.Join(dir, sources.CacheDirName)
	c.UpdateRecordPath = filepath.Join(dir, sources.UpdateRecordFilename)
	c.ConsentPath = filepath.Join(dir, sources.WhoisConsentFilename)
	c.ContactPath = filepath.Join(dir, sources.ContactFilename)
	c.PrefixConsentPath = filepath.Join(dir, sources.OnlinePrefixConsentFilename)
	c.IPv6Path = filepath.Join(dir, sources.IPv6MarkerFilename)
	c.SettingsPath = filepath.Join(dir, sources.SettingsFilename)
	c.IPv6 = sources.IPv6RoutesEnabled(c)
	return c
}

func lookupAction(ctx context.Context, cmd *cli.Command) error {
	outputFlags := 0
	if cmd.Bool("pretty") {
		outputFlags++
	}
	if cmd.Bool("json") {
		outputFlags++
	}
	if cmd.Bool("csv") {
		outputFlags++
	}
	if cmd.Bool("uniform") {
		outputFlags++
	}
	if cmd.Bool("oneline") {
		outputFlags++
	}
	if outputFlags > 1 {
		return fmt.Errorf("--pretty, --oneline, --json, --csv and --uniform are mutually exclusive")
	}

	if cmd.String("org") != "" {
		return runSearch(cmd, []string{cmd.String("org")}, false)
	}

	if cmd.Bool("rest") && cmd.Bool("stream") {
		return fmt.Errorf("--rest and --stream are mutually exclusive")
	}
	v4Only, v6Only, err := addressFamily(cmd)
	if err != nil {
		return err
	}

	isStream := cmd.Bool("stream") || (cmd.NArg() == 1 && cmd.Args().First() == "-")
	isREST := cmd.Bool("rest")

	if !isStream && !isREST && cmd.NArg() != 1 {
		cli.ShowRootCommandHelp(cmd)
		return fmt.Errorf("exactly one IP address, hostname, URL, ASN or file argument is required")
	}

	cfg := newConfig(cmd)

	wantCity := !cmd.Bool("no-city") && (cmd.Bool("city") || sources.CityDBPresent(cfg.CityPath))
	wantNetblock := !cmd.Bool("no-netblock") && (cmd.Bool("netblock") || sources.NetblockDBPresent(cfg.NetblockPath))

	whois := sources.WhoisAsk
	if isStream || isREST {
		// In continuous stream or REST server modes, never ask interactively.
		// Use whois only if explicitly opted in via --whois or ASNAME_WHOIS.
		whois = sources.WhoisNever
	}
	switch {
	case cmd.Bool("no-whois") || cmd.Bool("no-netblock"):
		whois = sources.WhoisNever
	case cmd.Bool("whois"):
		whois = sources.WhoisAlways
	}
	showNetblock := wantNetblock || whois == sources.WhoisAlways
	wantCategory := !cmd.Bool("no-category") && (cmd.Bool("category") || sources.CategoryDBPresent(cfg.CategoryPath))
	wantReputation := !cmd.Bool("no-reputation") && (cmd.Bool("reputation") || sources.ReputationDBPresent(cfg.ReputationPath))

	if !cmd.Bool("no-update") {
		contact := sources.NewContactAsker(cfg.ContactPath, cmd.String("contact-email"))
		if err := sources.AutoUpdate(sources.WithLog(ctx, cmd.Root().ErrWriter), cfg, effectiveMaxAge(cmd, cfg).Age, wantCity, wantNetblock, wantCategory, wantReputation, contact); err != nil {
			fmt.Fprintln(cmd.Root().ErrWriter, "asname: auto-update failed:", err)
		}
		// --geofeed builds the database the first time; AutoUpdate keeps
		// it fresh from then on.
		if cmd.Bool("geofeed") && cfg.GeofeedPath != "" && !sources.GeofeedDBPresent(cfg.GeofeedPath) {
			if err := sources.UpdateGeofeedDB(sources.WithLog(ctx, cmd.Root().ErrWriter), cfg); err != nil {
				fmt.Fprintln(cmd.Root().ErrWriter, "asname: building the geofeed database failed:", err)
			}
		}
	}

	// RIPEstat is asked about like whois: on a terminal by default, and in
	// stream and REST modes only when opted into.
	onlinePrefixes := sources.WhoisAsk
	if isStream || isREST {
		onlinePrefixes = sources.WhoisNever
	}
	switch {
	case cmd.Bool("no-online-prefixes"):
		onlinePrefixes = sources.WhoisNever
	case cmd.Bool("online-prefixes"):
		onlinePrefixes = sources.WhoisAlways
	}

	eng, err := engine.NewEngine(cfg, wantCity, wantNetblock, showNetblock, wantCategory, wantReputation, whois, cmd.Root().ErrWriter)
	if err != nil {
		return err
	}
	eng.SetOnlinePrefixes(onlinePrefixes)

	if isREST {
		server := rest.NewServerWithOptions(eng, restOptions(cmd, whois, onlinePrefixes))
		defer server.Close()
		return server.Start(context.Background())
	}
	defer eng.Close()

	if isStream {
		fmtMode := format.FormatDefault
		switch {
		case cmd.Bool("json"):
			fmtMode = format.FormatJSON
		case cmd.Bool("csv"):
			fmtMode = format.FormatCSV
		case cmd.Bool("uniform"):
			fmtMode = format.FormatUniform
		case prettyOutput(cmd):
			fmtMode = format.FormatPretty
		}

		useColor := shouldColorize(cmd)
		opts := stream.StreamOptions{
			Format:     fmtMode,
			ReverseDNS: cmd.Bool("reverse-dns"),
			UseColor:   useColor,
			V4Only:     v4Only,
			V6Only:     v6Only,
		}

		var r io.Reader = cmd.Root().Reader
		if cmd.NArg() == 1 && cmd.Args().First() != "-" {
			f, err := os.Open(cmd.Args().First())
			if err != nil {
				return err
			}
			defer f.Close()
			r = f
		}

		return stream.RunStream(ctx, r, cmd.Root().Writer, eng, opts)
	}

	targets, err := engine.ParseTargets(cmd.Args().First())
	if err != nil {
		return err
	}

	engine.ResolveTargets(ctx, targets)
	for i := range targets {
		targets[i] = targets[i].OnlyFamily(v4Only, v6Only)
	}

	results := make([]engine.LookupResult, 0, len(targets))
	showHost := false
	failures := 0
	for _, t := range targets {
		found, err := eng.LookupTarget(t)
		if err != nil {
			if len(targets) == 1 {
				return err
			}
			fmt.Fprintf(cmd.Root().ErrWriter, "asname: %s: %v\n", t.Raw, err)
			failures++
			continue
		}
		if t.Host != "" {
			showHost = true
		}
		results = append(results, found...)
	}

	engine.OnlyFamilyPrefixes(results, v4Only, v6Only)
	if cmd.Bool("reverse-dns") {
		engine.ResolveReverseDNS(ctx, results)
	}

	out := bufio.NewWriter(cmd.Root().Writer)
	uniform := cmd.Bool("uniform")
	isJSON := cmd.Bool("json")
	isCSV := cmd.Bool("csv")
	isPretty := prettyOutput(cmd)
	useColor := shouldColorize(cmd)

	if isCSV {
		fmt.Fprint(out, format.FormatCSVRow(format.LookupCSVHeader))
	}
	for i, res := range results {
		if isJSON {
			line, err := format.FormatJSONLookupOutput(res)
			if err != nil {
				return err
			}
			fmt.Fprint(out, line)
		} else if isCSV {
			fmt.Fprint(out, format.FormatCSVLookupOutput(res))
		} else if isPretty {
			fmt.Fprint(out, format.FormatPrettyLookupOutput(res, i, len(results), useColor))
		} else {
			fmt.Fprint(out, format.FormatLookupOutput(res, uniform, showHost))
			if res.IsASN && len(results) == 1 && !uniform && len(res.Prefixes) > 0 {
				fmt.Fprintln(out, "Announced Prefixes:")
				for _, p := range res.Prefixes {
					fmt.Fprintf(out, "  %s\n", p)
				}
			}
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

// searchCommand repeats the root's search flags so they work after `search`
// and its query; the root's copies are local to it, so they only parse before
// the query of a lookup. The flags every command shares are the root's.
func searchCommand() *cli.Command {
	return &cli.Command{
		Name:      "search",
		Usage:     "search AS names and registry netblocks by organization name or netname",
		ArgsUsage: "<organization-name | ->",
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:        "limit",
				Aliases:     []string{"l"},
				Usage:       "maximum number of ASNs, and of netblocks, to display",
				DefaultText: "unlimited",
			},
			&cli.BoolFlag{
				Name:  "asns-only",
				Usage: "only search AS names",
			},
			&cli.BoolFlag{
				Name:  "netblocks-only",
				Usage: "only search registry netblocks",
			},
			&cli.BoolFlag{
				Name:  "fuzzy",
				Usage: "also find names that match ignoring spaces and punctuation, or word by word in any order (company suffixes left out, abbreviations such as Univ expanded); best matches first",
			},
			&cli.BoolFlag{
				Name:  "ips-only",
				Usage: "only print matching CIDRs, one per line",
			},
			&cli.StringFlag{
				Name:  "in",
				Usage: "only ASNs registered in `country` (a code such as AU, or a name) and netblocks the country database places there",
			},
			&cli.BoolFlag{
				Name:  "v6",
				Usage: "also include IPv6 (search is IPv4 only unless this or --v6-only)",
			},
			&cli.BoolFlag{
				Name:    "uniform",
				Aliases: []string{"u"},
				Usage:   "print output as aligned fields",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.NArg() > 1 {
				cli.ShowSubcommandHelp(cmd)
				return fmt.Errorf("search takes one organization or netname; quote a query with spaces")
			}
			query := cmd.Args().First()
			if query == "" || query == "-" {
				r := cmd.Root().Reader
				if f, ok := r.(*os.File); ok && query == "" && isTerminal(f) {
					cli.ShowSubcommandHelp(cmd)
					return fmt.Errorf("search requires an organization or netname argument, or one on stdin")
				}
				queries, err := readSearchQueries(r)
				if err != nil {
					return err
				}
				return runSearch(cmd, queries, true)
			}
			return runSearch(cmd, []string{query}, false)
		},
	}
}

// readSearchQueries reads search queries from r, one per line, such as a
// list piped in with `cat orgs.txt | asname search`. Blank lines are ignored.
func readSearchQueries(r io.Reader) ([]string, error) {
	var queries []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			queries = append(queries, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading search queries from stdin: %w", err)
	}
	if len(queries) == 0 {
		return nil, fmt.Errorf("search requires an organization or netname argument, or one on stdin")
	}
	return queries, nil
}

// isTerminal reports whether f is an interactive terminal rather than a pipe
// or file.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// anyBool reports whether the boolean flag name is set on cmd or a command
// above it, as search has its own copies of some root flags.
// anyString is the value of the string flag name on cmd or the nearest
// command above it that sets it.
func anyString(cmd *cli.Command, name string) string {
	for _, c := range cmd.Lineage() {
		if v := c.String(name); v != "" {
			return v
		}
	}
	return ""
}

func anyBool(cmd *cli.Command, name string) bool {
	for _, c := range cmd.Lineage() {
		if c.Bool(name) {
			return true
		}
	}
	return false
}

// nearestInt returns the integer flag name from the nearest command that sets
// it, or 0.
func nearestInt(cmd *cli.Command, name string) int {
	for _, c := range cmd.Lineage() {
		if c.IsSet(name) {
			return c.Int(name)
		}
	}
	return 0
}

// prettyOutput reports whether lookup and search results print as cards.
// Cards are the default unless --oneline or another output format is chosen.
func prettyOutput(cmd *cli.Command) bool {
	if cmd.Bool("pretty") {
		return true
	}
	return !cmd.Bool("oneline") && !cmd.Bool("json") && !cmd.Bool("csv") &&
		!anyBool(cmd, "uniform") && !anyBool(cmd, "ips-only")
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// addressFamily returns --v4-only and --v6-only, which may not both be set.
func addressFamily(cmd *cli.Command) (v4Only, v6Only bool, err error) {
	v4Only, v6Only = cmd.Bool("v4-only"), cmd.Bool("v6-only")
	if v4Only && v6Only {
		return false, false, fmt.Errorf("--v4-only and --v6-only are mutually exclusive")
	}
	return v4Only, v6Only, nil
}

// searchAddressFamily is addressFamily with search's default: IPv4 only,
// unless --v6 (both families) or --v6-only is set.
func searchAddressFamily(cmd *cli.Command) (v4Only, v6Only bool, err error) {
	v4Only, v6Only, err = addressFamily(cmd)
	if err != nil {
		return false, false, err
	}
	includeV6 := anyBool(cmd, "v6")
	if includeV6 && v4Only {
		return false, false, fmt.Errorf("--v4-only and --v6 are mutually exclusive")
	}
	if includeV6 && v6Only {
		return false, false, fmt.Errorf("--v6 and --v6-only are mutually exclusive")
	}
	if !includeV6 && !v6Only {
		v4Only = true
	}
	return v4Only, v6Only, nil
}

// runSearch searches for each query in turn. With fromStdin, CSV and JSON
// output name the query each row matched.
func runSearch(cmd *cli.Command, queries []string, fromStdin bool) error {
	outputFlags := 0
	if cmd.Bool("pretty") {
		outputFlags++
	}
	if cmd.Bool("json") {
		outputFlags++
	}
	if cmd.Bool("csv") {
		outputFlags++
	}
	if anyBool(cmd, "uniform") {
		outputFlags++
	}
	if cmd.Bool("oneline") {
		outputFlags++
	}
	ipsOnly := anyBool(cmd, "ips-only")
	if ipsOnly {
		outputFlags++
	}
	if outputFlags > 1 {
		return fmt.Errorf("--pretty, --oneline, --json, --csv, --uniform and --ips-only are mutually exclusive")
	}

	asnsOnly, netblocksOnly := anyBool(cmd, "asns-only"), anyBool(cmd, "netblocks-only")
	if asnsOnly && netblocksOnly {
		return fmt.Errorf("--asns-only and --netblocks-only are mutually exclusive")
	}
	v4Only, v6Only, err := searchAddressFamily(cmd)
	if err != nil {
		return err
	}

	country := ""
	if v := anyString(cmd, "in"); v != "" {
		if country, err = sources.ParseCountry(v); err != nil {
			return err
		}
	}

	cfg := newConfig(cmd)

	// The AS names need no netblock database, so without one a combined
	// search still answers from them.
	wantNetblock := !asnsOnly
	if wantNetblock && !sources.NetblockDBPresent(cfg.NetblockPath) {
		if netblocksOnly {
			return fmt.Errorf("netblock database is not present; build it with `asname update --netblock-only` or pass `--netblock`")
		}
		fmt.Fprintln(cmd.Root().ErrWriter, "asname: netblock database is not present, so only AS names are searched; build it with `asname update --netblock-only`")
		wantNetblock = false
	}

	// Search reports reputation whenever the database is present; asking for
	// it builds the database first if it is missing.
	wantReputation := !anyBool(cmd, "no-reputation") && (anyBool(cmd, "reputation") || sources.ReputationDBPresent(cfg.ReputationPath))
	if anyBool(cmd, "reputation") && !anyBool(cmd, "no-update") && sources.Stale(cfg.ReputationPath, 0) {
		if err := os.MkdirAll(filepath.Dir(cfg.ReputationPath), 0o755); err != nil {
			return err
		}
		if err := sources.UpdateReputationDB(sources.WithLog(context.Background(), cmd.Root().ErrWriter), cfg); err != nil {
			fmt.Fprintln(cmd.Root().ErrWriter, "asname: updating reputation database failed:", err)
		}
	}

	eng, err := engine.NewEngine(cfg, false, wantNetblock, wantNetblock, false, wantReputation, sources.WhoisNever, cmd.Root().ErrWriter)
	if err != nil {
		return err
	}
	defer eng.Close()

	limit := nearestInt(cmd, "limit")
	isJSON, isCSV := cmd.Bool("json"), cmd.Bool("csv")
	out := bufio.NewWriter(cmd.Root().Writer)
	if isCSV {
		header := format.SearchCSVHeader
		if fromStdin {
			header = format.SearchQueryCSVHeader
		}
		fmt.Fprint(out, format.FormatCSVRow(header))
	}
	// --ips-only prints each CIDR once, even when several queries match it.
	seenCIDRs := make(map[string]struct{})

	for _, query := range queries {
		var asns []engine.ASNSearchResult
		if !netblocksOnly {
			asns = eng.SearchASNsWith(query, engine.ASNSearchOptions{Limit: limit, V4Only: v4Only, V6Only: v6Only, Fuzzy: anyBool(cmd, "fuzzy"), Country: country})
		}

		var netblocks []engine.NetblockEnrichedResult
		if wantNetblock {
			netblocks, err = eng.SearchNetblocks(query, sources.NetblockSearchOptions{
				Limit:   limit,
				V4Only:  v4Only,
				V6Only:  v6Only,
				Fuzzy:   anyBool(cmd, "fuzzy"),
				Country: country,
			})
			if err != nil {
				return err
			}
		}

		total := len(asns) + len(netblocks)
		if total == 0 {
			if isJSON || isCSV {
				continue
			}
			what := "ASNs or netblocks"
			if asnsOnly || !wantNetblock {
				what = "ASNs"
			} else if netblocksOnly {
				what = "netblocks"
			}
			fmt.Fprintf(cmd.Root().ErrWriter, "asname: no %s found matching %q\n", what, query)
			continue
		}

		if ipsOnly {
			writeSearchCIDRs(out, cmd.Root().ErrWriter, query, seenCIDRs, asns, netblocks)
			continue
		}
		label := ""
		if fromStdin {
			label = query
		}
		if err := writeSearchResults(cmd, out, label, asns, netblocks); err != nil {
			return err
		}
	}
	return out.Flush()
}

// writeSearchResults writes one query's matches in the chosen output format.
// A non-empty query is added to CSV and JSON rows.
func writeSearchResults(cmd *cli.Command, out *bufio.Writer, query string, asns []engine.ASNSearchResult, netblocks []engine.NetblockEnrichedResult) error {
	isJSON, isCSV := cmd.Bool("json"), cmd.Bool("csv")
	uniform := anyBool(cmd, "uniform")
	isPretty := prettyOutput(cmd)
	useColor := shouldColorize(cmd)
	total := len(asns) + len(netblocks)

	for i, res := range asns {
		if isJSON {
			line, err := format.FormatJSONASNSearchOutput(res, query)
			if err != nil {
				return err
			}
			fmt.Fprint(out, line)
		} else if isCSV {
			fmt.Fprint(out, format.FormatCSVASNSearchOutput(res, query))
		} else if isPretty {
			fmt.Fprint(out, format.FormatPrettyASNSearchOutput(res, i, total, useColor))
		} else {
			fmt.Fprint(out, format.FormatASNSearchOutput(res))
		}
	}
	for i, res := range netblocks {
		if isJSON {
			line, err := format.FormatJSONNetblockOutput(res, query)
			if err != nil {
				return err
			}
			fmt.Fprint(out, line)
		} else if isCSV {
			fmt.Fprint(out, format.FormatCSVNetblockOutput(res, query))
		} else if isPretty {
			fmt.Fprint(out, format.FormatPrettyNetblockOutput(res, len(asns)+i, total, useColor))
		} else {
			fmt.Fprint(out, format.FormatNetblockOutput(res, uniform))
		}
	}
	return nil
}

// writeSearchCIDRs writes one query's CIDRs, skipping any already in seen.
func writeSearchCIDRs(out *bufio.Writer, errOut io.Writer, query string, seen map[string]struct{}, asns []engine.ASNSearchResult, netblocks []engine.NetblockEnrichedResult) {
	n := 0
	write := func(cidrs []string) {
		for _, cidr := range cidrs {
			if cidr == "" {
				continue
			}
			n++
			if _, ok := seen[cidr]; ok {
				continue
			}
			seen[cidr] = struct{}{}
			fmt.Fprintln(out, cidr)
		}
	}
	for _, res := range asns {
		write(res.Prefixes)
	}
	for _, res := range netblocks {
		write(res.CIDRs)
	}
	if n == 0 {
		fmt.Fprintf(errOut, "asname: no CIDRs found matching %q\n", query)
	}
}

func countryCommand() *cli.Command {
	return &cli.Command{
		Name:      "country",
		Usage:     "list every IP block (CIDR) registered to a country",
		ArgsUsage: "<country-code|country-name>...",
		Description: "Prints the minimal CIDR blocks the country database assigns to each country, one per line.\n" +
			"The database comes from the RIR delegation files, so a block is listed under the country its\n" +
			"holder registered it in, which is not always where its addresses are used.",

		Action: countryAction,
	}
}

func countryAction(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() == 0 {
		cli.ShowSubcommandHelp(cmd)
		return fmt.Errorf("country requires a country code or name, such as AU or Australia")
	}
	isJSON, isCSV, isPretty := cmd.Bool("json"), cmd.Bool("csv"), cmd.Bool("pretty")
	if n := btoi(isJSON) + btoi(isCSV) + btoi(isPretty); n > 1 {
		return fmt.Errorf("--pretty, --json and --csv are mutually exclusive")
	}
	v4Only, v6Only, err := addressFamily(cmd)
	if err != nil {
		return err
	}

	cfg := newConfig(cmd)
	eng, err := engine.NewEngine(cfg, false, false, false, false, false, sources.WhoisNever, cmd.Root().ErrWriter)
	if err != nil {
		return err
	}
	defer eng.Close()

	out := bufio.NewWriter(cmd.Root().Writer)
	useColor := shouldColorize(cmd)
	if isCSV {
		fmt.Fprint(out, format.FormatCSVRow(format.CountryCSVHeader))
	}
	for i, arg := range cmd.Args().Slice() {
		cc, v4, v6, err := eng.CountryPrefixes(arg)
		if err != nil {
			out.Flush()
			return err
		}
		if v6Only {
			v4 = nil
		}
		if v4Only {
			v6 = nil
		}
		if len(v4)+len(v6) == 0 {
			fmt.Fprintf(cmd.Root().ErrWriter, "asname: no blocks registered to %s\n", cc)
			continue
		}

		switch {
		case isPretty:
			country := cc
			if name, ok := sources.CountryNames[cc]; ok {
				country = cc + ", " + name
			}
			fmt.Fprint(out, format.FormatPrettyCountryOutput(country, v4, v6, i, cmd.NArg(), useColor))
		case isJSON:
			for _, family := range []struct {
				cidrs []string
				isV6  bool
			}{{v4, false}, {v6, true}} {
				for _, c := range family.cidrs {
					line, err := format.FormatJSONCountryPrefix(cc, c, family.isV6)
					if err != nil {
						return err
					}
					fmt.Fprint(out, line)
				}
			}
		case isCSV:
			for _, c := range v4 {
				fmt.Fprint(out, format.FormatCSVCountryPrefix(cc, c, false))
			}
			for _, c := range v6 {
				fmt.Fprint(out, format.FormatCSVCountryPrefix(cc, c, true))
			}
		default:
			for _, c := range v4 {
				fmt.Fprintln(out, c)
			}
			for _, c := range v6 {
				fmt.Fprintln(out, c)
			}
		}
	}
	return out.Flush()
}

func cityCommand() *cli.Command {
	return &cli.Command{
		Name:      "city",
		Usage:     "list every IP block (CIDR) the city database locates in a city",
		ArgsUsage: "<city>[, <region|country>]...",
		Description: "Prints the minimal CIDR blocks the DB-IP Lite city database locates in each city, one per line.\n" +
			"A name several places share, such as Brisbane, lists them all; add a region, country code or\n" +
			"country name to pick one, as in \"Brisbane, AU\" or \"Brisbane, Queensland\". The locations are\n" +
			"geolocation estimates, so expect some blocks to be missing or misplaced. Needs the city database\n" +
			"(~125MB); download it with `asname update --city-only`.",

		Action: cityAction,
	}
}

func cityAction(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() == 0 {
		cli.ShowSubcommandHelp(cmd)
		return fmt.Errorf("city requires a city name, such as Brisbane or \"Brisbane, AU\"")
	}
	isJSON, isCSV, isPretty := cmd.Bool("json"), cmd.Bool("csv"), cmd.Bool("pretty")
	if n := btoi(isJSON) + btoi(isCSV) + btoi(isPretty); n > 1 {
		return fmt.Errorf("--pretty, --json and --csv are mutually exclusive")
	}
	v4Only, v6Only, err := addressFamily(cmd)
	if err != nil {
		return err
	}

	cfg := newConfig(cmd)
	if !sources.CityDBPresent(cfg.CityPath) {
		return fmt.Errorf("city database is not present; download it (~125MB) with `asname update --city-only`")
	}
	eng, err := engine.NewEngine(cfg, true, false, false, false, false, sources.WhoisNever, cmd.Root().ErrWriter)
	if err != nil {
		return err
	}
	defer eng.Close()

	var places []sources.CityPlace
	for _, arg := range cmd.Args().Slice() {
		found, err := eng.CityPrefixes(arg)
		if err != nil {
			return err
		}
		n := 0
		for _, p := range found {
			if v6Only {
				p.IPv4 = nil
			}
			if v4Only {
				p.IPv6 = nil
			}
			if len(p.IPv4)+len(p.IPv6) > 0 {
				found[n] = p
				n++
			}
		}
		found = found[:n]

		switch {
		case len(found) == 0:
			fmt.Fprintf(cmd.Root().ErrWriter, "asname: no blocks located in %q\n", arg)
		case len(found) > 1:
			fmt.Fprintf(cmd.Root().ErrWriter, "asname: %q matches %d places, so all are listed; add a region or country to pick one:\n", arg, len(found))
			for _, p := range found {
				fmt.Fprintf(cmd.Root().ErrWriter, "asname:   %s, %s (%d blocks)\n", sources.FormatCity(p.City, p.Region), p.Country, len(p.IPv4)+len(p.IPv6))
			}
		}
		places = append(places, found...)
	}

	out := bufio.NewWriter(cmd.Root().Writer)
	useColor := shouldColorize(cmd)
	if isCSV {
		fmt.Fprint(out, format.FormatCSVRow(format.CityCSVHeader))
	}
	for i, p := range places {
		switch {
		case isPretty:
			fmt.Fprint(out, format.FormatPrettyCityOutput(p, i, len(places), useColor))
		case isJSON:
			for _, family := range []struct {
				cidrs []string
				isV6  bool
			}{{p.IPv4, false}, {p.IPv6, true}} {
				for _, c := range family.cidrs {
					line, err := format.FormatJSONCityPrefix(p, c, family.isV6)
					if err != nil {
						return err
					}
					fmt.Fprint(out, line)
				}
			}
		case isCSV:
			for _, c := range p.IPv4 {
				fmt.Fprint(out, format.FormatCSVCityPrefix(p, c, false))
			}
			for _, c := range p.IPv6 {
				fmt.Fprint(out, format.FormatCSVCityPrefix(p, c, true))
			}
		default:
			for _, c := range p.IPv4 {
				fmt.Fprintln(out, c)
			}
			for _, c := range p.IPv6 {
				fmt.Fprintln(out, c)
			}
		}
	}
	return out.Flush()
}

func updateCommand() *cli.Command {
	return &cli.Command{
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
			&cli.BoolFlag{
				Name:  "city-only",
				Usage: "only refresh the IP->city database (large; downloads it if absent)",
			},
			&cli.BoolFlag{
				Name:  "netblock-only",
				Usage: "only refresh the IP->netblock database (large; builds it if absent)",
			},
			&cli.BoolFlag{
				Name:  "category-only",
				Usage: "only refresh the IP->category database (builds it if absent)",
			},
			&cli.BoolFlag{
				Name:  "geofeed-only",
				Usage: "only refresh the IP->geofeed database: fetches the networks' own location feeds (RFC 8805) that the netblock database's ranges name, ~6,000 small files from their hosts (builds it if absent)",
			},
			&cli.BoolFlag{
				Name:  "reputation-only",
				Usage: "only refresh the IP->reputation database of public blocklists (builds it if absent)",
			},
			&cli.StringFlag{
				Name:  "rib-url",
				Usage: "download the RIB MRT dump from this `URL` (.bz2 or .gz) instead of trying RouteViews then RIPE RIS",
			},
			&cli.BoolFlag{
				Name:    "ipv6",
				Sources: cli.EnvVars("ASNAME_IPV6"),
				Usage:   "also import IPv6 routes into the ASN and prefix databases (~25MB more from RouteViews); later updates keep doing so",
			},
			&cli.BoolFlag{
				Name:  "no-ipv6",
				Usage: "import IPv4 routes only, undoing an earlier --ipv6",
			},
			&cli.BoolFlag{
				Name:    "incremental",
				Aliases: []string{"i"},
				Usage:   "only rebuild databases whose last update failed or left a source out, reusing downloads from the last 24 hours",
			},
		},
		Action: updateAction,
	}
}

func updateAction(ctx context.Context, cmd *cli.Command) error {
	cfg := newConfig(cmd)
	switch {
	case cmd.Bool("ipv6") && cmd.Bool("no-ipv6"):
		return fmt.Errorf("--ipv6 and --no-ipv6 are mutually exclusive")
	case cmd.Bool("ipv6"):
		cfg.IPv6 = true
	case cmd.Bool("no-ipv6"):
		cfg.IPv6 = false
	}
	sel := updateSelection{
		Only:         map[string]bool{},
		Also:         map[string]bool{},
		Incremental:  cmd.Bool("incremental"),
		RIBURL:       cmd.String("rib-url"),
		ContactEmail: cmd.String("contact-email"),
	}
	for flag, key := range map[string]string{
		"db-only": sources.KeyASN, "names-only": sources.KeyNames, "country-only": sources.KeyCountry,
		"city-only": sources.KeyCity, "netblock-only": sources.KeyNetblock,
		"category-only": sources.KeyCategory, "reputation-only": sources.KeyReputation,
		"geofeed-only": sources.KeyGeofeed,
	} {
		if cmd.Bool(flag) {
			sel.Only[key] = true
		}
	}
	for _, key := range []string{sources.KeyCity, sources.KeyNetblock, sources.KeyGeofeed, sources.KeyCategory, sources.KeyReputation} {
		if cmd.Bool(key) {
			sel.Also[key] = true
		}
	}
	return runDatabaseUpdate(ctx, cfg, sel, cmd.Root().ErrWriter)
}

// restRefreshEvery is how often a REST server started with --allow-updates
// checks for databases older than --max-age.
const restRefreshEvery = 6 * time.Hour

// restOptions configures the REST server: the web UI, the status endpoint
// and, with --allow-updates, database updates that reopen the databases.
func restOptions(cmd *cli.Command, whois, onlinePrefixes sources.WhoisMode) rest.Options {
	opts := rest.Options{
		ListenAddr: cmd.String("listen"),
		CORS:       cmd.Bool("cors"),
		ReverseDNS: cmd.Bool("reverse-dns"),
		Version:    version,
		WebDir:     cmd.String("web-dir"),
	}
	// Online lookups: whois and RIPEstat answer a request that asks for
	// them unless turned off for the server; --whois and --online-prefixes
	// make them the default.
	opts.Online = rest.OnlineOptions{
		WhoisAvailable:    !cmd.Bool("no-whois") && !cmd.Bool("no-netblock"),
		WhoisDefault:      whois == sources.WhoisAlways,
		PrefixesAvailable: !cmd.Bool("no-online-prefixes"),
		PrefixesDefault:   onlinePrefixes == sources.WhoisAlways,
	}
	opts.Status = func() any {
		cfg := newConfig(cmd)
		age := effectiveMaxAge(cmd, cfg)
		v := format.NewJSONVersion(version, cmd.String("dir"), age.Age, cfg.IPv6, sources.DatabaseStatus(cfg), time.Now())
		v.MaxAgeSource = age.Source
		return v
	}
	if !cmd.Bool("allow-updates") {
		return opts
	}

	// wants reports which optional databases to use: those present, unless
	// suppressed for this run, plus those asked for on the command line.
	wants := func(cfg sources.Config) (city, netblock, category, reputation bool) {
		city = !cmd.Bool("no-city") && (cmd.Bool("city") || sources.CityDBPresent(cfg.CityPath))
		netblock = !cmd.Bool("no-netblock") && (cmd.Bool("netblock") || sources.NetblockDBPresent(cfg.NetblockPath))
		category = !cmd.Bool("no-category") && (cmd.Bool("category") || sources.CategoryDBPresent(cfg.CategoryPath))
		reputation = !cmd.Bool("no-reputation") && (cmd.Bool("reputation") || sources.ReputationDBPresent(cfg.ReputationPath))
		return
	}
	opts.Update = func(ctx context.Context, req rest.UpdateRequest, log io.Writer) error {
		cfg := newConfig(cmd)
		if req.StaleOnly {
			maxAge := effectiveMaxAge(cmd, cfg).Age
			if maxAge <= 0 {
				return nil
			}
			contact := sources.NewContactAsker(cfg.ContactPath, cmd.String("contact-email"))
			contact.Terminal, contact.Out = false, log
			city, netblock, category, reputation := wants(cfg)
			return sources.AutoUpdate(sources.WithLog(ctx, log), cfg, maxAge, city, netblock, category, reputation, contact)
		}
		sel := updateSelection{
			Only:         map[string]bool{},
			Incremental:  req.Incremental,
			ContactEmail: cmd.String("contact-email"),
			NoPrompt:     true,
		}
		for _, key := range req.Databases {
			sel.Only[key] = true
		}
		return runDatabaseUpdate(ctx, cfg, sel, log)
	}
	opts.Reload = func() (*engine.Engine, error) {
		cfg := newConfig(cmd)
		city, netblock, category, reputation := wants(cfg)
		showNetblock := netblock || whois == sources.WhoisAlways
		eng, err := engine.NewEngine(cfg, city, netblock, showNetblock, category, reputation, whois, cmd.Root().ErrWriter)
		if err != nil {
			return nil, err
		}
		eng.SetOnlinePrefixes(onlinePrefixes)
		return eng, nil
	}
	// The refresh age can change while the server runs (it is saved from
	// the web UI), so the check runs regardless and looks it up each time.
	opts.RefreshEvery = restRefreshEvery
	opts.NeedsRefresh = func() bool {
		cfg := newConfig(cmd)
		maxAge := effectiveMaxAge(cmd, cfg).Age
		if maxAge <= 0 {
			return false
		}
		now := time.Now()
		for _, db := range sources.DatabaseStatus(cfg) {
			if (!db.Present && !db.Optional) || (db.Present && now.Sub(db.Updated) > maxAge) {
				return true
			}
		}
		return false
	}
	opts.SaveSettings = func(req rest.SettingsRequest) error {
		cfg := newConfig(cmd)
		if req.MaxAgeHours != nil {
			if src := effectiveMaxAge(cmd, cfg).Source; src == maxAgeFromFlag || src == maxAgeOff {
				return rest.ErrSettingFixed("the refresh age is set on the server's command line (--max-age, ASNAME_MAX_AGE or --no-update); change it there")
			}
			hours := *req.MaxAgeHours
			if hours < 0 || hours > 24*3650 {
				return rest.ErrSettingInvalid("max_age_hours must be between 0 (never) and 87600")
			}
			s, err := sources.LoadSettings(cfg.SettingsPath)
			if err != nil {
				return err
			}
			s.MaxAge = (time.Duration(hours * float64(time.Hour))).String()
			if err := sources.SaveSettings(cfg.SettingsPath, s); err != nil {
				return err
			}
		}
		if req.IPv6Routes != nil {
			if err := sources.SetIPv6Routes(cfg, *req.IPv6Routes); err != nil {
				return err
			}
		}
		return nil
	}
	return opts
}

// Where the refresh age came from, as /v1/status reports it.
const (
	maxAgeOff      = "off"     // --no-update
	maxAgeFromFlag = "flag"    // --max-age or ASNAME_MAX_AGE
	maxAgeSaved    = "saved"   // saved in the data directory from the web UI
	maxAgeDefault  = "default" // 30 days
)

type maxAgeSetting struct {
	Age    time.Duration
	Source string
}

// effectiveMaxAge is the age at which databases are refreshed: off with
// --no-update, else --max-age or ASNAME_MAX_AGE when given, else the age
// saved in the data directory, else the 30-day default.
func effectiveMaxAge(cmd *cli.Command, cfg sources.Config) maxAgeSetting {
	if anyBool(cmd, "no-update") {
		return maxAgeSetting{0, maxAgeOff}
	}
	for _, c := range cmd.Lineage() {
		if c.IsSet("max-age") {
			return maxAgeSetting{c.Duration("max-age"), maxAgeFromFlag}
		}
	}
	if s, err := sources.LoadSettings(cfg.SettingsPath); err == nil {
		if age, ok := s.SavedMaxAge(); ok {
			return maxAgeSetting{age, maxAgeSaved}
		}
	}
	return maxAgeSetting{sources.DefaultMaxAge, maxAgeDefault}
}

// updateSelection says which databases runDatabaseUpdate rebuilds.
type updateSelection struct {
	// Only lists the databases to rebuild, by sources.UpdateKeys key. Empty
	// means the core databases plus every optional database already present.
	Only map[string]bool
	// Also adds optional databases to an Only-less update, building them if
	// absent.
	Also         map[string]bool
	Incremental  bool
	RIBURL       string
	ContactEmail string
	// NoPrompt never asks on the terminal for the bgp.tools contact
	// address; without a saved one the category update skips their tags.
	NoPrompt bool
}

// runDatabaseUpdate rebuilds the databases sel selects, writing progress to
// errOut. It backs `asname update` and the REST server's /v1/update.
func runDatabaseUpdate(ctx context.Context, cfg sources.Config, sel updateSelection, errOut io.Writer) error {
	rctx := sources.WithLog(ctx, errOut)
	for _, dir := range []string{cfg.DBPath, cfg.NamesPath, cfg.CountryPath, cfg.CityPath, cfg.NetblockPath, cfg.CategoryPath, cfg.ReputationPath, cfg.PrefixPath} {
		if dir != "" {
			if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
				return err
			}
		}
	}

	all := len(sel.Only) == 0
	run := map[string]bool{
		sources.KeyASN:        all || sel.Only[sources.KeyASN],
		sources.KeyNames:      all || sel.Only[sources.KeyNames],
		sources.KeyCountry:    all || sel.Only[sources.KeyCountry],
		sources.KeyCity:       sel.Only[sources.KeyCity] || sel.Also[sources.KeyCity] || (all && sources.CityDBPresent(cfg.CityPath)),
		sources.KeyNetblock:   sel.Only[sources.KeyNetblock] || sel.Also[sources.KeyNetblock] || (all && sources.NetblockDBPresent(cfg.NetblockPath)),
		sources.KeyGeofeed:    cfg.GeofeedPath != "" && (sel.Only[sources.KeyGeofeed] || sel.Also[sources.KeyGeofeed] || (all && sources.GeofeedDBPresent(cfg.GeofeedPath))),
		sources.KeyCategory:   sel.Only[sources.KeyCategory] || sel.Also[sources.KeyCategory] || (all && sources.CategoryDBPresent(cfg.CategoryPath)),
		sources.KeyReputation: sel.Only[sources.KeyReputation] || sel.Also[sources.KeyReputation] || (all && sources.ReputationDBPresent(cfg.ReputationPath)),
	}
	if sel.Incremental {
		// Keep only what the last update left incomplete, plus any core
		// database that is missing altogether.
		rec := sources.LoadUpdateRecord(cfg.UpdateRecordPath)
		missing := map[string]string{
			sources.KeyASN:     cfg.DBPath,
			sources.KeyNames:   cfg.NamesPath,
			sources.KeyCountry: cfg.CountryPath,
		}
		var retry []string
		for _, key := range sources.UpdateKeys {
			if !run[key] {
				continue
			}
			path, core := missing[key]
			switch {
			case rec[key].Incomplete():
				retry = append(retry, describeOutcome(key, rec[key]))
			case core && sources.Stale(path, 0):
				retry = append(retry, key+" (missing)")
			default:
				run[key] = false
			}
		}
		if len(retry) == 0 {
			fmt.Fprintln(errOut, "asname: the last update of every selected database completed; nothing to retry")
			return nil
		}
		fmt.Fprintf(errOut, "asname: retrying %s\n", strings.Join(retry, ", "))
	}

	// A database that fails keeps its existing file; the others are still
	// rebuilt, since they come from different hosts.
	var failed []error
	if run[sources.KeyASN] {
		if err := sources.UpdateDatabase(rctx, cfg, sel.RIBURL); err != nil {
			failed = append(failed, fmt.Errorf("updating ASN database: %v", err))
		}
	}
	if run[sources.KeyNames] {
		if err := sources.UpdateNames(rctx, cfg); err != nil {
			failed = append(failed, fmt.Errorf("updating name database: %v", err))
		}
	}
	if run[sources.KeyCountry] {
		if err := sources.UpdateCountryDB(rctx, cfg); err != nil {
			failed = append(failed, fmt.Errorf("updating country database: %v", err))
		}
	}
	if run[sources.KeyCity] {
		if err := sources.UpdateCityDB(rctx, cfg); err != nil {
			failed = append(failed, fmt.Errorf("updating city database: %v", err))
		}
	}
	if run[sources.KeyNetblock] {
		if err := sources.UpdateNetblockDB(rctx, cfg); err != nil {
			failed = append(failed, fmt.Errorf("updating netblock database: %v", err))
		}
	}
	// After the netblock database, whose ranges name the feeds.
	if run[sources.KeyGeofeed] {
		if err := sources.UpdateGeofeedDB(rctx, cfg); err != nil {
			failed = append(failed, fmt.Errorf("updating geofeed database: %v", err))
		}
	}
	if run[sources.KeyCategory] {
		contact := sources.NewContactAsker(cfg.ContactPath, sel.ContactEmail)
		if sel.NoPrompt {
			contact.Terminal, contact.Out = false, errOut
		}
		if err := sources.UpdateCategoryDB(rctx, cfg, contact); err != nil {
			failed = append(failed, fmt.Errorf("updating category database: %v", err))
		}
	}
	// Built last, so its per-ASN counts use the ASN database just refreshed.
	if run[sources.KeyReputation] {
		if err := sources.UpdateReputationDB(rctx, cfg); err != nil {
			failed = append(failed, fmt.Errorf("updating reputation database: %v", err))
		}
	}

	if ctx.Err() == nil {
		rec := sources.LoadUpdateRecord(cfg.UpdateRecordPath)
		var incomplete []string
		for _, key := range sources.UpdateKeys {
			if run[key] && rec[key].Incomplete() {
				incomplete = append(incomplete, describeOutcome(key, rec[key]))
			}
		}
		if len(incomplete) > 0 {
			fmt.Fprintf(errOut, "asname: incomplete: %s\nasname: run `asname update --incremental` to retry only these\n", strings.Join(incomplete, ", "))
		}
	}
	return errors.Join(failed...)
}

// describeOutcome names a database and what its last update left out.
func describeOutcome(key string, o sources.UpdateOutcome) string {
	if o.Error != "" {
		return key + " (failed, previous file kept)"
	}
	return key + " (missing " + strings.Join(o.Failed, ", ") + ")"
}

func versionCommand() *cli.Command {
	return &cli.Command{
		Name:   "version",
		Usage:  "print version information and when each database was last updated",
		Action: versionAction,
	}
}

func versionAction(ctx context.Context, cmd *cli.Command) error {
	cfg := newConfig(cmd)
	dbs := sources.DatabaseStatus(cfg)
	maxAge := effectiveMaxAge(cmd, cfg).Age
	now := time.Now()

	if cmd.Bool("json") {
		line, err := format.FormatJSONVersion(version, cmd.String("dir"), maxAge, cfg.IPv6, dbs, now)
		if err != nil {
			return err
		}
		_, err = fmt.Fprint(cmd.Root().Writer, line)
		return err
	}

	out := bufio.NewWriter(cmd.Root().Writer)
	fmt.Fprintf(out, "asname v%s\n\n", version)
	dir := cmd.String("dir")
	refresh := "auto-refresh off"
	if maxAge > 0 {
		refresh = "auto-refreshed when older than " + format.Age(maxAge)
	}
	fmt.Fprintf(out, "Databases in %s (%s):\n", dir, refresh)
	incomplete := false
	for _, db := range dbs {
		name := db.Path
		if filepath.Dir(db.Path) == filepath.Clean(dir) {
			name = filepath.Base(db.Path)
		}
		fmt.Fprintf(out, "  %-14s %-17s ", db.Name, name)
		if !db.Present {
			if db.Optional {
				fmt.Fprintln(out, "not present (optional)")
			} else {
				fmt.Fprintln(out, "not present; run `asname update`")
			}
			continue
		}
		age := now.Sub(db.Updated)
		fmt.Fprintf(out, "updated %s (%s ago)  %s", db.Updated.Format("2006-01-02 15:04"), format.Age(age), format.Bytes(db.Size))
		if !db.Built.IsZero() {
			fmt.Fprintf(out, "  data built %s", db.Built.Format("2006-01-02"))
		}
		if maxAge > 0 && age > maxAge {
			fmt.Fprint(out, "  stale: refreshed on the next lookup")
		}
		fmt.Fprintln(out)
		switch {
		case db.LastError != "":
			fmt.Fprintf(out, "  %-14s last update failed, previous file kept: %s\n", "", db.LastError)
			incomplete = true
		case len(db.Missing) > 0:
			fmt.Fprintf(out, "  %-14s incomplete: missing %s\n", "", strings.Join(db.Missing, ", "))
			incomplete = true
		}
	}
	if incomplete {
		fmt.Fprintln(out, "\nRun `asname update --incremental` to retry what the last update left out.")
	}
	if cfg.IPv6 {
		fmt.Fprintln(out, "\nIPv6 routes: on (`asname update --no-ipv6` to stop importing them)")
	} else {
		fmt.Fprintln(out, "\nIPv6 routes: off (`asname update --ipv6` to import them)")
	}
	return out.Flush()
}
