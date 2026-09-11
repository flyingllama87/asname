package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v2"

	"github.com/flyingllama87/asname/internal/engine"
	"github.com/flyingllama87/asname/internal/format"
	"github.com/flyingllama87/asname/internal/rest"
	"github.com/flyingllama87/asname/internal/sources"
	"github.com/flyingllama87/asname/internal/stream"
)

var version = "dev"

func main() {
	sources.Version = version

	cli.AppHelpTemplate = `NAME:
   {{.Name}}{{if .Usage}} - {{.Usage}}{{end}}

USAGE:
   {{if .UsageText}}{{.UsageText}}{{else}}{{.HelpName}} {{if .VisibleFlags}}[options]{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments...]{{end}}{{end}}{{if .VisibleCommands}}

COMMANDS:{{range .VisibleCategories}}{{if .Name}}
   {{.Name}}:{{range .VisibleCommands}}
     {{join .Names ", "}}{{"\t"}}{{.Usage}}{{end}}{{else}}{{range .VisibleCommands}}
   {{join .Names ", "}}{{"\t"}}{{.Usage}}{{end}}{{end}}{{end}}{{end}}{{if .VisibleFlags}}

OUTPUT FORMATTING:
   --pretty, -p                   display output in a multi-line formatted card layout with generous whitespace
   --json, -j                     output lookup results as JSON lines (JSONL)
   --uniform, -u                  print lookup output as aligned fields
   --color                        force ANSI colored output even when stdout is piped
   --no-color                     suppress ANSI colored output (also respects NO_COLOR env var)

EXECUTION MODES:
   --stream, -s                   stream and resolve targets line-by-line from stdin in real-time
   --rest                         run in foreground as an HTTP REST API server
   --listen value, -l value       network address and port to bind for the REST API server (default: "127.0.0.1:8086") [$ASNAME_LISTEN]
   --cors                         enable permissive CORS headers on the REST API server

OPTIONAL LOOKUPS & METADATA:
   --reverse-dns, -r              also query reverse DNS and include PTR names in the output
   --city, -c                     include the city, downloading the city database (~125MB) if absent; once present it is used without this flag
   --no-city                      omit the city even when the city database is present
   --netblock, -n                 include the registry netblock and its owner, building the database (~300MB of downloads) if absent; once present it is used without this flag
   --no-netblock                  omit the netblock even when the netblock database is present
   --whois                        look up addresses the offline netblock database cannot name (ARIN and LACNIC) over whois, without asking [$ASNAME_WHOIS]
   --no-whois                     never query whois, and do not ask
   --category, -C                 include what kind of network it is (cloud, CDN, hosting, ISP...), building the database if absent; once present it is used without this flag
   --no-category                  omit the category even when the category database is present

DATA FILES & AUTO-UPDATE:
   --dir directory, -d directory  data directory holding the ASN database and name file (default: "/home/mj12/.asname") [$ASNAME_DIR]
   --db file                      asnlookup database file (default: <dir>/asname.db) [$ASNAME_DB]
   --names file                   ASN->name mapping file (default: <dir>/asn_db.txt) [$ASNAME_NAMES]
   --country file                 IP->country database file (default: <dir>/country.db) [$ASNAME_COUNTRY]
   --city-db file                 IP->city database file (default: <dir>/city.mmdb) [$ASNAME_CITY]
   --netblock-db file             IP->netblock database file (default: <dir>/netblock.db) [$ASNAME_NETBLOCK]
   --category-db file             IP->category database file (default: <dir>/category.db) [$ASNAME_CATEGORY]
   --max-age duration             auto-refresh data older than this duration (0 disables) (default: 720h0m0s)
   --no-update                    never auto-refresh data before a lookup
   --contact-email address        address to identify with when fetching bgp.tools' operator tags [$ASNAME_CONTACT_EMAIL]
   --help, -h                     show help{{end}}
`

	app := &cli.App{
		Name:      "asname",
		Usage:     "look up the ASN, AS name and country of an IP address, hostname or URL",
		ArgsUsage: "<IP|hostname|URL|file>",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "pretty",
				Aliases: []string{"p"},
				Usage:   "display output in a multi-line formatted card layout with generous whitespace",
			},
			&cli.BoolFlag{
				Name:    "json",
				Aliases: []string{"j"},
				Usage:   "output lookup results as JSON lines (JSONL)",
			},
			&cli.BoolFlag{
				Name:    "uniform",
				Aliases: []string{"u"},
				Usage:   "print lookup output as aligned fields",
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
				Name:    "reverse-dns",
				Aliases: []string{"r"},
				Usage:   "also query reverse DNS and include PTR names in the output",
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
				Name:    "whois",
				EnvVars: []string{"ASNAME_WHOIS"},
				Usage:   "look up addresses the offline netblock database cannot name (ARIN and LACNIC) over whois, without asking",
			},
			&cli.BoolFlag{
				Name:  "no-whois",
				Usage: "never query whois, and do not ask",
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
				Name:    "dir",
				Aliases: []string{"d"},
				EnvVars: []string{sources.DirEnvVar},
				Value:   sources.DefaultDir(),
				Usage:   "data `directory` holding the ASN database and name file",
			},
			&cli.StringFlag{
				Name:    "db",
				EnvVars: []string{sources.DBEnvVar},
				Usage:   "asnlookup database `file` (default: <dir>/" + sources.DBFilename + ")",
			},
			&cli.StringFlag{
				Name:    "names",
				EnvVars: []string{sources.NamesEnvVar},
				Usage:   "ASN->name mapping `file` (default: <dir>/" + sources.NamesFilename + ")",
			},
			&cli.StringFlag{
				Name:    "country",
				EnvVars: []string{sources.CountryEnvVar},
				Usage:   "IP->country database `file` (default: <dir>/" + sources.CountryFilename + ")",
			},
			&cli.StringFlag{
				Name:    "city-db",
				EnvVars: []string{sources.CityEnvVar},
				Usage:   "IP->city database `file` (default: <dir>/" + sources.CityFilename + ")",
			},
			&cli.StringFlag{
				Name:    "netblock-db",
				EnvVars: []string{sources.NetblockEnvVar},
				Usage:   "IP->netblock database `file` (default: <dir>/" + sources.NetblockFilename + ")",
			},
			&cli.StringFlag{
				Name:    "category-db",
				EnvVars: []string{sources.CategoryEnvVar},
				Usage:   "IP->category database `file` (default: <dir>/" + sources.CategoryFilename + ")",
			},
			&cli.DurationFlag{
				Name:  "max-age",
				Value: sources.DefaultMaxAge,
				Usage: "auto-refresh data older than this `duration` (0 disables)",
			},
			&cli.BoolFlag{
				Name:  "no-update",
				Usage: "never auto-refresh data before a lookup",
			},
			&cli.StringFlag{
				Name:    "contact-email",
				EnvVars: []string{sources.ContactEnvVar},
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

func newConfig(ctx *cli.Context) sources.Config {
	dir := ctx.String("dir")
	c := sources.Config{
		DBPath:       ctx.String("db"),
		NamesPath:    ctx.String("names"),
		CountryPath:  ctx.String("country"),
		CityPath:     ctx.String("city-db"),
		NetblockPath: ctx.String("netblock-db"),
		CategoryPath: ctx.String("category-db"),
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
	c.CachePath = filepath.Join(dir, sources.CacheDirName)
	c.ConsentPath = filepath.Join(dir, sources.WhoisConsentFilename)
	c.ContactPath = filepath.Join(dir, sources.ContactFilename)
	return c
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

	wantCity := !ctx.Bool("no-city") && (ctx.Bool("city") || sources.CityDBPresent(cfg.CityPath))
	wantNetblock := !ctx.Bool("no-netblock") && (ctx.Bool("netblock") || sources.NetblockDBPresent(cfg.NetblockPath))

	whois := sources.WhoisAsk
	if isStream || isREST {
		// In continuous stream or REST server modes, never ask interactively.
		// Use whois only if explicitly opted in via --whois or ASNAME_WHOIS.
		whois = sources.WhoisNever
	}
	switch {
	case ctx.Bool("no-whois") || ctx.Bool("no-netblock"):
		whois = sources.WhoisNever
	case ctx.Bool("whois"):
		whois = sources.WhoisAlways
	}
	showNetblock := wantNetblock || whois == sources.WhoisAlways
	wantCategory := !ctx.Bool("no-category") && (ctx.Bool("category") || sources.CategoryDBPresent(cfg.CategoryPath))

	if !ctx.Bool("no-update") {
		contact := sources.NewContactAsker(cfg.ContactPath, ctx.String("contact-email"))
		if err := sources.AutoUpdate(cfg, ctx.Duration("max-age"), wantCity, wantNetblock, wantCategory, contact); err != nil {
			fmt.Fprintln(os.Stderr, "asname: auto-update failed:", err)
		}
	}

	eng, err := engine.NewEngine(cfg, wantCity, wantNetblock, showNetblock, wantCategory, whois)
	if err != nil {
		return err
	}
	defer eng.Close()

	if isREST {
		server := rest.NewServer(eng, ctx.String("listen"), ctx.Bool("cors"), ctx.Bool("reverse-dns"), version)
		return server.Start(context.Background())
	}

	if isStream {
		fmtMode := format.FormatDefault
		switch {
		case ctx.Bool("json"):
			fmtMode = format.FormatJSON
		case ctx.Bool("pretty"):
			fmtMode = format.FormatPretty
		case ctx.Bool("uniform"):
			fmtMode = format.FormatUniform
		}

		useColor := format.ShouldColorize(os.Stdout, ctx.Bool("color"), ctx.Bool("no-color"))
		opts := stream.StreamOptions{
			Format:     fmtMode,
			ReverseDNS: ctx.Bool("reverse-dns"),
			UseColor:   useColor,
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

		return stream.RunStream(context.Background(), r, os.Stdout, eng, opts)
	}

	targets, err := engine.ParseTargets(ctx.Args().First())
	if err != nil {
		return err
	}

	engine.ResolveTargets(context.Background(), targets)

	results := make([]engine.LookupResult, 0, len(targets))
	showHost := false
	failures := 0
	for _, t := range targets {
		found, err := eng.LookupTarget(t)
		if err != nil {
			if len(targets) == 1 {
				return err
			}
			fmt.Fprintf(os.Stderr, "asname: %s: %v\n", t.Raw, err)
			failures++
			continue
		}
		if t.Host != "" {
			showHost = true
		}
		results = append(results, found...)
	}

	if ctx.Bool("reverse-dns") {
		engine.ResolveReverseDNS(context.Background(), results)
	}

	out := bufio.NewWriter(os.Stdout)
	uniform := ctx.Bool("uniform")
	isJSON := ctx.Bool("json")
	isPretty := ctx.Bool("pretty")
	useColor := format.ShouldColorize(os.Stdout, ctx.Bool("color"), ctx.Bool("no-color"))

	for i, res := range results {
		if isJSON {
			line, err := format.FormatJSONLookupOutput(res)
			if err != nil {
				return err
			}
			fmt.Fprint(out, line)
		} else if isPretty {
			fmt.Fprint(out, format.FormatPrettyLookupOutput(res, i, len(results), useColor))
		} else {
			fmt.Fprint(out, format.FormatLookupOutput(res, uniform, showHost))
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
		&cli.StringFlag{
			Name:  "rib-url",
			Usage: "download the RIB MRT dump from this `URL` (.bz2 or .gz) instead of trying RouteViews then RIPE RIS",
		},
	},
	Action: updateAction,
}

func updateAction(ctx *cli.Context) error {
	cfg := newConfig(ctx)
	for _, dir := range []string{cfg.DBPath, cfg.NamesPath, cfg.CountryPath, cfg.CityPath, cfg.NetblockPath, cfg.CategoryPath} {
		if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
			return err
		}
	}

	dbOnly := ctx.Bool("db-only")
	namesOnly := ctx.Bool("names-only")
	countryOnly := ctx.Bool("country-only")
	cityOnly := ctx.Bool("city-only")
	netblockOnly := ctx.Bool("netblock-only")
	categoryOnly := ctx.Bool("category-only")
	all := !dbOnly && !namesOnly && !countryOnly && !cityOnly && !netblockOnly && !categoryOnly

	if all || dbOnly {
		if err := sources.UpdateDatabase(cfg, ctx.String("rib-url")); err != nil {
			return fmt.Errorf("updating ASN database: %v", err)
		}
	}
	if all || namesOnly {
		if err := sources.UpdateNames(cfg); err != nil {
			return fmt.Errorf("updating name database: %v", err)
		}
	}
	if all || countryOnly {
		if err := sources.UpdateCountryDB(cfg); err != nil {
			return fmt.Errorf("updating country database: %v", err)
		}
	}
	if cityOnly || ctx.Bool("city") || (all && sources.CityDBPresent(cfg.CityPath)) {
		if err := sources.UpdateCityDB(cfg); err != nil {
			return fmt.Errorf("updating city database: %v", err)
		}
	}
	if netblockOnly || ctx.Bool("netblock") || (all && sources.NetblockDBPresent(cfg.NetblockPath)) {
		if err := sources.UpdateNetblockDB(cfg); err != nil {
			return fmt.Errorf("updating netblock database: %v", err)
		}
	}
	if categoryOnly || ctx.Bool("category") || (all && sources.CategoryDBPresent(cfg.CategoryPath)) {
		contact := sources.NewContactAsker(cfg.ContactPath, ctx.String("contact-email"))
		if err := sources.UpdateCategoryDB(cfg, contact); err != nil {
			return fmt.Errorf("updating category database: %v", err)
		}
	}
	return nil
}

var versionCommand = &cli.Command{
	Name:  "version",
	Usage: "print version information and exit",
	Action: func(_ *cli.Context) error {
		fmt.Printf("asname v%s\n", version)
		return nil
	},
}
