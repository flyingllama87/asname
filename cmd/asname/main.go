package main

import (
	"bufio"
	"context"
	"errors"
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

SEARCH:
   --org query, -O query          search AS names and registry netblocks by organization name or netname
   --limit value, -l value        maximum number of ASNs, and of netblocks, to display (default: unlimited)
   --asns-only                    only search AS names
   --netblocks-only               only search registry netblocks
   --v4-only                      only display IPv4 netblocks and ASN prefixes in search
   --v6-only                      only display IPv6 netblocks and ASN prefixes in search

DATA FILES & AUTO-UPDATE:
   --dir directory, -d directory  data directory holding the ASN database and name file (default: "/home/mj12/.asname") [$ASNAME_DIR]
   --db file                      asnlookup database file (default: <dir>/asname.db) [$ASNAME_DB]
   --names file                   ASN->name mapping file (default: <dir>/asn_db.txt) [$ASNAME_NAMES]
   --country file                 IP->country database file (default: <dir>/country.db) [$ASNAME_COUNTRY]
   --city-db file                 IP->city database file (default: <dir>/city.mmdb) [$ASNAME_CITY]
   --netblock-db file             IP->netblock database file (default: <dir>/netblock.db) [$ASNAME_NETBLOCK]
   --category-db file             IP->category database file (default: <dir>/category.db) [$ASNAME_CATEGORY]
   --prefix-db file               ASN->prefix database file (default: <dir>/prefixes.db) [$ASNAME_PREFIXES]
   --max-age duration             auto-refresh data older than this duration (0 disables) (default: 720h0m0s)
   --no-update                    never auto-refresh data before a lookup
   --contact-email address        address to identify with when fetching bgp.tools' operator tags [$ASNAME_CONTACT_EMAIL]
   --help, -h                     show help{{end}}
`

	if err := newApp().Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "asname:", err)
		os.Exit(1)
	}
}

// newApp builds the command line app. Actions write results to App.Writer and
// warnings to App.ErrWriter, which default to stdout and stderr.
func newApp() *cli.App {
	return &cli.App{
		Name:      "asname",
		Usage:     "look up the ASN, AS name, country and prefixes of an IP address, hostname, URL or ASN; or search AS names and netblocks by organization",
		ArgsUsage: "<IP|hostname|URL|ASN|file>",
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
				Name:    "org",
				Aliases: []string{"O"},
				Usage:   "search AS names and registry netblocks by organization name or netname",
			},
			&cli.IntFlag{
				Name:        "limit",
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
				Name:  "v4-only",
				Usage: "only display IPv4 netblocks and ASN prefixes in search",
			},
			&cli.BoolFlag{
				Name:  "v6-only",
				Usage: "only display IPv6 netblocks and ASN prefixes in search",
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
			&cli.StringFlag{
				Name:    "prefix-db",
				EnvVars: []string{sources.PrefixEnvVar},
				Usage:   "ASN->prefix database `file` (default: <dir>/" + sources.PrefixFilename + ")",
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
			searchCommand,
			countryCommand,
			cityCommand,
			updateCommand,
			versionCommand,
		},
		Action: lookupAction,
	}
}

// shouldColorize reports whether output written to ctx.App.Writer is colored.
func shouldColorize(ctx *cli.Context) bool {
	f, _ := ctx.App.Writer.(*os.File)
	return format.ShouldColorize(f, searchBool(ctx, "color"), searchBool(ctx, "no-color"))
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
	c.PrefixPath = ctx.String("prefix-db")
	if c.PrefixPath == "" {
		c.PrefixPath = filepath.Join(dir, sources.PrefixFilename)
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

	if ctx.String("org") != "" {
		return runSearch(ctx, ctx.String("org"))
	}

	if ctx.Bool("rest") && ctx.Bool("stream") {
		return fmt.Errorf("--rest and --stream are mutually exclusive")
	}

	isStream := ctx.Bool("stream") || (ctx.NArg() == 1 && ctx.Args().First() == "-")
	isREST := ctx.Bool("rest")

	if !isStream && !isREST && ctx.NArg() != 1 {
		cli.ShowAppHelp(ctx)
		return fmt.Errorf("exactly one IP address, hostname, URL, ASN or file argument is required")
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
		if err := sources.AutoUpdate(sources.WithLog(ctx.Context, ctx.App.ErrWriter), cfg, ctx.Duration("max-age"), wantCity, wantNetblock, wantCategory, contact); err != nil {
			fmt.Fprintln(ctx.App.ErrWriter, "asname: auto-update failed:", err)
		}
	}

	eng, err := engine.NewEngine(cfg, wantCity, wantNetblock, showNetblock, wantCategory, whois, ctx.App.ErrWriter)
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

		useColor := shouldColorize(ctx)
		opts := stream.StreamOptions{
			Format:     fmtMode,
			ReverseDNS: ctx.Bool("reverse-dns"),
			UseColor:   useColor,
		}

		var r io.Reader = ctx.App.Reader
		if ctx.NArg() == 1 && ctx.Args().First() != "-" {
			f, err := os.Open(ctx.Args().First())
			if err != nil {
				return err
			}
			defer f.Close()
			r = f
		}

		return stream.RunStream(context.Background(), r, ctx.App.Writer, eng, opts)
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
			fmt.Fprintf(ctx.App.ErrWriter, "asname: %s: %v\n", t.Raw, err)
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

	out := bufio.NewWriter(ctx.App.Writer)
	uniform := ctx.Bool("uniform")
	isJSON := ctx.Bool("json")
	isPretty := ctx.Bool("pretty")
	useColor := shouldColorize(ctx)

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

var searchCommand = &cli.Command{
	Name:      "search",
	Usage:     "search AS names and registry netblocks by organization name or netname",
	ArgsUsage: "<organization-name>",
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
			Name:    "pretty",
			Aliases: []string{"p"},
			Usage:   "display results in a multi-line formatted card layout with generous whitespace",
		},
		&cli.BoolFlag{
			Name:    "json",
			Aliases: []string{"j"},
			Usage:   "output results as JSON lines (JSONL)",
		},
		&cli.BoolFlag{
			Name:    "uniform",
			Aliases: []string{"u"},
			Usage:   "print output as aligned fields",
		},
		&cli.BoolFlag{
			Name:  "v4-only",
			Usage: "only display IPv4 netblocks and ASN prefixes",
		},
		&cli.BoolFlag{
			Name:  "v6-only",
			Usage: "only display IPv6 netblocks and ASN prefixes",
		},
		&cli.BoolFlag{
			Name:  "color",
			Usage: "force ANSI colored output even when stdout is piped",
		},
		&cli.BoolFlag{
			Name:  "no-color",
			Usage: "suppress ANSI colored output (also respects NO_COLOR env var)",
		},
		&cli.StringFlag{
			Name:    "dir",
			Aliases: []string{"d"},
			EnvVars: []string{sources.DirEnvVar},
			Value:   sources.DefaultDir(),
			Usage:   "data `directory` holding the netblock database",
		},
		&cli.StringFlag{
			Name:    "netblock-db",
			EnvVars: []string{sources.NetblockEnvVar},
			Usage:   "IP->netblock database `file` (default: <dir>/" + sources.NetblockFilename + ")",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("search requires an organization or netname argument")
		}
		return runSearch(c, c.Args().First())
	},
}

func searchBool(ctx *cli.Context, name string) bool {
	if ctx.Bool(name) {
		return true
	}
	for _, parent := range ctx.Lineage() {
		if parent != nil && parent != ctx && parent.Bool(name) {
			return true
		}
	}
	return false
}

func runSearch(ctx *cli.Context, query string) error {
	outputFlags := 0
	if searchBool(ctx, "pretty") {
		outputFlags++
	}
	if searchBool(ctx, "json") {
		outputFlags++
	}
	if searchBool(ctx, "uniform") {
		outputFlags++
	}
	if outputFlags > 1 {
		return fmt.Errorf("--pretty, --json and --uniform are mutually exclusive")
	}

	asnsOnly, netblocksOnly := ctx.Bool("asns-only"), ctx.Bool("netblocks-only")
	if asnsOnly && netblocksOnly {
		return fmt.Errorf("--asns-only and --netblocks-only are mutually exclusive")
	}
	v4Only, v6Only := ctx.Bool("v4-only"), ctx.Bool("v6-only")
	if v4Only && v6Only {
		return fmt.Errorf("--v4-only and --v6-only are mutually exclusive")
	}

	cfg := newConfig(ctx)

	// The AS names need no netblock database, so without one a combined
	// search still answers from them.
	wantNetblock := !asnsOnly
	if wantNetblock && !sources.NetblockDBPresent(cfg.NetblockPath) {
		if netblocksOnly {
			return fmt.Errorf("netblock database is not present; build it with `asname update --netblock-only` or pass `--netblock`")
		}
		fmt.Fprintln(ctx.App.ErrWriter, "asname: netblock database is not present, so only AS names are searched; build it with `asname update --netblock-only`")
		wantNetblock = false
	}

	eng, err := engine.NewEngine(cfg, false, wantNetblock, wantNetblock, false, sources.WhoisNever, ctx.App.ErrWriter)
	if err != nil {
		return err
	}
	defer eng.Close()

	limit := ctx.Int("limit")

	var asns []engine.ASNSearchResult
	if !netblocksOnly {
		asns = eng.SearchASNs(query, limit, v4Only, v6Only)
	}

	var netblocks []engine.NetblockEnrichedResult
	if wantNetblock {
		netblocks, err = eng.SearchNetblocks(query, sources.NetblockSearchOptions{
			Limit:  limit,
			V4Only: v4Only,
			V6Only: v6Only,
		})
		if err != nil {
			return err
		}
	}

	isJSON := searchBool(ctx, "json")
	total := len(asns) + len(netblocks)
	if total == 0 {
		if isJSON {
			return nil
		}
		what := "ASNs or netblocks"
		if asnsOnly || !wantNetblock {
			what = "ASNs"
		} else if netblocksOnly {
			what = "netblocks"
		}
		fmt.Fprintf(ctx.App.ErrWriter, "asname: no %s found matching %q\n", what, query)
		return nil
	}

	out := bufio.NewWriter(ctx.App.Writer)
	uniform := searchBool(ctx, "uniform")
	isPretty := searchBool(ctx, "pretty")
	useColor := shouldColorize(ctx)

	for i, res := range asns {
		if isJSON {
			line, err := format.FormatJSONASNSearchOutput(res)
			if err != nil {
				return err
			}
			fmt.Fprint(out, line)
		} else if isPretty {
			fmt.Fprint(out, format.FormatPrettyASNSearchOutput(res, i, total, useColor))
		} else {
			fmt.Fprint(out, format.FormatASNSearchOutput(res))
		}
	}
	for i, res := range netblocks {
		if isJSON {
			line, err := format.FormatJSONNetblockOutput(res)
			if err != nil {
				return err
			}
			fmt.Fprint(out, line)
		} else if isPretty {
			fmt.Fprint(out, format.FormatPrettyNetblockOutput(res, len(asns)+i, total, useColor))
		} else {
			fmt.Fprint(out, format.FormatNetblockOutput(res, uniform))
		}
	}
	return out.Flush()
}

var countryCommand = &cli.Command{
	Name:      "country",
	Usage:     "list every IP block (CIDR) registered to a country",
	ArgsUsage: "<country-code|country-name>...",
	Description: "Prints the minimal CIDR blocks the country database assigns to each country, one per line.\n" +
		"The database comes from the RIR delegation files, so a block is listed under the country its\n" +
		"holder registered it in, which is not always where its addresses are used.",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "pretty",
			Aliases: []string{"p"},
			Usage:   "display each country as a card with block counts",
		},
		&cli.BoolFlag{
			Name:    "json",
			Aliases: []string{"j"},
			Usage:   "output one JSON object per block (JSONL)",
		},
		&cli.BoolFlag{
			Name:  "v4-only",
			Usage: "only list IPv4 blocks",
		},
		&cli.BoolFlag{
			Name:  "v6-only",
			Usage: "only list IPv6 blocks",
		},
		&cli.BoolFlag{
			Name:  "color",
			Usage: "force ANSI colored output even when stdout is piped",
		},
		&cli.BoolFlag{
			Name:  "no-color",
			Usage: "suppress ANSI colored output (also respects NO_COLOR env var)",
		},
		&cli.StringFlag{
			Name:    "dir",
			Aliases: []string{"d"},
			EnvVars: []string{sources.DirEnvVar},
			Value:   sources.DefaultDir(),
			Usage:   "data `directory` holding the country database",
		},
		&cli.StringFlag{
			Name:    "country-db",
			EnvVars: []string{sources.CountryEnvVar},
			Usage:   "IP->country database `file` (default: <dir>/" + sources.CountryFilename + ")",
		},
	},
	Action: countryAction,
}

func countryAction(ctx *cli.Context) error {
	if ctx.NArg() == 0 {
		cli.ShowSubcommandHelp(ctx)
		return fmt.Errorf("country requires a country code or name, such as AU or Australia")
	}
	isJSON, isPretty := searchBool(ctx, "json"), searchBool(ctx, "pretty")
	if isJSON && isPretty {
		return fmt.Errorf("--pretty and --json are mutually exclusive")
	}
	v4Only, v6Only := ctx.Bool("v4-only"), ctx.Bool("v6-only")
	if v4Only && v6Only {
		return fmt.Errorf("--v4-only and --v6-only are mutually exclusive")
	}

	cfg := newConfig(ctx)
	if path := ctx.String("country-db"); path != "" {
		cfg.CountryPath = path
	}
	eng, err := engine.NewEngine(cfg, false, false, false, false, sources.WhoisNever, ctx.App.ErrWriter)
	if err != nil {
		return err
	}
	defer eng.Close()

	out := bufio.NewWriter(ctx.App.Writer)
	useColor := shouldColorize(ctx)
	for i, arg := range ctx.Args().Slice() {
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
			fmt.Fprintf(ctx.App.ErrWriter, "asname: no blocks registered to %s\n", cc)
			continue
		}

		switch {
		case isPretty:
			country := cc
			if name, ok := sources.CountryNames[cc]; ok {
				country = cc + ", " + name
			}
			fmt.Fprint(out, format.FormatPrettyCountryOutput(country, v4, v6, i, ctx.NArg(), useColor))
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

var cityCommand = &cli.Command{
	Name:      "city",
	Usage:     "list every IP block (CIDR) the city database locates in a city",
	ArgsUsage: "<city>[, <region|country>]...",
	Description: "Prints the minimal CIDR blocks the DB-IP Lite city database locates in each city, one per line.\n" +
		"A name several places share, such as Brisbane, lists them all; add a region, country code or\n" +
		"country name to pick one, as in \"Brisbane, AU\" or \"Brisbane, Queensland\". The locations are\n" +
		"geolocation estimates, so expect some blocks to be missing or misplaced. Needs the city database\n" +
		"(~125MB); download it with `asname update --city-only`.",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "pretty",
			Aliases: []string{"p"},
			Usage:   "display each place as a card with block counts",
		},
		&cli.BoolFlag{
			Name:    "json",
			Aliases: []string{"j"},
			Usage:   "output one JSON object per block (JSONL)",
		},
		&cli.BoolFlag{
			Name:  "v4-only",
			Usage: "only list IPv4 blocks",
		},
		&cli.BoolFlag{
			Name:  "v6-only",
			Usage: "only list IPv6 blocks",
		},
		&cli.BoolFlag{
			Name:  "color",
			Usage: "force ANSI colored output even when stdout is piped",
		},
		&cli.BoolFlag{
			Name:  "no-color",
			Usage: "suppress ANSI colored output (also respects NO_COLOR env var)",
		},
		&cli.StringFlag{
			Name:    "dir",
			Aliases: []string{"d"},
			EnvVars: []string{sources.DirEnvVar},
			Value:   sources.DefaultDir(),
			Usage:   "data `directory` holding the city database",
		},
		&cli.StringFlag{
			Name:    "city-db",
			EnvVars: []string{sources.CityEnvVar},
			Usage:   "IP->city database `file` (default: <dir>/" + sources.CityFilename + ")",
		},
	},
	Action: cityAction,
}

func cityAction(ctx *cli.Context) error {
	if ctx.NArg() == 0 {
		cli.ShowSubcommandHelp(ctx)
		return fmt.Errorf("city requires a city name, such as Brisbane or \"Brisbane, AU\"")
	}
	isJSON, isPretty := searchBool(ctx, "json"), searchBool(ctx, "pretty")
	if isJSON && isPretty {
		return fmt.Errorf("--pretty and --json are mutually exclusive")
	}
	v4Only, v6Only := ctx.Bool("v4-only"), ctx.Bool("v6-only")
	if v4Only && v6Only {
		return fmt.Errorf("--v4-only and --v6-only are mutually exclusive")
	}

	cfg := newConfig(ctx)
	if path := ctx.String("city-db"); path != "" {
		cfg.CityPath = path
	}
	if !sources.CityDBPresent(cfg.CityPath) {
		return fmt.Errorf("city database is not present; download it (~125MB) with `asname update --city-only`")
	}
	eng, err := engine.NewEngine(cfg, true, false, false, false, sources.WhoisNever, ctx.App.ErrWriter)
	if err != nil {
		return err
	}
	defer eng.Close()

	var places []sources.CityPlace
	for _, arg := range ctx.Args().Slice() {
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
			fmt.Fprintf(ctx.App.ErrWriter, "asname: no blocks located in %q\n", arg)
		case len(found) > 1:
			fmt.Fprintf(ctx.App.ErrWriter, "asname: %q matches %d places, so all are listed; add a region or country to pick one:\n", arg, len(found))
			for _, p := range found {
				fmt.Fprintf(ctx.App.ErrWriter, "asname:   %s, %s (%d blocks)\n", sources.FormatCity(p.City, p.Region), p.Country, len(p.IPv4)+len(p.IPv6))
			}
		}
		places = append(places, found...)
	}

	out := bufio.NewWriter(ctx.App.Writer)
	useColor := shouldColorize(ctx)
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
	rctx := sources.WithLog(ctx.Context, ctx.App.ErrWriter)
	for _, dir := range []string{cfg.DBPath, cfg.NamesPath, cfg.CountryPath, cfg.CityPath, cfg.NetblockPath, cfg.CategoryPath, cfg.PrefixPath} {
		if dir != "" {
			if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
				return err
			}
		}
	}

	dbOnly := ctx.Bool("db-only")
	namesOnly := ctx.Bool("names-only")
	countryOnly := ctx.Bool("country-only")
	cityOnly := ctx.Bool("city-only")
	netblockOnly := ctx.Bool("netblock-only")
	categoryOnly := ctx.Bool("category-only")
	all := !dbOnly && !namesOnly && !countryOnly && !cityOnly && !netblockOnly && !categoryOnly

	// A database that fails keeps its existing file; the others are still
	// rebuilt, since they come from different hosts.
	var failed []error
	if all || dbOnly {
		if err := sources.UpdateDatabase(rctx, cfg, ctx.String("rib-url")); err != nil {
			failed = append(failed, fmt.Errorf("updating ASN database: %v", err))
		}
	}
	if all || namesOnly {
		if err := sources.UpdateNames(rctx, cfg); err != nil {
			failed = append(failed, fmt.Errorf("updating name database: %v", err))
		}
	}
	if all || countryOnly {
		if err := sources.UpdateCountryDB(rctx, cfg); err != nil {
			failed = append(failed, fmt.Errorf("updating country database: %v", err))
		}
	}
	if cityOnly || ctx.Bool("city") || (all && sources.CityDBPresent(cfg.CityPath)) {
		if err := sources.UpdateCityDB(rctx, cfg); err != nil {
			failed = append(failed, fmt.Errorf("updating city database: %v", err))
		}
	}
	if netblockOnly || ctx.Bool("netblock") || (all && sources.NetblockDBPresent(cfg.NetblockPath)) {
		if err := sources.UpdateNetblockDB(rctx, cfg); err != nil {
			failed = append(failed, fmt.Errorf("updating netblock database: %v", err))
		}
	}
	if categoryOnly || ctx.Bool("category") || (all && sources.CategoryDBPresent(cfg.CategoryPath)) {
		contact := sources.NewContactAsker(cfg.ContactPath, ctx.String("contact-email"))
		if err := sources.UpdateCategoryDB(rctx, cfg, contact); err != nil {
			failed = append(failed, fmt.Errorf("updating category database: %v", err))
		}
	}
	return errors.Join(failed...)
}

var versionCommand = &cli.Command{
	Name:  "version",
	Usage: "print version information and exit",
	Action: func(ctx *cli.Context) error {
		fmt.Fprintf(ctx.App.Writer, "asname v%s\n", version)
		return nil
	},
}
