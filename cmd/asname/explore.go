package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/flyingllama87/asname/internal/engine"
	"github.com/flyingllama87/asname/internal/format"
	"github.com/flyingllama87/asname/internal/sources"
)

// exploreCommand lists announced prefixes by size, country, kind of network
// and reputation, as the web UI's Explore tab does.
func exploreCommand() *cli.Command {
	return &cli.Command{
		Name:  "explore",
		Usage: "list announced prefixes filtered by size, country, kind of network and reputation",
		Description: "Every prefix in the routing table, with its origin AS, registry country, tags and blocklist hits.\n" +
			"Examples:\n" +
			"  asname explore --len 8\n" +
			"  asname explore --in AU --reputation drop\n" +
			"  asname explore --tag hosting --min-ipsum 3 --sort listed --ips-only",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "len", Usage: "prefix `length`, such as 8, or a range, such as 16-24"},
			&cli.StringFlag{Name: "in", Usage: "only prefixes registered in `country` (a code such as AU, or a name)"},
			&cli.StringFlag{Name: "as-in", Usage: "only prefixes whose origin AS is registered in `country`"},
			&cli.StringFlag{Name: "asn", Usage: "only prefixes announced by `AS`"},
			&cli.StringSliceFlag{Name: "tag", Usage: "only prefixes with any of these kinds of network (`tag`: hosting, vpn, isp...); repeat or separate with commas"},
			&cli.StringFlag{Name: "reputation", Usage: "`filter`: listed, clean, drop (all of the prefix), drop-inside, asn-drop, firehol2, firehol3"},
			&cli.IntFlag{Name: "min-ipsum", Usage: "only prefixes holding an address on at least `N` IPsum feeds"},
			&cli.FloatFlag{Name: "min-listed-pct", Usage: "only prefixes with at least `P` percent of their addresses listed"},
			&cli.StringFlag{Name: "sort", Value: "address", Usage: "address, size (largest first), listed or share"},
			&cli.IntFlag{Name: "limit", Aliases: []string{"l"}, Value: 500, Usage: "at most `N` prefixes (0 for all)"},
			&cli.BoolFlag{Name: "ips-only", Usage: "only print the prefixes, one per line"},
			&cli.BoolFlag{Name: "count", Usage: "only print how many match, and what they break down into"},
		},
		Action: exploreAction,
	}
}

func exploreAction(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() > 0 {
		return fmt.Errorf("explore takes only flags; see `asname explore --help`")
	}
	var o engine.ExploreOptions
	var err error
	if v := cmd.String("len"); v != "" {
		a, b, rng := strings.Cut(strings.ReplaceAll(v, "/", ""), "-")
		lo, err1 := strconv.Atoi(strings.TrimSpace(a))
		hi, err2 := lo, error(nil)
		if rng {
			hi, err2 = strconv.Atoi(strings.TrimSpace(b))
		}
		if err1 != nil || err2 != nil || lo < 0 || hi > 128 || lo > hi {
			return fmt.Errorf("--len must be a prefix length such as 8 or a range such as 16-24")
		}
		o.MinLen, o.MaxLen = lo, hi
	}
	if v := cmd.String("in"); v != "" {
		if o.Country, err = sources.ParseCountry(v); err != nil {
			return err
		}
	}
	if v := cmd.String("as-in"); v != "" {
		if o.ASCountry, err = sources.ParseCountry(v); err != nil {
			return err
		}
	}
	if v := cmd.String("asn"); v != "" {
		n, ok := engine.ParseASNTarget(v)
		if !ok {
			return fmt.Errorf("--asn must be an AS number such as AS13335")
		}
		o.ASN = n
	}
	for _, t := range cmd.StringSlice("tag") {
		for _, x := range strings.Split(t, ",") {
			if x = strings.TrimSpace(x); x != "" {
				o.Tags = append(o.Tags, x)
			}
		}
	}
	o.Reputation = cmd.String("reputation")
	if !engine.ValidExploreReputation(o.Reputation) {
		return fmt.Errorf("--reputation must be listed, clean, drop, drop-inside, asn-drop, firehol2 or firehol3")
	}
	o.MinIPsum = int(cmd.Int("min-ipsum"))
	o.MinListedPct = cmd.Float("min-listed-pct")
	switch o.Sort = cmd.String("sort"); o.Sort {
	case "address", "size", "listed", "share":
	default:
		return fmt.Errorf("--sort must be address, size, listed or share")
	}
	o.Limit = int(cmd.Int("limit"))
	o.V4Only, o.V6Only = anyBool(cmd, "v4-only"), anyBool(cmd, "v6-only")
	if cmd.Bool("count") {
		o.Limit = 1
	}

	cfg := newConfig(cmd)
	eng, err := engine.NewEngine(cfg, false, false, false, sources.CategoryDBPresent(cfg.CategoryPath), sources.ReputationDBPresent(cfg.ReputationPath), sources.WhoisNever, cmd.Root().ErrWriter)
	if err != nil {
		return err
	}
	defer eng.Close()
	res, err := eng.Explore(o)
	if err != nil {
		return err
	}

	out := bufio.NewWriter(cmd.Root().Writer)
	defer out.Flush()
	if cmd.Bool("count") {
		fmt.Fprintf(out, "%d prefixes, %d IPv4 addresses\n", res.Total, res.Addresses)
		for _, f := range []struct {
			name string
			list []engine.ExploreFacet
		}{{"Countries", res.Countries}, {"Kinds", res.Tags}, {"Origin ASes", res.ASNs}} {
			if len(f.list) == 0 {
				continue
			}
			parts := make([]string, len(f.list))
			for i, x := range f.list {
				parts[i] = fmt.Sprintf("%s %d", x.Label, x.Count)
				if x.Label != x.Value {
					parts[i] = fmt.Sprintf("%s (%s) %d", x.Label, x.Value, x.Count)
				}
			}
			fmt.Fprintf(out, "%s: %s\n", f.name, strings.Join(parts, "; "))
		}
		return nil
	}
	if cmd.Bool("json") {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(format.NewJSONExplore(res, 0))
	}
	for _, p := range res.Prefixes {
		if cmd.Bool("ips-only") {
			fmt.Fprintln(out, p.Prefix)
			continue
		}
		cc, _, _ := strings.Cut(p.Country, ",")
		fmt.Fprintf(out, "%-20s AS%-10d %-2s  %-30s %s\n", p.Prefix, p.ASN, cc, strings.Join(p.Tags, ","), exploreRep(p))
	}
	if !cmd.Bool("ips-only") && res.Total > len(res.Prefixes) {
		fmt.Fprintf(cmd.Root().ErrWriter, "asname: showing %d of %d; raise --limit (0 for all)\n", len(res.Prefixes), res.Total)
	}
	return nil
}

func exploreRep(p engine.ExplorePrefix) string {
	var parts []string
	switch {
	case p.Drop:
		parts = append(parts, "Spamhaus DROP "+strings.Join(p.SBL, " "))
	case p.DropInside:
		parts = append(parts, "contains Spamhaus DROP "+strings.Join(p.SBL, " "))
	}
	if p.ASNDrop {
		parts = append(parts, "origin AS on ASN-DROP")
	}
	if p.FireHOL2 {
		parts = append(parts, "FireHOL L2")
	} else if p.FireHOL3 {
		parts = append(parts, "FireHOL L3")
	}
	if p.ListedIPs > 0 {
		s := fmt.Sprintf("%d listed", p.ListedIPs)
		if p.Addresses > 0 {
			s += " (" + sources.FormatShare(p.ListedSharePct) + ")"
		}
		if p.MaxIPsum > 0 {
			s += fmt.Sprintf(", IPsum max %d", p.MaxIPsum)
		}
		parts = append(parts, s)
	}
	if len(parts) == 0 {
		return "not listed"
	}
	return strings.Join(parts, "; ")
}
