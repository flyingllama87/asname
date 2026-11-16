package engine

import (
	"context"
	"errors"
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

	"github.com/flyingllama87/asname/internal/sources"
	"github.com/flyingllama87/asname/pkg/database"
)

// Engine holds the databases for the run so that a batch of lookups parses them once.
type Engine struct {
	db           database.Database
	names        map[uint32]string
	countryDB    database.Database
	cityDB       *maxminddb.Reader
	netblockDB   *sources.NetblockDB
	showNetblock bool
	whois        *sources.WhoisAsker
	// rdap answers the online netblock lookup, falling back to whois. It
	// is shared by the views WithOnline returns.
	rdap         *sources.RDAPClient
	categoryDB   *sources.CategoryDB
	reputationDB *sources.ReputationDB
	// asnReps caches asnReputation's results, as counting an ASN's announced
	// space reads all of its prefixes; stream and REST lookups run concurrently.
	// It is shared by the views WithOnline returns.
	asnReps  *sync.Map
	prefixDB *sources.PrefixDB
	log      io.Writer

	// onlinePrefixes decides whether LookupASN may ask RIPEstat for an ASN's
	// announced prefixes when the prefix database does not cover it. It is
	// off until SetOnlinePrefixes says otherwise.
	onlinePrefixes *sources.PrefixAsker
}

// NewEngine opens the databases cfg names. Warnings about optional databases
// that could not be opened, and about failed whois lookups, go to log; a nil
// log discards them.
func NewEngine(cfg sources.Config, wantCity, wantNetblock, showNetblock, wantCategory, wantReputation bool, whois sources.WhoisMode, log io.Writer) (*Engine, error) {
	if log == nil {
		log = io.Discard
	}
	dbFile, err := os.Open(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("opening ASN database (run `asname update`): %v", err)
	}
	defer dbFile.Close()
	db, err := database.NewFromDump(dbFile)
	if err != nil {
		return nil, fmt.Errorf("parsing ASN database: %v", err)
	}

	names, err := sources.LoadNames(cfg.NamesPath)
	if err != nil {
		return nil, fmt.Errorf("loading name database (run `asname update`): %v", err)
	}

	countryDB, err := sources.LoadCountryDB(cfg.CountryPath)
	if err != nil {
		fmt.Fprintln(log, "asname: country database unavailable (run `asname update`):", err)
		countryDB = nil
	}

	var cityDB *maxminddb.Reader
	if wantCity {
		if cityDB, err = sources.LoadCityDB(cfg.CityPath); err != nil {
			fmt.Fprintln(log, "asname: city database unavailable (run `asname update --city-only`):", err)
			cityDB = nil
		}
	}

	var nbDB *sources.NetblockDB
	if wantNetblock {
		if nbDB, err = sources.OpenNetblockDB(cfg.NetblockPath); err != nil {
			fmt.Fprintln(log, "asname: netblock database unavailable (run `asname update --netblock-only`):", err)
			nbDB = nil
		}
	}

	var catDB *sources.CategoryDB
	if wantCategory {
		if catDB, err = sources.OpenCategoryDB(cfg.CategoryPath); err != nil {
			fmt.Fprintln(log, "asname: category database unavailable (run `asname update --category-only`):", err)
			catDB = nil
		}
	}

	var repDB *sources.ReputationDB
	if wantReputation {
		if repDB, err = sources.OpenReputationDB(cfg.ReputationPath); err != nil {
			fmt.Fprintln(log, "asname: reputation database unavailable (run `asname update --reputation-only`):", err)
			repDB = nil
		}
	}

	whoisAsker := sources.NewWhoisAsker(cfg.ConsentPath, whois)
	if whois != sources.WhoisAsk {
		// Only the interactive mode owns the terminal; the others report the
		// rate-limit cutoff like any other warning.
		whoisAsker.Out = log
	}

	var prefixDB *sources.PrefixDB
	if cfg.PrefixPath != "" && sources.PrefixDBPresent(cfg.PrefixPath) {
		if prefixDB, err = sources.OpenPrefixDB(cfg.PrefixPath); err != nil {
			prefixDB = nil
		}
	}

	return &Engine{
		db:             db,
		names:          names,
		countryDB:      countryDB,
		cityDB:         cityDB,
		netblockDB:     nbDB,
		showNetblock:   showNetblock,
		whois:          whoisAsker,
		rdap:           sources.NewRDAPClient(rdapCacheDir(cfg.ConsentPath)),
		categoryDB:     catDB,
		reputationDB:   repDB,
		prefixDB:       prefixDB,
		log:            log,
		onlinePrefixes: sources.NewPrefixAsker(cfg.PrefixConsentPath, sources.WhoisNever),
		asnReps:        &sync.Map{},
	}, nil
}

// Online says whether a lookup may go to the network for what the offline
// databases lack: whois for an address's netblock, and RIPEstat for an
// ASN's announced prefixes.
type Online struct {
	Whois    bool
	Prefixes bool
}

// WithOnline returns a view of e whose lookups query whois and RIPEstat as
// online says, instead of as e was opened. The view shares e's databases;
// it has its own allowance of whois queries (MaxWhoisQueries), so each
// request to a long-running server gets a fresh one. Close e, not the view.
func (e *Engine) WithOnline(online Online) *Engine {
	v := *e
	whois := sources.WhoisNever
	if online.Whois {
		whois = sources.WhoisAlways
	}
	v.whois = sources.NewWhoisAsker("", whois)
	v.whois.Out = e.log
	// Asking for whois shows the netblock even without the netblock
	// database, as --whois does.
	v.showNetblock = e.showNetblock || online.Whois
	prefixes := sources.WhoisNever
	if online.Prefixes {
		prefixes = sources.WhoisAlways
	}
	v.onlinePrefixes = sources.NewPrefixAsker("", prefixes)
	v.onlinePrefixes.Out = e.log
	return &v
}

// OnlinePrefixMode reports how LookupASN treats prefixes the database lacks.
func (e *Engine) OnlinePrefixMode() sources.WhoisMode { return e.onlinePrefixes.Mode }

// SetOnlinePrefixes sets whether LookupASN may query RIPEstat for prefixes
// the prefix database lacks: always, never, or after asking on the terminal.
// Only a question actually put to the terminal writes to it directly; the
// hint given in its place without one goes to the log like any warning.
func (e *Engine) SetOnlinePrefixes(mode sources.WhoisMode) {
	e.onlinePrefixes.Mode = mode
	if mode != sources.WhoisAsk || !e.onlinePrefixes.Terminal {
		e.onlinePrefixes.Out = e.log
	}
}

func (e *Engine) Close() {
	if e.cityDB != nil {
		e.cityDB.Close()
	}
	if e.netblockDB != nil {
		e.netblockDB.Close()
	}
	if e.prefixDB != nil {
		e.prefixDB.Close()
	}
}

func (e *Engine) HasCountryDB() bool    { return e.countryDB != nil }
func (e *Engine) HasCityDB() bool       { return e.cityDB != nil }
func (e *Engine) HasNetblockDB() bool   { return e.netblockDB != nil }
func (e *Engine) HasCategoryDB() bool   { return e.categoryDB != nil }
func (e *Engine) HasReputationDB() bool { return e.reputationDB != nil }
func (e *Engine) HasPrefixDB() bool     { return e.prefixDB != nil }

// LookupResult is everything known about a single address or ASN.
type LookupResult struct {
	Target       string
	Host         string
	IP           net.IP
	ASN          string
	Name         string
	Country      string
	City         string
	Netblock     string
	NetblockLive bool
	// NetblockSource says which service answered a live netblock lookup:
	// "rdap" or "whois" (sources.OnlineSource*). Empty when NetblockLive is
	// false.
	NetblockSource string
	// NetblockCountry is the country the registry range itself names, as
	// "US, United States"; Country is the RIR delegation of its parent
	// allocation. NetblockCreated is when the range was registered,
	// YYYY-MM-DD. Both are empty when the netblock database does not say.
	NetblockCountry string
	NetblockCreated string
	Category        string
	// VPNLists says, for each vpn:<provider> tag in Category, where its
	// addresses came from and when that list was current.
	VPNLists map[string]sources.VPNList
	// Reputation names the blocklists listing the address itself, and
	// ASNReputation what they say about its ASN. Both are empty without the
	// reputation database; Reputation is a non-nil empty slice when the
	// database is loaded and no list names the address. ASNReputation is
	// nil without the database, or when the address is not announced.
	Reputation    []string
	ASNReputation *sources.ASNReputation
	RDNS          string
	IsASN         bool
	Prefixes      []string
	IPv4Prefixes  []string
	IPv6Prefixes  []string
	PrefixSource  string
}

func (e *Engine) LookupTarget(t Target) ([]LookupResult, error) {
	return e.LookupTargetContext(context.Background(), t)
}

// LookupTargetContext is LookupTarget with ctx bounding any online prefix query.
func (e *Engine) LookupTargetContext(ctx context.Context, t Target) ([]LookupResult, error) {
	if t.Err != nil {
		return nil, t.Err
	}
	if t.ASN > 0 {
		res, err := e.LookupASNContext(ctx, t.ASN)
		if err != nil {
			return nil, err
		}
		res.Target = t.Raw
		return []LookupResult{res}, nil
	}
	results := make([]LookupResult, 0, len(t.IPs))
	for _, ip := range t.IPs {
		res, err := e.Lookup(ip)
		if err != nil {
			return nil, err
		}
		res.Target = t.Raw
		res.Host = t.Host
		results = append(results, res)
	}
	return results, nil
}

// LookupASN returns details about an ASN including its owner, classification, and announced prefixes.
func (e *Engine) LookupASN(asn uint32) (LookupResult, error) {
	return e.LookupASNContext(context.Background(), asn)
}

// LookupASNContext is LookupASN with ctx bounding the online prefix query made
// when the prefix database does not cover asn.
func (e *Engine) LookupASNContext(ctx context.Context, asn uint32) (LookupResult, error) {
	asnStr := fmt.Sprintf("AS%d", asn)
	res := LookupResult{
		Target: asnStr,
		ASN:    asnStr,
		IsASN:  true,
		Name:   "Unknown",
	}

	if name, ok := e.names[asn]; ok {
		res.Name = name
		_, res.Country = splitNameCountry(name)
	}
	if res.Country == "" {
		res.Country = "Unknown"
	}

	if e.categoryDB != nil {
		res.Category = e.categoryDB.LookupASN(asn)
	}

	var prefixRes sources.ASNPrefixResult
	if e.prefixDB != nil {
		if pr, err := e.prefixDB.Lookup(asn); err == nil && pr.Total() > 0 {
			prefixRes = pr
		}
	}

	if prefixRes.Total() == 0 && e.onlinePrefixes.Allowed(asn) {
		ctx, cancel := context.WithTimeout(ctx, 7*time.Second)
		defer cancel()
		if pr, err := sources.FetchASNPrefixesOnline(ctx, asn); err == nil && pr.Total() > 0 {
			prefixRes = pr
		}
	}

	res.IPv4Prefixes = prefixRes.IPv4
	res.IPv6Prefixes = prefixRes.IPv6
	res.Prefixes = prefixRes.All()
	res.PrefixSource = prefixRes.Source

	if e.reputationDB != nil {
		rep := e.reputationDB.LookupASN(asn)
		rep.AnnouncedIPv4 = sources.CountIPv4(res.IPv4Prefixes)
		res.ASNReputation = &rep
	}

	return res, nil
}

func (e *Engine) Lookup(ip net.IP) (LookupResult, error) {
	res := LookupResult{IP: ip, Name: "Unknown", Country: "Unknown"}

	ip = ip.To16()
	if ip == nil {
		return LookupResult{}, fmt.Errorf("invalid IP address: %v", res.IP)
	}

	var asn uint32
	haveASN := false
	as, err := e.db.Lookup(ip)
	switch err {
	case nil:
		asn, haveASN = as.Number, true
		res.ASN = fmt.Sprintf("AS%d", as.Number)
		if n, ok := e.names[as.Number]; ok {
			res.Name = n
		}
	case database.ErrNotFound:
		res.ASN = "N/A"
	default:
		return LookupResult{}, fmt.Errorf("lookup failed: %v", err)
	}

	if e.countryDB != nil {
		if c := sources.LookupCountry(e.countryDB, ip); c != "" {
			res.Country = c
		}
	}

	if e.cityDB != nil {
		res.City = "Unknown"
		if c := sources.LookupCity(e.cityDB, ip); c != "" {
			res.City = c
		}
	}

	var nb sources.NetblockInfo
	if e.netblockDB != nil {
		var err error
		if nb, err = e.netblockDB.Lookup(ip); err != nil {
			return LookupResult{}, fmt.Errorf("netblock lookup failed: %v", err)
		}
		if nb.Country != "" {
			res.NetblockCountry = sources.CountryLabel(nb.Country)
		}
		res.NetblockCreated = nb.Created
	}
	netblockTags := nb.Tags
	if e.showNetblock {
		res.Netblock = "Unknown"
		if nb.Empty() && res.Country != "Unknown" && e.whois.Allowed(res.IP) {
			online, src, rdapErr, err := e.rdap.LookupOnlineNetblock(context.Background(), res.IP)
			switch {
			case err != nil:
				fmt.Fprintf(e.log, "asname: online netblock lookup for %s failed: %v\n", res.IP, err)
			case !online.Empty():
				if rdapErr != nil && !errors.Is(rdapErr, sources.ErrRDAPNotFound) {
					fmt.Fprintf(e.log, "asname: RDAP lookup for %s failed, used whois: %v\n", res.IP, rdapErr)
				}
				nb = online
				res.NetblockLive = true
				res.NetblockSource = src
				if res.NetblockCountry == "" && nb.Country != "" {
					res.NetblockCountry = sources.CountryLabel(nb.Country)
				}
				if res.NetblockCreated == "" {
					res.NetblockCreated = nb.Created
				}
			}
		}
		if !nb.Empty() {
			res.Netblock = nb.String()
		}
	}

	if e.categoryDB != nil {
		res.Category = "Unknown"
		if c := e.categoryDB.Lookup(ip, asn, haveASN); c != "" {
			res.Category = c
			res.VPNLists = e.categoryDB.VPNLists(c)
		}
	}
	// Leasing and anonymised-holder flags come from the netblock database.
	if len(netblockTags) > 0 {
		tags := strings.Join(netblockTags, ", ")
		if res.Category == "" || res.Category == "Unknown" {
			res.Category = tags
		} else {
			res.Category += ", " + tags
		}
	}

	if e.reputationDB != nil {
		// Non-nil even when empty, so a formatter can tell "not listed"
		// from "not checked".
		res.Reputation = e.reputationDB.Lookup(ip)
		if res.Reputation == nil {
			res.Reputation = []string{}
		}
		if haveASN {
			rep := e.asnReputation(asn)
			res.ASNReputation = &rep
		}
	}

	return res, nil
}

// asnReputation is the reputation of asn with its announced IPv4 space
// filled in from the prefix database when anything inside it is listed.
func (e *Engine) asnReputation(asn uint32) sources.ASNReputation {
	if cached, ok := e.asnReps.Load(asn); ok {
		return cached.(sources.ASNReputation)
	}
	rep := e.reputationDB.LookupASN(asn)
	if rep.ListedIPs > 0 && e.prefixDB != nil {
		if pr, err := e.prefixDB.Lookup(asn); err == nil {
			rep.AnnouncedIPv4 = sources.CountIPv4(pr.IPv4)
		}
	}
	e.asnReps.Store(asn, rep)
	return rep
}

// splitNameCountry splits an AS name such as "GOOGLE - Google LLC, US" into
// the organization part and its country, formatted "US, United States". A
// name without a trailing two-letter code is returned whole with no country.
func splitNameCountry(name string) (org, country string) {
	idx := strings.LastIndex(name, ", ")
	if idx < 0 {
		return name, ""
	}
	cc := strings.TrimSpace(name[idx+2:])
	if len(cc) != 2 {
		return name, ""
	}
	if countryName, ok := sources.CountryNames[cc]; ok {
		return name[:idx], fmt.Sprintf("%s, %s", cc, countryName)
	}
	return name[:idx], cc
}

// ASNSearchResult is an Autonomous System whose registered name matched a
// search, with the prefixes the local prefix database has it announcing.
type ASNSearchResult struct {
	Number       uint32
	ASN          string
	Name         string
	Country      string
	Prefixes     []string
	IPv4Prefixes []string
	IPv6Prefixes []string
	// ASNReputation is nil without the reputation database.
	ASNReputation *sources.ASNReputation
	// Match is how the name matched, as sources.NameMatcher ranks it.
	Match int
}

// ASNSearchOptions are SearchASNsWith's options.
type ASNSearchOptions struct {
	Limit          int
	V4Only, V6Only bool
	// Fuzzy also finds names that match ignoring spaces and punctuation, or
	// word by word (see sources.NameMatcher), best match first.
	Fuzzy bool
}

// SearchASNs returns the ASNs whose name contains query, ignoring case, in
// ascending ASN order, stopping after limit results when limit > 0. Each
// carries its announced prefixes when the prefix database is open; they are
// never fetched online, as one search can match hundreds of ASNs. The
// trailing country code of a name is not searched, so a query such as "us"
// does not match every AS registered in the United States. v4Only and v6Only
// keep only the prefixes of that family; the ASNs themselves are kept.
func (e *Engine) SearchASNs(query string, limit int, v4Only, v6Only bool) []ASNSearchResult {
	return e.SearchASNsWith(query, ASNSearchOptions{Limit: limit, V4Only: v4Only, V6Only: v6Only})
}

// SearchASNsWith is SearchASNs with options; with opts.Fuzzy the results
// come best match first, then in ASN order.
func (e *Engine) SearchASNsWith(query string, opts ASNSearchOptions) []ASNSearchResult {
	limit, v4Only, v6Only := opts.Limit, opts.V4Only, opts.V6Only
	query = strings.TrimSpace(query)
	if query == "" {
		return nil
	}
	m := sources.NewNameMatcher(query, opts.Fuzzy)
	var matched []uint32
	rank := make(map[uint32]int)
	for asn, name := range e.names {
		org, _ := splitNameCountry(name)
		if r := m.Rank([]byte(org)); r != sources.MatchNone {
			matched = append(matched, asn)
			rank[asn] = r
		}
	}
	sort.Slice(matched, func(i, j int) bool {
		if ri, rj := rank[matched[i]], rank[matched[j]]; ri != rj {
			return ri < rj
		}
		return matched[i] < matched[j]
	})
	if limit > 0 && len(matched) > limit {
		matched = matched[:limit]
	}

	results := make([]ASNSearchResult, len(matched))
	for i, asn := range matched {
		name := e.names[asn]
		_, country := splitNameCountry(name)
		if country == "" {
			country = "Unknown"
		}
		results[i] = ASNSearchResult{Number: asn, ASN: fmt.Sprintf("AS%d", asn), Name: name, Country: country}
		if opts.Fuzzy {
			results[i].Match = rank[asn]
		}
		if e.prefixDB != nil {
			if pr, err := e.prefixDB.Lookup(asn); err == nil {
				if v4Only {
					pr.IPv6 = nil
				}
				if v6Only {
					pr.IPv4 = nil
				}
				results[i].Prefixes = pr.All()
				results[i].IPv4Prefixes = pr.IPv4
				results[i].IPv6Prefixes = pr.IPv6
			}
		}
		if e.reputationDB != nil {
			rep := e.asnReputation(asn)
			results[i].ASNReputation = &rep
		}
	}
	return results
}

// CountryPrefixes returns the CIDR blocks the country database assigns to
// the country cc, which is a two-letter ISO code or an English name. The
// database comes from the RIR delegation files, so these are the blocks
// registered to holders in that country, not where the addresses are used.
func (e *Engine) CountryPrefixes(country string) (cc string, v4, v6 []string, err error) {
	if e.countryDB == nil {
		return "", nil, nil, fmt.Errorf("country database is not open (run `asname update --country-only`)")
	}
	if cc, err = sources.ParseCountry(country); err != nil {
		return "", nil, nil, err
	}
	v4, v6, err = sources.CountryPrefixes(e.countryDB, cc)
	return cc, v4, v6, err
}

// CityPrefixes lists the blocks the city database locates in each place whose
// city is named query; see sources.CityPrefixes.
func (e *Engine) CityPrefixes(query string) ([]sources.CityPlace, error) {
	if e.cityDB == nil {
		return nil, fmt.Errorf("city database is not open (run `asname update --city-only`)")
	}
	return sources.CityPrefixes(e.cityDB, query)
}

// NetblockEnrichedResult represents a netblock search result enriched with ASN and Country data.
type NetblockEnrichedResult struct {
	sources.NetblockSearchResult
	ASN     string
	ASName  string
	Country string
}

func (e *Engine) SearchNetblocks(query string, opts sources.NetblockSearchOptions) ([]NetblockEnrichedResult, error) {
	if e.netblockDB == nil {
		return nil, fmt.Errorf("netblock database is not open (build with `asname update --netblock-only` or pass `--netblock`)")
	}
	rawResults, err := e.netblockDB.SearchOrg(query, opts)
	if err != nil {
		return nil, err
	}

	enriched := make([]NetblockEnrichedResult, len(rawResults))
	for i, r := range rawResults {
		item := NetblockEnrichedResult{
			NetblockSearchResult: r,
			ASN:                  "N/A",
			ASName:               "Unknown",
			Country:              "Unknown",
		}
		if r.RangeStart != nil {
			ip := r.RangeStart.To16()
			if ip != nil && e.db != nil {
				if as, err := e.db.Lookup(ip); err == nil {
					item.ASN = fmt.Sprintf("AS%d", as.Number)
					if name, ok := e.names[as.Number]; ok {
						item.ASName = name
					}
				}
			}
			if ip != nil && e.countryDB != nil {
				if c := sources.LookupCountry(e.countryDB, ip); c != "" {
					item.Country = c
				}
			}
		}
		enriched[i] = item
	}
	return enriched, nil
}

// OnlyFamilyPrefixes keeps only the IPv4 prefixes of each ASN result when
// v4Only is set, or only the IPv6 prefixes when v6Only is set.
func OnlyFamilyPrefixes(results []LookupResult, v4Only, v6Only bool) {
	for i := range results {
		r := &results[i]
		if v4Only {
			r.IPv6Prefixes = nil
		}
		if v6Only {
			r.IPv4Prefixes = nil
		}
		if (v4Only || v6Only) && r.IsASN {
			r.Prefixes = append(append([]string(nil), r.IPv4Prefixes...), r.IPv6Prefixes...)
		}
	}
}

// rdapCacheDir is where the RDAP bootstrap files are kept: the data
// directory, which also holds the whois consent file. Empty (in memory
// only) when there is none.
func rdapCacheDir(consentPath string) string {
	if consentPath == "" {
		return ""
	}
	return filepath.Dir(consentPath)
}
