package engine

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
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
	categoryDB   *sources.CategoryDB
	prefixDB     *sources.PrefixDB
}

func NewEngine(cfg sources.Config, wantCity, wantNetblock, showNetblock, wantCategory bool, whois sources.WhoisMode) (*Engine, error) {
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
		fmt.Fprintln(os.Stderr, "asname: country database unavailable (run `asname update`):", err)
		countryDB = nil
	}

	var cityDB *maxminddb.Reader
	if wantCity {
		if cityDB, err = sources.LoadCityDB(cfg.CityPath); err != nil {
			fmt.Fprintln(os.Stderr, "asname: city database unavailable (run `asname update --city-only`):", err)
			cityDB = nil
		}
	}

	var nbDB *sources.NetblockDB
	if wantNetblock {
		if nbDB, err = sources.OpenNetblockDB(cfg.NetblockPath); err != nil {
			fmt.Fprintln(os.Stderr, "asname: netblock database unavailable (run `asname update --netblock-only`):", err)
			nbDB = nil
		}
	}

	var catDB *sources.CategoryDB
	if wantCategory {
		if catDB, err = sources.OpenCategoryDB(cfg.CategoryPath); err != nil {
			fmt.Fprintln(os.Stderr, "asname: category database unavailable (run `asname update --category-only`):", err)
			catDB = nil
		}
	}

	var prefixDB *sources.PrefixDB
	if cfg.PrefixPath != "" && sources.PrefixDBPresent(cfg.PrefixPath) {
		if prefixDB, err = sources.OpenPrefixDB(cfg.PrefixPath); err != nil {
			prefixDB = nil
		}
	}

	return &Engine{
		db:           db,
		names:        names,
		countryDB:    countryDB,
		cityDB:       cityDB,
		netblockDB:   nbDB,
		showNetblock: showNetblock,
		whois:        sources.NewWhoisAsker(cfg.ConsentPath, whois),
		categoryDB:   catDB,
		prefixDB:     prefixDB,
	}, nil
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

func (e *Engine) HasCountryDB() bool  { return e.countryDB != nil }
func (e *Engine) HasCityDB() bool     { return e.cityDB != nil }
func (e *Engine) HasNetblockDB() bool { return e.netblockDB != nil }
func (e *Engine) HasCategoryDB() bool { return e.categoryDB != nil }
func (e *Engine) HasPrefixDB() bool   { return e.prefixDB != nil }

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
	Category     string
	RDNS         string
	IsASN        bool
	Prefixes     []string
	IPv4Prefixes []string
	IPv6Prefixes []string
	PrefixSource string
}

func (e *Engine) LookupTarget(t Target) ([]LookupResult, error) {
	if t.Err != nil {
		return nil, t.Err
	}
	if t.ASN > 0 {
		res, err := e.LookupASN(t.ASN)
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
	asnStr := fmt.Sprintf("AS%d", asn)
	res := LookupResult{
		Target: asnStr,
		ASN:    asnStr,
		IsASN:  true,
		Name:   "Unknown",
	}

	if name, ok := e.names[asn]; ok {
		res.Name = name
		if idx := strings.LastIndex(name, ", "); idx >= 0 && idx+2 < len(name) {
			cc := strings.TrimSpace(name[idx+2:])
			if len(cc) == 2 {
				if countryName, ok := sources.CountryNames[cc]; ok {
					res.Country = fmt.Sprintf("%s, %s", cc, countryName)
				} else {
					res.Country = cc
				}
			}
		}
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

	if prefixRes.Total() == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
		defer cancel()
		if pr, err := sources.FetchASNPrefixesOnline(ctx, asn); err == nil && pr.Total() > 0 {
			prefixRes = pr
		}
	}

	res.IPv4Prefixes = prefixRes.IPv4
	res.IPv6Prefixes = prefixRes.IPv6
	res.Prefixes = prefixRes.All()
	res.PrefixSource = prefixRes.Source

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

	if e.showNetblock {
		res.Netblock = "Unknown"
		var nb sources.NetblockInfo
		if e.netblockDB != nil {
			var err error
			if nb, err = e.netblockDB.Lookup(ip); err != nil {
				return LookupResult{}, fmt.Errorf("netblock lookup failed: %v", err)
			}
		}
		if nb.Empty() && res.Country != "Unknown" && e.whois.Allowed(res.IP) {
			online, err := sources.LookupWhoisNetblock(res.IP)
			if err != nil {
				fmt.Fprintf(os.Stderr, "asname: whois lookup for %s failed: %v\n", res.IP, err)
			} else if !online.Empty() {
				nb = online
				res.NetblockLive = true
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
		}
	}

	return res, nil
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

