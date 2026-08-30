package engine

import (
	"fmt"
	"net"
	"os"

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

	return &Engine{
		db:           db,
		names:        names,
		countryDB:    countryDB,
		cityDB:       cityDB,
		netblockDB:   nbDB,
		showNetblock: showNetblock,
		whois:        sources.NewWhoisAsker(cfg.ConsentPath, whois),
		categoryDB:   catDB,
	}, nil
}

func (e *Engine) Close() {
	if e.cityDB != nil {
		e.cityDB.Close()
	}
	if e.netblockDB != nil {
		e.netblockDB.Close()
	}
}

func (e *Engine) HasCountryDB() bool  { return e.countryDB != nil }
func (e *Engine) HasCityDB() bool     { return e.cityDB != nil }
func (e *Engine) HasNetblockDB() bool { return e.netblockDB != nil }
func (e *Engine) HasCategoryDB() bool { return e.categoryDB != nil }

// LookupResult is everything known about a single address.
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
}

func (e *Engine) LookupTarget(t Target) ([]LookupResult, error) {
	if t.Err != nil {
		return nil, t.Err
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
