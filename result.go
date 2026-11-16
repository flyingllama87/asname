package asname

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/flyingllama87/asname/internal/engine"
	"github.com/flyingllama87/asname/internal/sources"
)

// Result is everything known about an IP address, hostname, URL, or ASN.
//
// A field the databases cannot answer is empty: the CLI's "Unknown" and "N/A"
// placeholders are display text and never appear here. ASN keeps its "AS"
// prefix (see ASNNumber) and Country reads "US, United States" (see
// CountryCode and CountryName).
type Result struct {
	Target  string `json:"target,omitempty"`
	Host    string `json:"host,omitempty"`
	IP      net.IP `json:"ip,omitempty"`
	ASN     string `json:"asn,omitempty"`
	Name    string `json:"name,omitempty"`
	Country string `json:"country,omitempty"`
	City    string `json:"city,omitempty"`
	// CitySource names who made the city database City comes from:
	// "DB-IP", "MaxMind GeoLite2" or "MaxMind GeoIP2".
	CitySource string `json:"city_source,omitempty"`
	// CityMaxMind is MaxMind's estimate of the place, beside City's, when
	// the city update had a MaxMind account; CityMaxMindSource names the
	// edition ("MaxMind GeoLite2").
	CityMaxMind       string `json:"city_maxmind,omitempty"`
	CityMaxMindSource string `json:"city_maxmind_source,omitempty"`
	// Geofeed is where the network's own geofeed (RFC 8805) places the
	// address, which can differ from City (an estimate); nil without
	// the geofeed database or when no feed covers the address.
	Geofeed      *GeofeedLocation `json:"geofeed,omitempty"`
	Netblock     string           `json:"netblock,omitempty"`
	NetblockLive bool             `json:"netblock_live,omitempty"`
	// NetblockSource is the service that answered a live netblock lookup,
	// "rdap" or "whois"; empty when NetblockLive is false.
	NetblockSource string `json:"netblock_source,omitempty"`
	// NameSource is "rdap" when Name came from the registry because the
	// offline AS names list lacks the ASN.
	NameSource string `json:"name_source,omitempty"`
	// NetblockCountry is the country the registry range itself names, as
	// "US, United States". Country is that of the RIR allocation the range
	// sits in, which for a sub-allocated or leased block is often elsewhere.
	// NetblockCreated is when the range was registered, YYYY-MM-DD.
	NetblockCountry string `json:"netblock_country,omitempty"`
	NetblockCreated string `json:"netblock_created,omitempty"`
	Category        string `json:"category,omitempty"`
	// CategoryInferred holds tags asname's own rules add, weaker evidence
	// than Category, each with what it was inferred from: "netname" (the
	// range's registry netname), "name" (the AS name) or "list" (asname's
	// list of well-known networks).
	CategoryInferred []InferredTag `json:"category_inferred,omitempty"`
	// Reputation names the public blocklists listing the address, such as
	// "ipsum:7" (IPsum, on 7 of its source lists), "firehol-level2" or
	// "spamhaus-drop:SBL123456". ASNReputation is what the lists say about
	// the ASN as a whole. Both are empty without the reputation database.
	Reputation    []string       `json:"reputation,omitempty"`
	ASNReputation *ASNReputation `json:"asn_reputation,omitempty"`
	RDNS          string         `json:"rdns,omitempty"`
	IsASN         bool           `json:"is_asn,omitempty"`
	Prefixes      []string       `json:"prefixes,omitempty"`
	IPv4Prefixes  []string       `json:"ipv4_prefixes,omitempty"`
	IPv6Prefixes  []string       `json:"ipv6_prefixes,omitempty"`
	PrefixSource  string         `json:"prefix_source,omitempty"`
}

// ASNNumber parses and returns the numeric ASN (e.g. 15169 for "AS15169").
// Returns 0 if the ASN is missing or not a valid number.
func (r Result) ASNNumber() uint32 {
	if r.ASN == "" {
		return 0
	}
	clean := strings.TrimPrefix(strings.ToUpper(r.ASN), "AS")
	n, err := strconv.ParseUint(clean, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// CountryCode returns the 2-letter ISO country code (e.g. "US" from "US, United States").
// Returns "" if unknown.
func (r Result) CountryCode() string {
	if r.Country == "" {
		return ""
	}
	if i := strings.Index(r.Country, ","); i > 0 {
		return strings.TrimSpace(r.Country[:i])
	}
	if len(r.Country) == 2 {
		return r.Country
	}
	return ""
}

// CountryName returns the country name (e.g. "United States" from "US, United States").
// Returns the raw country string if no comma is present.
func (r Result) CountryName() string {
	if r.Country == "" {
		return ""
	}
	if i := strings.Index(r.Country, ","); i >= 0 && i+1 < len(r.Country) {
		return strings.TrimSpace(r.Country[i+1:])
	}
	return r.Country
}

// String returns a human-readable one-line summary, showing a missing ASN as
// "N/A" and a missing name or country as "Unknown", as the CLI does.
func (r Result) String() string {
	asn, name, country := orText(r.ASN, "N/A"), orText(r.Name, "Unknown"), orText(r.Country, "Unknown")
	if r.IsASN {
		s := fmt.Sprintf("ASN: %s | Name: %s | Country: %s", asn, name, country)
		if r.Category != "" {
			s += " | Category: " + r.Category
		}
		return s
	}
	s := fmt.Sprintf("IP: %s | ASN: %s | Name: %s | Country: %s", r.IP, asn, name, country)
	if r.City != "" {
		s += " | City: " + r.City
	}
	if r.Netblock != "" {
		s += " | Netblock: " + r.Netblock
	}
	if r.NetblockCountry != "" && r.NetblockCountry != r.Country {
		s += " | Block country: " + r.NetblockCountry
	}
	if r.Category != "" {
		s += " | Category: " + r.Category
	}
	if r.RDNS != "" {
		s += " | RDNS: " + r.RDNS
	}
	return s
}

func orText(s, placeholder string) string {
	if s == "" {
		return placeholder
	}
	return s
}

// known maps the engine's display placeholders to the empty string. The
// engine fills them in for the CLI's formatters; a library caller should not
// have to know them.
func known(s string) string {
	if s == "Unknown" || s == "N/A" {
		return ""
	}
	return s
}

func resultFromEngine(r engine.LookupResult) Result {
	return Result{
		Target:            r.Target,
		Host:              r.Host,
		IP:                r.IP,
		ASN:               known(r.ASN),
		Name:              known(r.Name),
		Country:           known(r.Country),
		City:              known(r.City),
		CitySource:        r.CitySource,
		CityMaxMind:       r.CityMaxMind,
		CityMaxMindSource: r.CityMaxMindSource,
		Geofeed:           geofeedFromEngine(r.Geofeed),
		Netblock:          known(r.Netblock),
		NetblockLive:      r.NetblockLive,
		NetblockSource:    r.NetblockSource,
		NameSource:        r.NameSource,
		NetblockCountry:   r.NetblockCountry,
		NetblockCreated:   r.NetblockCreated,
		Category:          known(r.Category),
		CategoryInferred:  inferredTags(r.Inferred),
		Reputation:        r.Reputation,
		ASNReputation:     asnReputationFromEngine(r.ASNReputation),
		RDNS:              known(r.RDNS),
		IsASN:             r.IsASN,
		Prefixes:          r.Prefixes,
		IPv4Prefixes:      r.IPv4Prefixes,
		IPv6Prefixes:      r.IPv6Prefixes,
		PrefixSource:      r.PrefixSource,
	}
}

// GeofeedLocation is where a network's own geofeed places an address: an
// ISO 3166-1 country code, an ISO 3166-2 region code ("NL-LI") and a city,
// with the URL of the feed. Only Country is always set. It is the holder's
// claim: leased and VPN space can say anything.
type GeofeedLocation struct {
	Country string `json:"country"`
	Region  string `json:"region,omitempty"`
	City    string `json:"city,omitempty"`
	Feed    string `json:"feed"`
}

// String reads "Kerkrade, NL-LI, Netherlands".
func (g GeofeedLocation) String() string {
	return sources.GeofeedLocation{Country: g.Country, Region: g.Region, City: g.City}.String()
}

func geofeedFromEngine(g *sources.GeofeedLocation) *GeofeedLocation {
	if g == nil {
		return nil
	}
	return &GeofeedLocation{Country: g.Country, Region: g.Region, City: g.City, Feed: g.Feed}
}

// ASNReputation is what public blocklists say about an Autonomous System.
// ListedIPs counts the distinct addresses inside its routes that IPsum or
// FireHOL list, and MaxLists the most IPsum sources naming any one of them.
// AnnouncedIPv4 is the IPv4 space it announces, when the prefix database
// knows it, so ListedIPs can be read as a share of it.
type ASNReputation struct {
	SpamhausASNDrop bool   `json:"spamhaus_asn_drop"`
	ListedIPs       uint32 `json:"listed_ips"`
	DropPrefixes    uint32 `json:"drop_prefixes"`
	MaxLists        uint32 `json:"max_lists,omitempty"`
	AnnouncedIPv4   uint64 `json:"announced_ipv4,omitempty"`
}

// Listed reports whether any list names the ASN or anything inside it.
func (r ASNReputation) Listed() bool { return r.toSources().Listed() }

// String renders the reputation on one line, as the CLI does.
func (r ASNReputation) String() string { return r.toSources().String() }

func (r ASNReputation) toSources() sources.ASNReputation {
	return sources.ASNReputation{
		ASNDrop: r.SpamhausASNDrop, ListedIPs: r.ListedIPs, DropPrefixes: r.DropPrefixes,
		MaxLists: r.MaxLists, AnnouncedIPv4: r.AnnouncedIPv4,
	}
}

func asnReputationFromEngine(r *sources.ASNReputation) *ASNReputation {
	if r == nil {
		return nil
	}
	return &ASNReputation{
		SpamhausASNDrop: r.ASNDrop, ListedIPs: r.ListedIPs, DropPrefixes: r.DropPrefixes,
		MaxLists: r.MaxLists, AnnouncedIPv4: r.AnnouncedIPv4,
	}
}

// CountryResult lists the CIDR blocks registered to one country. Country is
// the upper-case ISO code and Name its English name, when known.
type CountryResult struct {
	Country string   `json:"country"`
	Name    string   `json:"name,omitempty"`
	IPv4    []string `json:"ipv4,omitempty"`
	IPv6    []string `json:"ipv6,omitempty"`
}

// CityResult lists the CIDR blocks the city database locates in one place.
// Country is the upper-case ISO code.
type CityResult struct {
	City    string   `json:"city"`
	Region  string   `json:"region,omitempty"`
	Country string   `json:"country"`
	IPv4    []string `json:"ipv4,omitempty"`
	IPv6    []string `json:"ipv6,omitempty"`
}

// SearchScope selects what Search looks through.
type SearchScope int

const (
	// SearchAll searches AS names and registry netblocks.
	SearchAll SearchScope = iota
	// SearchASNsOnly searches AS names only.
	SearchASNsOnly
	// SearchNetblocksOnly searches registry netblocks only.
	SearchNetblocksOnly
)

// SearchOptions controls search filters and limits. Limit caps the ASNs and
// the netblocks separately (0 for unlimited); V4Only and V6Only keep only
// netblocks, and ASN prefixes, of that family. Scope is used by Search and
// ignored by SearchNetblocks.
type SearchOptions struct {
	Limit  int
	V4Only bool
	V6Only bool
	Scope  SearchScope
	// Fuzzy also finds names that match ignoring spaces and punctuation, or
	// word by word in any order, with company suffixes left out and common
	// abbreviations expanded. Results come best match first.
	Fuzzy bool
	// Country, a two-letter code such as "AU", keeps only the ASNs
	// registered there and the netblocks the country database places
	// there; empty searches every country.
	Country string
}

// SearchResults holds the matches of Search: the Autonomous Systems whose
// registered name matched, and the registry netblocks whose organization or
// netname matched.
type SearchResults struct {
	ASNs      []ASNResult      `json:"asns,omitempty"`
	Netblocks []NetblockResult `json:"netblocks,omitempty"`
}

// ASNResult is an Autonomous System whose registered name matched a search.
// Name is the full AS name, such as "GOOGLE - Google LLC, US", and Country
// reads "US, United States". The prefixes are those the local prefix
// database has it announcing, and are empty without that database.
type ASNResult struct {
	ASN          string   `json:"asn"`
	Number       uint32   `json:"number"`
	Name         string   `json:"name,omitempty"`
	Country      string   `json:"country,omitempty"`
	Prefixes     []string `json:"prefixes,omitempty"`
	IPv4Prefixes []string `json:"ipv4_prefixes,omitempty"`
	IPv6Prefixes []string `json:"ipv6_prefixes,omitempty"`
	// ASNReputation is nil without the reputation database.
	ASNReputation *ASNReputation `json:"asn_reputation,omitempty"`
}

func asnResultFromEngine(r engine.ASNSearchResult) ASNResult {
	return ASNResult{
		ASN:           r.ASN,
		Number:        r.Number,
		Name:          known(r.Name),
		Country:       known(r.Country),
		Prefixes:      r.Prefixes,
		IPv4Prefixes:  r.IPv4Prefixes,
		IPv6Prefixes:  r.IPv6Prefixes,
		ASNReputation: asnReputationFromEngine(r.ASNReputation),
	}
}

// NetblockResult represents a matched IP range from registry netblocks.
type NetblockResult struct {
	RangeStart net.IP   `json:"range_start,omitempty"`
	RangeEnd   net.IP   `json:"range_end,omitempty"`
	CIDRs      []string `json:"cidrs,omitempty"`
	Netname    string   `json:"netname,omitempty"`
	Org        string   `json:"org,omitempty"`
	IsV6       bool     `json:"is_v6,omitempty"`
	ASN        string   `json:"asn,omitempty"`
	ASName     string   `json:"as_name,omitempty"`
	Country    string   `json:"country,omitempty"`
}

func netblockResultFromEngine(r engine.NetblockEnrichedResult) NetblockResult {
	return NetblockResult{
		RangeStart: r.RangeStart,
		RangeEnd:   r.RangeEnd,
		CIDRs:      r.CIDRs,
		Netname:    r.Netname,
		Org:        r.Org,
		IsV6:       r.IsV6,
		ASN:        known(r.ASN),
		ASName:     known(r.ASName),
		Country:    known(r.Country),
	}
}

// InferredTag is a category tag asname inferred, and what from.
type InferredTag struct {
	Tag  string `json:"tag"`
	From string `json:"from"`
}

func inferredTags(in []engine.InferredTag) []InferredTag {
	if len(in) == 0 {
		return nil
	}
	out := make([]InferredTag, len(in))
	for i, t := range in {
		out[i] = InferredTag{Tag: t.Tag, From: t.From}
	}
	return out
}
