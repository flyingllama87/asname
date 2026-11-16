package format

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/flyingllama87/asname/internal/engine"
	"github.com/flyingllama87/asname/internal/sources"
)

type JSONLookupResult struct {
	Target  string   `json:"target,omitempty"`
	Host    *string  `json:"host"`
	IP      string   `json:"ip,omitempty"`
	Version int      `json:"version,omitempty"`
	ASN     *JSONASN `json:"asn,omitempty"`
	// ServedBy is the CDN the hostname is served through: the address is
	// then that CDN's edge server nearest the resolver, not the site's own.
	ServedBy *JSONServedBy `json:"served_by,omitempty"`
	// NAT64 says the address asked about was IP inside a NAT64 prefix.
	NAT64 *JSONNAT64 `json:"nat64,omitempty"`
	// IPv6Skipped counts the hostname's IPv6 addresses not looked up: the
	// ASN database has no IPv6 routes. On the hostname's first result.
	IPv6Skipped int          `json:"ipv6_skipped,omitempty"`
	Country     *JSONCountry `json:"country,omitempty"`
	City        *JSONCity    `json:"city,omitempty"`
	// CityMaxMind is MaxMind's estimate, beside City's, when asname has
	// MaxMind's city database too.
	CityMaxMind *JSONCity    `json:"city_maxmind,omitempty"`
	Geofeed     *JSONGeofeed `json:"geofeed,omitempty"`
	// Relay is where Apple says the users of this iCloud Private Relay
	// egress range are.
	Relay *JSONRelay `json:"relay,omitempty"`
	// Special is the IANA special-purpose block the address is in.
	Special    *JSONSpecial    `json:"special,omitempty"`
	Netblock   *JSONNetblock   `json:"netblock,omitempty"`
	Category   *JSONCategory   `json:"category,omitempty"`
	Reputation *JSONReputation `json:"reputation,omitempty"`
	ReverseDNS *JSONReverseDNS `json:"reverse_dns,omitempty"`
	Prefixes   *JSONPrefixes   `json:"prefixes,omitempty"`
	Error      string          `json:"error,omitempty"`
	// Text is the result as `asname -p` prints it, when asked for with
	// text=true on the REST API, for copying into a ticket.
	Text string `json:"text,omitempty"`
}

type JSONPrefixes struct {
	Total     int      `json:"total"`
	IPv4Count int      `json:"ipv4_count"`
	IPv6Count int      `json:"ipv6_count"`
	Source    string   `json:"source"`
	List      []string `json:"list,omitempty"`
}

type JSONASN struct {
	Number    uint32 `json:"number"`
	ASNString string `json:"asn_string"`
	Name      string `json:"name,omitempty"`
	// Handle and Organization split Name ("TPG-INTERNET-AP - TPG Telecom
	// Limited, AU") into the AS's handle and its holder's name.
	Handle       string `json:"handle,omitempty"`
	Organization string `json:"organization,omitempty"`
	// NameSource is "rdap" when the name came from the registry because
	// the offline AS names list lacks the ASN.
	NameSource string `json:"name_source,omitempty"`
	Announced  bool   `json:"announced"`
	// NoIPv6Routes says the ASN database has no IPv6 routes, so an IPv6
	// address's network is unknown rather than unannounced.
	NoIPv6Routes bool `json:"no_ipv6_routes,omitempty"`
}

// JSONNAT64 is the NAT64 address a lookup was asked about, and its prefix.
// DNS64 is set when the resolver made the address up for a hostname that
// has no IPv6 address.
type JSONNAT64 struct {
	Address string `json:"address"`
	Prefix  string `json:"prefix"`
	DNS64   bool   `json:"dns64,omitempty"`
}

// JSONServedBy is the CDN a looked-up hostname is served through.
type JSONServedBy struct {
	CDN  string `json:"cdn"`
	Via  string `json:"via"`
	Name string `json:"name"`
}

type JSONCountry struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

type JSONCity struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
	// Source names who made the city database: "DB-IP", "MaxMind
	// GeoLite2" or "MaxMind GeoIP2".
	Source string `json:"source,omitempty"`
}

// JSONGeofeed is where the network's own geofeed (RFC 8805) places the
// address: Region is an ISO 3166-2 code, Name the whole place as text, Feed
// the URL of the geofeed that says so.
type JSONGeofeed struct {
	Country *JSONCountry `json:"country"`
	Region  string       `json:"region,omitempty"`
	City    string       `json:"city,omitempty"`
	Name    string       `json:"name"`
	Feed    string       `json:"feed"`
}

// JSONRelay is the location an iCloud Private Relay egress range stands for.
type JSONRelay struct {
	Provider string       `json:"provider"`
	Country  *JSONCountry `json:"country"`
	Region   string       `json:"region,omitempty"`
	City     string       `json:"city,omitempty"`
	Name     string       `json:"name"`
}

// JSONSpecial is an IANA special-purpose block (RFC 6890).
type JSONSpecial struct {
	Prefix string `json:"prefix"`
	Name   string `json:"name"`
	RFC    string `json:"rfc"`
	// GloballyReachable is IANA's flag; absent when it depends.
	GloballyReachable *bool `json:"globally_reachable,omitempty"`
}

type JSONNetblock struct {
	Handle       string `json:"handle,omitempty"`
	Organization string `json:"organization,omitempty"`
	Raw          string `json:"raw"`
	Source       string `json:"source"`
	LiveQuery    bool   `json:"live_query"`
	// Country is the country the range itself names; the top-level country
	// is the RIR allocation it sits in. Created is YYYY-MM-DD.
	Country *JSONCountry `json:"country,omitempty"`
	Created string       `json:"created,omitempty"`
}

type JSONCategory struct {
	Tags []string `json:"tags"`
	Raw  string   `json:"raw"`
	// Inferred holds tags asname's own rules add, shown apart from the
	// sources' tags, each with what it was inferred from: "netname" (the
	// range's registry netname), "name" (the AS name) or "list" (asname's
	// list of well-known networks).
	Inferred []JSONInferredTag `json:"inferred,omitempty"`
}

type JSONInferredTag struct {
	Tag  string `json:"tag"`
	From string `json:"from"`
}

func jsonInferred(in []engine.InferredTag) []JSONInferredTag {
	if len(in) == 0 {
		return nil
	}
	out := make([]JSONInferredTag, len(in))
	for i, t := range in {
		out[i] = JSONInferredTag{Tag: t.Tag, From: t.From}
	}
	return out
}

// JSONReputation is what public blocklists say about a result. Lists names
// those listing the address itself, and is absent for an ASN lookup; ASN is
// absent when the address is not announced.
type JSONReputation struct {
	Listed bool               `json:"listed"`
	Lists  []string           `json:"lists,omitempty"`
	ASN    *JSONASNReputation `json:"asn,omitempty"`
}

// JSONASNReputation is the reputation of an ASN as a whole. ListedSharePct is
// ListedIPs as a percentage of AnnouncedIPv4, present only when that is known.
type JSONASNReputation struct {
	Listed          bool     `json:"listed"`
	SpamhausASNDrop bool     `json:"spamhaus_asn_drop"`
	ListedIPs       uint32   `json:"listed_ips"`
	DropPrefixes    uint32   `json:"drop_prefixes"`
	MaxLists        uint32   `json:"max_lists,omitempty"`
	AnnouncedIPv4   uint64   `json:"announced_ipv4,omitempty"`
	ListedSharePct  *float64 `json:"listed_share_pct,omitempty"`
	Summary         string   `json:"summary"`
}

func newJSONASNReputation(r *sources.ASNReputation) *JSONASNReputation {
	if r == nil {
		return nil
	}
	out := &JSONASNReputation{
		Listed:          r.Listed(),
		SpamhausASNDrop: r.ASNDrop,
		ListedIPs:       r.ListedIPs,
		DropPrefixes:    r.DropPrefixes,
		MaxLists:        r.MaxLists,
		AnnouncedIPv4:   r.AnnouncedIPv4,
		Summary:         r.String(),
	}
	if share := r.ListedShare(); share >= 0 {
		out.ListedSharePct = &share
	}
	return out
}

func newJSONReputation(res engine.LookupResult) *JSONReputation {
	if res.Reputation == nil && res.ASNReputation == nil {
		return nil
	}
	out := &JSONReputation{Lists: res.Reputation, ASN: newJSONASNReputation(res.ASNReputation)}
	out.Listed = len(res.Reputation) > 0 || (res.IsASN && out.ASN != nil && out.ASN.Listed)
	return out
}

type JSONReverseDNS struct {
	Names []string `json:"names"`
	Raw   string   `json:"raw"`
}

func ToJSONResult(res engine.LookupResult) JSONLookupResult {
	if res.IsASN {
		out := JSONLookupResult{
			Target: res.Target,
		}
		numStr := strings.TrimPrefix(res.ASN, "AS")
		num, _ := strconv.ParseUint(numStr, 10, 32)
		out.ASN = &JSONASN{
			Number:     uint32(num),
			ASNString:  res.ASN,
			Name:       res.Name,
			NameSource: res.NameSource,
			Announced:  true,
		}
		out.ASN.Handle, out.ASN.Organization = asnNameParts(res.Name)
		if res.Country != "" && res.Country != "Unknown" {
			parts := strings.SplitN(res.Country, ", ", 2)
			if len(parts) == 2 {
				out.Country = &JSONCountry{Code: parts[0], Name: parts[1]}
			} else {
				out.Country = &JSONCountry{Code: res.Country, Name: res.Country}
			}
		}
		if res.Category != "" || len(res.Inferred) > 0 {
			tags := []string{}
			if res.Category != "" {
				tags = strings.Split(res.Category, ", ")
			}
			out.Category = &JSONCategory{Tags: tags, Raw: res.Category, Inferred: jsonInferred(res.Inferred)}
		}
		out.Reputation = newJSONReputation(res)
		if len(res.Prefixes) > 0 {
			out.Prefixes = &JSONPrefixes{
				Total:     len(res.Prefixes),
				IPv4Count: len(res.IPv4Prefixes),
				IPv6Count: len(res.IPv6Prefixes),
				Source:    res.PrefixSource,
				List:      res.Prefixes,
			}
		}
		return out
	}

	out := JSONLookupResult{
		Target: res.Target,
		IP:     res.IP.String(),
	}

	if res.Host != "" {
		h := res.Host
		out.Host = &h
	}

	if res.IP.To4() != nil {
		out.Version = 4
	} else {
		out.Version = 6
	}

	out.IPv6Skipped = res.IPv6Skipped
	if n := res.NAT64; n != nil {
		out.NAT64 = &JSONNAT64{Address: n.Address, Prefix: n.Prefix, DNS64: n.DNS64}
	}
	if res.ServedBy != nil {
		out.ServedBy = &JSONServedBy{CDN: res.ServedBy.CDN, Via: res.ServedBy.Via, Name: res.ServedBy.Name}
	}
	if res.ASN != "" && res.ASN != "N/A" {
		numStr := strings.TrimPrefix(res.ASN, "AS")
		num, _ := strconv.ParseUint(numStr, 10, 32)
		out.ASN = &JSONASN{
			Number:     uint32(num),
			ASNString:  res.ASN,
			Name:       res.Name,
			NameSource: res.NameSource,
			Announced:  true,
		}
		out.ASN.Handle, out.ASN.Organization = asnNameParts(res.Name)
	} else if res.ASN == "N/A" {
		out.ASN = &JSONASN{
			Number:       0,
			ASNString:    "N/A",
			Name:         "Unknown",
			Announced:    false,
			NoIPv6Routes: res.NoIPv6Routes,
		}
	}

	if res.Country != "" && res.Country != "Unknown" {
		parts := strings.SplitN(res.Country, ", ", 2)
		if len(parts) == 2 {
			out.Country = &JSONCountry{Code: parts[0], Name: parts[1]}
		} else {
			out.Country = &JSONCountry{Code: parts[0], Name: parts[0]}
		}
	}

	if res.City != "" && res.City != "Unknown" {
		out.City = &JSONCity{
			Name:    res.City,
			Present: true,
			Source:  res.CitySource,
		}
	}
	if res.CityMaxMind != "" {
		out.CityMaxMind = &JSONCity{Name: res.CityMaxMind, Present: true, Source: res.CityMaxMindSource}
	}

	if r := res.Relay; r != nil {
		name := sources.CountryNames[r.Country]
		if name == "" {
			name = r.Country
		}
		out.Relay = &JSONRelay{Provider: "iCloud Private Relay", Country: &JSONCountry{Code: r.Country, Name: name}, Region: r.Region, City: r.City, Name: r.String()}
	}
	if sp := res.Special; sp != nil {
		out.Special = &JSONSpecial{Prefix: sp.Prefix, Name: sp.Name, RFC: sp.RFC}
		if sp.Global != "" {
			g := sp.Global == "true"
			out.Special.GloballyReachable = &g
		}
	}
	if g := res.Geofeed; g != nil {
		name := sources.CountryNames[g.Country]
		if name == "" {
			name = g.Country
		}
		out.Geofeed = &JSONGeofeed{
			Country: &JSONCountry{Code: g.Country, Name: name},
			Region:  g.Region,
			City:    g.City,
			Name:    g.String(),
			Feed:    g.Feed,
		}
	}

	if res.Netblock != "" && res.Netblock != "Unknown" {
		src := "offline"
		if res.NetblockLive {
			src = liveSource(res.NetblockSource)
		}
		handle, org := ParseNetblockField(res.Netblock)
		out.Netblock = &JSONNetblock{
			Handle:       handle,
			Organization: org,
			Raw:          res.Netblock,
			Source:       src,
			LiveQuery:    res.NetblockLive,
			Created:      res.NetblockCreated,
		}
		if res.NetblockCountry != "" {
			code, name, _ := strings.Cut(res.NetblockCountry, ", ")
			if name == "" {
				name = code
			}
			out.Netblock.Country = &JSONCountry{Code: code, Name: name}
		}
	}

	if (res.Category != "" && res.Category != "Unknown") || len(res.Inferred) > 0 {
		tags := []string{}
		raw := ""
		if res.Category != "Unknown" {
			raw = res.Category
			for _, t := range strings.Split(res.Category, ", ") {
				t = strings.TrimSpace(t)
				if t != "" {
					tags = append(tags, t)
				}
			}
		}
		out.Category = &JSONCategory{
			Tags:     tags,
			Raw:      raw,
			Inferred: jsonInferred(res.Inferred),
		}
	}

	out.Reputation = newJSONReputation(res)

	if res.RDNS != "" && res.RDNS != "N/A" {
		rawNames := strings.Split(res.RDNS, ", ")
		names := make([]string, 0, len(rawNames))
		for _, n := range rawNames {
			n = strings.TrimSpace(n)
			if n != "" {
				names = append(names, n)
			}
		}
		out.ReverseDNS = &JSONReverseDNS{
			Names: names,
			Raw:   res.RDNS,
		}
	}

	return out
}

func ParseNetblockField(s string) (handle string, org string) {
	if i := strings.Index(s, " ("); i >= 0 && strings.HasSuffix(s, ")") {
		return s[:i], strings.TrimSuffix(s[i+2:], ")")
	}
	return s, ""
}

func FormatJSONLookupOutput(res engine.LookupResult) (string, error) {
	jr := ToJSONResult(res)
	b, err := json.Marshal(jr)
	if err != nil {
		return "", fmt.Errorf("marshaling json: %w", err)
	}
	return string(b) + "\n", nil
}

func FormatJSONError(target, errStr string) (string, error) {
	jr := JSONLookupResult{
		Target: target,
		Error:  errStr,
	}
	b, err := json.Marshal(jr)
	if err != nil {
		return "", err
	}
	return string(b) + "\n", nil
}

// JSONASNSearchResult is one AS name search match. Type is always "asn", so
// a JSON Lines consumer can tell it from a JSONNetblockSearchResult.
// Query is set when several queries are read from stdin.
type JSONASNSearchResult struct {
	Query        string             `json:"query,omitempty"`
	Type         string             `json:"type"`
	ASN          string             `json:"asn"`
	Name         string             `json:"name"`
	Country      string             `json:"country,omitempty"`
	IPv4Prefixes []string           `json:"ipv4_prefixes,omitempty"`
	IPv6Prefixes []string           `json:"ipv6_prefixes,omitempty"`
	Reputation   *JSONASNReputation `json:"reputation,omitempty"`
	// Match is how a fuzzy search matched: exact, compact or words.
	Match string `json:"match,omitempty"`
}

// NewJSONASNSearchResult converts an engine AS name match for JSON output.
func NewJSONASNSearchResult(res engine.ASNSearchResult, query string) JSONASNSearchResult {
	return JSONASNSearchResult{
		Query:        query,
		Type:         "asn",
		ASN:          res.ASN,
		Name:         res.Name,
		Country:      res.Country,
		IPv4Prefixes: res.IPv4Prefixes,
		IPv6Prefixes: res.IPv6Prefixes,
		Reputation:   newJSONASNReputation(res.ASNReputation),
		Match:        sources.MatchName(res.Match),
	}
}

func FormatJSONASNSearchOutput(res engine.ASNSearchResult, query string) (string, error) {
	data, err := json.Marshal(NewJSONASNSearchResult(res, query))
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}

// JSONCountryPrefix is one CIDR block of a country listing.
type JSONCountryPrefix struct {
	Country string `json:"country"`
	CIDR    string `json:"cidr"`
	IsV6    bool   `json:"is_v6"`
}

func FormatJSONCountryPrefix(cc, cidr string, isV6 bool) (string, error) {
	data, err := json.Marshal(JSONCountryPrefix{Country: cc, CIDR: cidr, IsV6: isV6})
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}

// JSONCityPrefix is one CIDR block of a city listing.
type JSONCityPrefix struct {
	City    string `json:"city"`
	Region  string `json:"region,omitempty"`
	Country string `json:"country"`
	CIDR    string `json:"cidr"`
	IsV6    bool   `json:"is_v6"`
}

func FormatJSONCityPrefix(p sources.CityPlace, cidr string, isV6 bool) (string, error) {
	data, err := json.Marshal(JSONCityPrefix{City: p.City, Region: p.Region, Country: p.Country, CIDR: cidr, IsV6: isV6})
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}

// JSONNetblockSearchResult is one netblock search match. Type is always
// "netblock". Query is set when several queries are read from stdin.
type JSONNetblockSearchResult struct {
	Query      string   `json:"query,omitempty"`
	Type       string   `json:"type"`
	RangeStart string   `json:"range_start"`
	RangeEnd   string   `json:"range_end"`
	CIDRs      []string `json:"cidrs"`
	Netname    string   `json:"netname,omitempty"`
	Org        string   `json:"org,omitempty"`
	IsV6       bool     `json:"is_v6"`
	ASN        string   `json:"asn,omitempty"`
	ASName     string   `json:"as_name,omitempty"`
	Country    string   `json:"country,omitempty"`
	// Match is how a fuzzy search matched: exact, compact or words.
	Match string `json:"match,omitempty"`
}

// NewJSONNetblockSearchResult converts an engine netblock match for JSON output.
func NewJSONNetblockSearchResult(res engine.NetblockEnrichedResult, query string) JSONNetblockSearchResult {
	return JSONNetblockSearchResult{
		Query:      query,
		Type:       "netblock",
		RangeStart: res.RangeStart.String(),
		RangeEnd:   res.RangeEnd.String(),
		CIDRs:      res.CIDRs,
		Netname:    res.Netname,
		Org:        res.Org,
		IsV6:       res.IsV6,
		ASN:        res.ASN,
		ASName:     res.ASName,
		Country:    res.Country,
		Match:      sources.MatchName(res.Match),
	}
}

func FormatJSONNetblockOutput(res engine.NetblockEnrichedResult, query string) (string, error) {
	data, err := json.Marshal(NewJSONNetblockSearchResult(res, query))
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}

// JSONVersion is the output of `asname version --json`.
type JSONVersion struct {
	Version string `json:"version"`
	Dir     string `json:"dir"`
	// MaxAgeHours is the age at which auto-update refreshes a database; 0
	// when it is off.
	MaxAgeHours float64 `json:"max_age_hours"`
	// IPv6Routes reports whether ASN updates import IPv6 routes.
	IPv6Routes bool         `json:"ipv6_routes"`
	Databases  []JSONDBInfo `json:"databases"`
	// MaxAgeSource says where MaxAgeHours came from: off (--no-update),
	// flag (--max-age or ASNAME_MAX_AGE), saved (from the web UI) or
	// default. Only the REST server's /v1/status sets it.
	MaxAgeSource string `json:"max_age_source,omitempty"`
}

// JSONDBInfo describes one data file. Updated is when asname last wrote it;
// Built, when present, is when its source data was built.
type JSONDBInfo struct {
	Name       string     `json:"name"`
	Key        string     `json:"key"`
	Path       string     `json:"path"`
	Optional   bool       `json:"optional"`
	Present    bool       `json:"present"`
	Size       int64      `json:"size,omitempty"`
	Updated    *time.Time `json:"updated,omitempty"`
	AgeSeconds int64      `json:"age_seconds,omitempty"`
	Built      *time.Time `json:"built,omitempty"`
	Stale      bool       `json:"stale"`
	// Missing names the sources the last update could not read; LastError
	// is set when it failed outright and the previous file was kept.
	Missing   []string `json:"missing,omitempty"`
	LastError string   `json:"last_error,omitempty"`
	// Sources lists every public source the database is built from, with
	// how each fared in the last update when recorded. VPNLists, for the
	// category database, says which list each vpn:<provider> tag came from.
	Sources  []sources.SourceStatus  `json:"sources,omitempty"`
	VPNLists []sources.VPNListStatus `json:"vpn_lists,omitempty"`
}

// FormatJSONVersion renders the version and database status as one JSON line.
func FormatJSONVersion(version, dir string, maxAge time.Duration, ipv6 bool, dbs []sources.DBStatus, now time.Time) (string, error) {
	b, err := json.Marshal(NewJSONVersion(version, dir, maxAge, ipv6, dbs, now))
	if err != nil {
		return "", err
	}
	return string(b) + "\n", nil
}

// NewJSONVersion converts the version and database status for JSON output.
func NewJSONVersion(version, dir string, maxAge time.Duration, ipv6 bool, dbs []sources.DBStatus, now time.Time) JSONVersion {
	out := JSONVersion{Version: version, Dir: dir, MaxAgeHours: maxAge.Hours(), IPv6Routes: ipv6, Databases: make([]JSONDBInfo, len(dbs))}
	for i, db := range dbs {
		info := JSONDBInfo{Name: db.Name, Key: db.UpdateKey, Path: db.Path, Optional: db.Optional, Present: db.Present, Missing: db.Missing, LastError: db.LastError,
			Sources: db.Sources, VPNLists: db.VPNLists}
		if db.Present {
			updated, age := db.Updated, now.Sub(db.Updated)
			info.Size, info.Updated, info.AgeSeconds = db.Size, &updated, int64(age/time.Second)
			info.Stale = maxAge > 0 && age > maxAge
		}
		if !db.Built.IsZero() {
			built := db.Built
			info.Built = &built
		}
		out.Databases[i] = info
	}
	return out
}

// asnNameParts splits an AS name into handle and organisation, for display.
func asnNameParts(name string) (handle, org string) {
	if name == "" || name == "Unknown" {
		return "", ""
	}
	handle, org, _ = sources.SplitASName(name)
	return handle, org
}
