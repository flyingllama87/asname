package asname

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/flyingllama87/asname/internal/engine"
)

// Result is everything known about an IP address, hostname, URL, or ASN.
type Result struct {
	Target       string   `json:"target,omitempty"`
	Host         string   `json:"host,omitempty"`
	IP           net.IP   `json:"ip,omitempty"`
	ASN          string   `json:"asn,omitempty"`
	Name         string   `json:"name,omitempty"`
	Country      string   `json:"country,omitempty"`
	City         string   `json:"city,omitempty"`
	Netblock     string   `json:"netblock,omitempty"`
	NetblockLive bool     `json:"netblock_live,omitempty"`
	Category     string   `json:"category,omitempty"`
	RDNS         string   `json:"rdns,omitempty"`
	IsASN        bool     `json:"is_asn,omitempty"`
	Prefixes     []string `json:"prefixes,omitempty"`
	IPv4Prefixes []string `json:"ipv4_prefixes,omitempty"`
	IPv6Prefixes []string `json:"ipv6_prefixes,omitempty"`
	PrefixSource string   `json:"prefix_source,omitempty"`
}

// ASNNumber parses and returns the numeric ASN (e.g. 15169 for "AS15169").
// Returns 0 if the ASN is missing or not a valid number.
func (r Result) ASNNumber() uint32 {
	if r.ASN == "" || r.ASN == "N/A" {
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
	if r.Country == "" || r.Country == "Unknown" {
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
	if r.Country == "" || r.Country == "Unknown" {
		return ""
	}
	if i := strings.Index(r.Country, ","); i >= 0 && i+1 < len(r.Country) {
		return strings.TrimSpace(r.Country[i+1:])
	}
	return r.Country
}

// String returns a human-readable one-line summary.
func (r Result) String() string {
	if r.IsASN {
		s := fmt.Sprintf("ASN: %s → Name: %s → Country: %s", r.ASN, r.Name, r.Country)
		if r.Category != "" {
			s += " → Category: " + r.Category
		}
		return s
	}
	s := fmt.Sprintf("IP: %s → ASN: %s → Name: %s → Country: %s", r.IP, r.ASN, r.Name, r.Country)
	if r.City != "" && r.City != "Unknown" {
		s += " → City: " + r.City
	}
	if r.Netblock != "" && r.Netblock != "Unknown" {
		s += " → Netblock: " + r.Netblock
	}
	if r.Category != "" && r.Category != "Unknown" {
		s += " → Category: " + r.Category
	}
	if r.RDNS != "" && r.RDNS != "N/A" {
		s += " → RDNS: " + r.RDNS
	}
	return s
}

func resultFromEngine(r engine.LookupResult) Result {
	return Result{
		Target:       r.Target,
		Host:         r.Host,
		IP:           r.IP,
		ASN:          r.ASN,
		Name:         r.Name,
		Country:      r.Country,
		City:         r.City,
		Netblock:     r.Netblock,
		NetblockLive: r.NetblockLive,
		Category:     r.Category,
		RDNS:         r.RDNS,
		IsASN:        r.IsASN,
		Prefixes:     r.Prefixes,
		IPv4Prefixes: r.IPv4Prefixes,
		IPv6Prefixes: r.IPv6Prefixes,
		PrefixSource: r.PrefixSource,
	}
}

// SearchOptions controls search filters and limits for Netblock searches.
type SearchOptions struct {
	Limit  int
	V4Only bool
	V6Only bool
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
		ASN:        r.ASN,
		ASName:     r.ASName,
		Country:    r.Country,
	}
}
