package format

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/flyingllama87/asname/internal/engine"
	"github.com/flyingllama87/asname/internal/sources"
)

type JSONLookupResult struct {
	Target     string          `json:"target,omitempty"`
	Host       *string         `json:"host"`
	IP         string          `json:"ip,omitempty"`
	Version    int             `json:"version,omitempty"`
	ASN        *JSONASN        `json:"asn,omitempty"`
	Country    *JSONCountry    `json:"country,omitempty"`
	City       *JSONCity       `json:"city,omitempty"`
	Netblock   *JSONNetblock   `json:"netblock,omitempty"`
	Category   *JSONCategory   `json:"category,omitempty"`
	ReverseDNS *JSONReverseDNS `json:"reverse_dns,omitempty"`
	Prefixes   *JSONPrefixes   `json:"prefixes,omitempty"`
	Error      string          `json:"error,omitempty"`
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
	Announced bool   `json:"announced"`
}

type JSONCountry struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

type JSONCity struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
}

type JSONNetblock struct {
	Handle       string `json:"handle,omitempty"`
	Organization string `json:"organization,omitempty"`
	Raw          string `json:"raw"`
	Source       string `json:"source"`
	LiveQuery    bool   `json:"live_query"`
}

type JSONCategory struct {
	Tags []string `json:"tags"`
	Raw  string   `json:"raw"`
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
			Number:    uint32(num),
			ASNString: res.ASN,
			Name:      res.Name,
			Announced: true,
		}
		if res.Country != "" && res.Country != "Unknown" {
			parts := strings.SplitN(res.Country, ", ", 2)
			if len(parts) == 2 {
				out.Country = &JSONCountry{Code: parts[0], Name: parts[1]}
			} else {
				out.Country = &JSONCountry{Code: res.Country, Name: res.Country}
			}
		}
		if res.Category != "" {
			tags := strings.Split(res.Category, ", ")
			out.Category = &JSONCategory{Tags: tags, Raw: res.Category}
		}
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

	if res.ASN != "" && res.ASN != "N/A" {
		numStr := strings.TrimPrefix(res.ASN, "AS")
		num, _ := strconv.ParseUint(numStr, 10, 32)
		out.ASN = &JSONASN{
			Number:    uint32(num),
			ASNString: res.ASN,
			Name:      res.Name,
			Announced: true,
		}
	} else if res.ASN == "N/A" {
		out.ASN = &JSONASN{
			Number:    0,
			ASNString: "N/A",
			Name:      "Unknown",
			Announced: false,
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
		}
	}

	if res.Netblock != "" && res.Netblock != "Unknown" {
		src := "offline"
		if res.NetblockLive {
			src = "whois"
		}
		handle, org := ParseNetblockField(res.Netblock)
		out.Netblock = &JSONNetblock{
			Handle:       handle,
			Organization: org,
			Raw:          res.Netblock,
			Source:       src,
			LiveQuery:    res.NetblockLive,
		}
	}

	if res.Category != "" && res.Category != "Unknown" {
		rawTags := strings.Split(res.Category, ", ")
		tags := make([]string, 0, len(rawTags))
		for _, t := range rawTags {
			t = strings.TrimSpace(t)
			if t != "" {
				tags = append(tags, t)
			}
		}
		out.Category = &JSONCategory{
			Tags: tags,
			Raw:  res.Category,
		}
	}

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
type JSONASNSearchResult struct {
	Type         string   `json:"type"`
	ASN          string   `json:"asn"`
	Name         string   `json:"name"`
	Country      string   `json:"country,omitempty"`
	IPv4Prefixes []string `json:"ipv4_prefixes,omitempty"`
	IPv6Prefixes []string `json:"ipv6_prefixes,omitempty"`
}

// NewJSONASNSearchResult converts an engine AS name match for JSON output.
func NewJSONASNSearchResult(res engine.ASNSearchResult) JSONASNSearchResult {
	return JSONASNSearchResult{
		Type:         "asn",
		ASN:          res.ASN,
		Name:         res.Name,
		Country:      res.Country,
		IPv4Prefixes: res.IPv4Prefixes,
		IPv6Prefixes: res.IPv6Prefixes,
	}
}

func FormatJSONASNSearchOutput(res engine.ASNSearchResult) (string, error) {
	data, err := json.Marshal(NewJSONASNSearchResult(res))
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
// "netblock".
type JSONNetblockSearchResult struct {
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
}

// NewJSONNetblockSearchResult converts an engine netblock match for JSON output.
func NewJSONNetblockSearchResult(res engine.NetblockEnrichedResult) JSONNetblockSearchResult {
	return JSONNetblockSearchResult{
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
	}
}

func FormatJSONNetblockOutput(res engine.NetblockEnrichedResult) (string, error) {
	data, err := json.Marshal(NewJSONNetblockSearchResult(res))
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}
