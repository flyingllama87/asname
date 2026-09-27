package format

import (
	"encoding/csv"
	"strconv"
	"strings"

	"github.com/flyingllama87/asname/internal/engine"
	"github.com/flyingllama87/asname/internal/sources"
)

// CSV output is RFC 4180: a header row, then one row per result. Its fields
// are those of the JSON output, flattened; a field that holds several values
// separates them with spaces, and an unknown value is an empty field.

// LookupCSVHeader names the columns of FormatCSVLookupOutput and FormatCSVError.
var LookupCSVHeader = []string{
	"target", "host", "ip", "version", "asn", "as_name", "country_code", "country_name",
	"city", "netblock", "netblock_source", "category", "reverse_dns",
	"prefixes", "error",
}

// SearchCSVHeader names the columns of FormatCSVASNSearchOutput and
// FormatCSVNetblockOutput; type is "asn" or "netblock".
var SearchCSVHeader = []string{
	"type", "asn", "as_name", "country", "netname", "org", "range_start", "range_end",
	"version", "cidrs", "ipv4_prefixes", "ipv6_prefixes",
}

// CountryCSVHeader names the columns of FormatCSVCountryPrefix.
var CountryCSVHeader = []string{"country", "cidr", "version"}

// CityCSVHeader names the columns of FormatCSVCityPrefix.
var CityCSVHeader = []string{"city", "region", "country", "cidr", "version"}

// FormatCSVRow renders fields as one CSV line, quoting them where needed.
func FormatCSVRow(fields []string) string {
	var b strings.Builder
	w := csv.NewWriter(&b)
	_ = w.Write(fields) // a strings.Builder never fails
	w.Flush()
	return b.String()
}

// FormatCSVLookupOutput renders one lookup result as a LookupCSVHeader row.
func FormatCSVLookupOutput(res engine.LookupResult) string {
	j := ToJSONResult(res)
	row := make(map[string]string, len(LookupCSVHeader))
	row["target"] = j.Target
	if j.Host != nil {
		row["host"] = *j.Host
	}
	row["ip"] = j.IP
	if j.Version != 0 {
		row["version"] = strconv.Itoa(j.Version)
	}
	if j.ASN != nil && j.ASN.Number != 0 {
		row["asn"] = j.ASN.ASNString
		row["as_name"] = j.ASN.Name
	}
	if j.Country != nil {
		row["country_code"], row["country_name"] = j.Country.Code, j.Country.Name
	}
	if j.City != nil {
		row["city"] = j.City.Name
	}
	if j.Netblock != nil {
		row["netblock"] = j.Netblock.Raw
		row["netblock_source"] = j.Netblock.Source
	}
	if j.Category != nil {
		row["category"] = strings.Join(j.Category.Tags, " ")
	}
	if j.ReverseDNS != nil {
		row["reverse_dns"] = strings.Join(j.ReverseDNS.Names, " ")
	}
	if j.Prefixes != nil {
		row["prefixes"] = strings.Join(j.Prefixes.List, " ")
	}
	return formatCSVColumns(LookupCSVHeader, row)
}

// FormatCSVError renders a target that could not be looked up as a
// LookupCSVHeader row.
func FormatCSVError(target, errStr string) string {
	return formatCSVColumns(LookupCSVHeader, map[string]string{"target": target, "error": errStr})
}

// FormatCSVASNSearchOutput renders an AS name match as a SearchCSVHeader row.
func FormatCSVASNSearchOutput(res engine.ASNSearchResult) string {
	j := NewJSONASNSearchResult(res)
	return formatCSVColumns(SearchCSVHeader, map[string]string{
		"type":          j.Type,
		"asn":           j.ASN,
		"as_name":       j.Name,
		"country":       j.Country,
		"ipv4_prefixes": strings.Join(j.IPv4Prefixes, " "),
		"ipv6_prefixes": strings.Join(j.IPv6Prefixes, " "),
	})
}

// FormatCSVNetblockOutput renders a netblock match as a SearchCSVHeader row.
func FormatCSVNetblockOutput(res engine.NetblockEnrichedResult) string {
	j := NewJSONNetblockSearchResult(res)
	return formatCSVColumns(SearchCSVHeader, map[string]string{
		"type":        j.Type,
		"asn":         j.ASN,
		"as_name":     j.ASName,
		"country":     j.Country,
		"netname":     j.Netname,
		"org":         j.Org,
		"range_start": j.RangeStart,
		"range_end":   j.RangeEnd,
		"version":     ipVersion(j.IsV6),
		"cidrs":       strings.Join(j.CIDRs, " "),
	})
}

// FormatCSVCountryPrefix renders one of a country's blocks as a
// CountryCSVHeader row.
func FormatCSVCountryPrefix(cc, cidr string, isV6 bool) string {
	return FormatCSVRow([]string{cc, cidr, ipVersion(isV6)})
}

// FormatCSVCityPrefix renders one of a place's blocks as a CityCSVHeader row.
func FormatCSVCityPrefix(p sources.CityPlace, cidr string, isV6 bool) string {
	return FormatCSVRow([]string{p.City, p.Region, p.Country, cidr, ipVersion(isV6)})
}

func formatCSVColumns(header []string, row map[string]string) string {
	fields := make([]string, len(header))
	for i, name := range header {
		fields[i] = row[name]
	}
	return FormatCSVRow(fields)
}

func ipVersion(isV6 bool) string {
	if isV6 {
		return "6"
	}
	return "4"
}
