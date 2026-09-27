package format

import (
	"encoding/csv"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/flyingllama87/asname/internal/engine"
	"github.com/flyingllama87/asname/internal/sources"
)

// parseCSVRow parses one CSV line into a map keyed by header.
func parseCSVRow(t *testing.T, header []string, line string) map[string]string {
	t.Helper()
	fields, err := csv.NewReader(strings.NewReader(line)).Read()
	require.NoError(t, err)
	require.Len(t, fields, len(header))
	row := map[string]string{}
	for i, name := range header {
		row[name] = fields[i]
	}
	return row
}

func TestFormatCSVRowQuotes(t *testing.T) {
	assert.Equal(t, "a,\"b, c\",\"say \"\"hi\"\"\"\n", FormatCSVRow([]string{"a", "b, c", `say "hi"`}))
}

func TestFormatCSVLookupOutput(t *testing.T) {
	row := parseCSVRow(t, LookupCSVHeader, FormatCSVLookupOutput(engine.LookupResult{
		Target:   "dns.google",
		Host:     "dns.google",
		IP:       net.ParseIP("8.8.8.8"),
		ASN:      "AS15169",
		Name:     "GOOGLE - Google LLC, US",
		Country:  "US, United States",
		City:     "Mountain View, California",
		Netblock: "GOGL (Google LLC)",
		Category: "cdn, hosting",
		RDNS:     "dns.google",
	}))
	assert.Equal(t, map[string]string{
		"target": "dns.google", "host": "dns.google", "ip": "8.8.8.8", "version": "4",
		"asn": "AS15169", "as_name": "GOOGLE - Google LLC, US",
		"country_code": "US", "country_name": "United States", "city": "Mountain View, California",
		"netblock": "GOGL (Google LLC)", "netblock_source": "offline",
		"category": "cdn hosting", "reverse_dns": "dns.google", "prefixes": "", "error": "",
	}, row)

	unknown := parseCSVRow(t, LookupCSVHeader, FormatCSVLookupOutput(engine.LookupResult{
		Target: "2001:db8::1", IP: net.ParseIP("2001:db8::1"), ASN: "N/A", Name: "Unknown", Country: "Unknown",
	}))
	assert.Equal(t, "6", unknown["version"])
	assert.Empty(t, unknown["asn"]+unknown["as_name"]+unknown["country_code"], "unknown values are empty")

	asn := parseCSVRow(t, LookupCSVHeader, FormatCSVLookupOutput(engine.LookupResult{
		Target: "AS15169", ASN: "AS15169", IsASN: true, Name: "GOOGLE",
		Prefixes: []string{"8.8.8.0/24", "2001:4860::/32"}, IPv4Prefixes: []string{"8.8.8.0/24"}, IPv6Prefixes: []string{"2001:4860::/32"},
	}))
	assert.Equal(t, "8.8.8.0/24 2001:4860::/32", asn["prefixes"])
	assert.Empty(t, asn["version"])

	failed := parseCSVRow(t, LookupCSVHeader, FormatCSVError("nope.invalid", "lookup nope.invalid: no such host"))
	assert.Equal(t, "nope.invalid", failed["target"])
	assert.Equal(t, "lookup nope.invalid: no such host", failed["error"])
}

func TestFormatCSVSearchOutput(t *testing.T) {
	asn := parseCSVRow(t, SearchCSVHeader, FormatCSVASNSearchOutput(engine.ASNSearchResult{
		Number: 64500, ASN: "AS64500", Name: "VALVE-CORP - Valve Corporation, US", Country: "US",
		IPv4Prefixes: []string{"208.64.200.0/22", "103.28.54.0/24"},
	}))
	assert.Equal(t, "asn", asn["type"])
	assert.Equal(t, "208.64.200.0/22 103.28.54.0/24", asn["ipv4_prefixes"])

	var nb engine.NetblockEnrichedResult
	nb.RangeStart, nb.RangeEnd = net.ParseIP("8.8.8.0"), net.ParseIP("8.8.8.255")
	nb.CIDRs, nb.Netname, nb.Org = []string{"8.8.8.0/24"}, "GOGL", "Google LLC"
	nb.ASN, nb.ASName, nb.Country = "AS15169", "GOOGLE", "US"
	row := parseCSVRow(t, SearchCSVHeader, FormatCSVNetblockOutput(nb))
	assert.Equal(t, "netblock", row["type"])
	assert.Equal(t, "8.8.8.0/24", row["cidrs"])
	assert.Equal(t, "4", row["version"])
	assert.Equal(t, "Google LLC", row["org"])
}

func TestFormatCSVBlocks(t *testing.T) {
	assert.Equal(t, "AU,2001:db8::/32,6\n", FormatCSVCountryPrefix("AU", "2001:db8::/32", true))
	assert.Equal(t, "Brisbane,Queensland,AU,1.0.0.0/23,4\n",
		FormatCSVCityPrefix(sources.CityPlace{City: "Brisbane", Region: "Queensland", Country: "AU"}, "1.0.0.0/23", false))
}
