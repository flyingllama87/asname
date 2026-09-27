package format

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/flyingllama87/asname/internal/engine"
	"github.com/flyingllama87/asname/internal/sources"
)

func googleResult() engine.LookupResult {
	return engine.LookupResult{
		IP:      net.ParseIP("8.8.8.8"),
		ASN:     "AS15169",
		Name:    "GOOGLE - Google LLC, US",
		Country: "US, United States",
	}
}

func TestFormatLookupOutputDefault(t *testing.T) {
	got := FormatLookupOutput(googleResult(), false, false)
	require.Equal(t, "IP: 8.8.8.8 | ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States\n", got)
}

func TestFormatLookupOutputUniform(t *testing.T) {
	got := FormatLookupOutput(googleResult(), true, false)
	require.Equal(t, fmt.Sprintf("IP: %-*s | ASN: %-*s | Name: %-*s | Country: %s\n",
		UniformIPWidth, "8.8.8.8",
		UniformASNWidth, "AS15169",
		UniformNameWidth, "GOOGLE - Google LLC, US",
		"US, United States"), got)
	require.NotContains(t, strings.TrimSuffix(got, "\n"), "\n")
}

func TestFormatLookupOutputUniformWithReverseDNS(t *testing.T) {
	res := googleResult()
	res.RDNS = "dns.google"
	got := FormatLookupOutput(res, true, false)

	require.Equal(t, fmt.Sprintf("IP: %-*s | ASN: %-*s | Name: %-*s | Country: %-*s | Reverse DNS: %s\n",
		UniformIPWidth, "8.8.8.8",
		UniformASNWidth, "AS15169",
		UniformNameWidth, "GOOGLE - Google LLC, US",
		UniformCountryWidth, "US, United States",
		"dns.google"), got)
	require.NotContains(t, strings.TrimSuffix(got, "\n"), "\n")
}

func TestFormatLookupOutputWithHost(t *testing.T) {
	res := googleResult()
	res.Host = "dns.google"
	got := FormatLookupOutput(res, false, true)

	require.Equal(t, "Host: dns.google | IP: 8.8.8.8 | ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States\n", got)
}

func TestFormatLookupOutputUniformHostColumnIsAligned(t *testing.T) {
	withHost := googleResult()
	withHost.Host = "dns.google"

	got := FormatLookupOutput(withHost, true, true)
	require.Equal(t, fmt.Sprintf("Host: %-*s | IP: %-*s | ASN: %-*s | Name: %-*s | Country: %s\n",
		UniformHostWidth, "dns.google",
		UniformIPWidth, "8.8.8.8",
		UniformASNWidth, "AS15169",
		UniformNameWidth, "GOOGLE - Google LLC, US",
		"US, United States"), got)

	bare := FormatLookupOutput(googleResult(), true, true)
	require.True(t, strings.HasPrefix(bare, "Host: -"))
	require.Equal(t, strings.Index(got, " | IP:"), strings.Index(bare, " | IP:"))
}

func TestFormatLookupOutputOmitsEmptyHost(t *testing.T) {
	require.NotContains(t, FormatLookupOutput(googleResult(), false, true), "Host:")
}

func TestFormatLookupOutputCity(t *testing.T) {
	res := googleResult()
	require.NotContains(t, FormatLookupOutput(res, false, false), "City:")

	res.City = "Mountain View, California"
	require.Contains(t, FormatLookupOutput(res, false, false), "| City: Mountain View, California\n")
}

func TestFormatLookupOutputCityUniform(t *testing.T) {
	res := googleResult()
	res.City = "Mountain View, California"
	res.RDNS = "dns.google"

	got := FormatLookupOutput(res, true, false)
	require.Contains(t, got, "| City: Mountain View, California")
	require.Contains(t, got, "| Reverse DNS: dns.google\n")
	require.Contains(t, got, "Mountain View, California          | Reverse DNS")
}

func TestFormatLookupOutputASN(t *testing.T) {
	res := engine.LookupResult{
		Target:       "AS15169",
		ASN:          "AS15169",
		IsASN:        true,
		Name:         "GOOGLE - Google LLC, US",
		Country:      "US, United States",
		Category:     "cdn, content, hosting, vpn",
		Prefixes:     []string{"8.8.8.0/24", "2001:4860::/32"},
		IPv4Prefixes: []string{"8.8.8.0/24"},
		IPv6Prefixes: []string{"2001:4860::/32"},
	}
	got := FormatLookupOutput(res, false, false)
	require.Equal(t, "ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States | Category: cdn, content, hosting, vpn | Prefixes: 2 announced (1 IPv4, 1 IPv6)\n", got)
}

func TestFormatNetblockOutput(t *testing.T) {
	res := engine.NetblockEnrichedResult{
		NetblockSearchResult: sources.NetblockSearchResult{
			RangeStart: net.ParseIP("8.8.8.0"),
			RangeEnd:   net.ParseIP("8.8.8.255"),
			CIDRs:      []string{"8.8.8.0/24"},
			Netname:    "GOGL",
			Org:        "Google LLC",
		},
		ASN:     "AS15169",
		ASName:  "GOOGLE - Google LLC, US",
		Country: "US, United States",
	}
	got := FormatNetblockOutput(res, false)
	require.Equal(t, "Netblock: 8.8.8.0/24 | Org: Google LLC (GOGL) | ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States\n", got)
}


func TestFormatASNSearchOutput(t *testing.T) {
	res := engine.ASNSearchResult{Number: 15169, ASN: "AS15169", Name: "GOOGLE - Google LLC, US", Country: "US, United States"}
	require.Equal(t, "ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States\n", FormatASNSearchOutput(res))

	line, err := FormatJSONASNSearchOutput(res)
	require.NoError(t, err)
	require.Equal(t, `{"type":"asn","asn":"AS15169","name":"GOOGLE - Google LLC, US","country":"US, United States"}`+"\n", line)

	require.Contains(t, FormatPrettyASNSearchOutput(res, 0, 1, false), "AS Name:           GOOGLE - Google LLC, US")
}

func TestFormatASNSearchOutputWithPrefixes(t *testing.T) {
	res := engine.ASNSearchResult{
		ASN: "AS32590", Name: "VALVE-CORPORATION - Valve Corporation, US", Country: "US, United States",
		Prefixes: []string{"45.121.184.0/24", "2a01:bc80::/29"}, IPv4Prefixes: []string{"45.121.184.0/24"}, IPv6Prefixes: []string{"2a01:bc80::/29"},
	}
	require.Equal(t, "ASN: AS32590 | Name: VALVE-CORPORATION - Valve Corporation, US | Country: US, United States | Prefixes: 45.121.184.0/24, 2a01:bc80::/29\n", FormatASNSearchOutput(res))

	line, err := FormatJSONASNSearchOutput(res)
	require.NoError(t, err)
	require.Contains(t, line, `"ipv4_prefixes":["45.121.184.0/24"],"ipv6_prefixes":["2a01:bc80::/29"]`)

	require.Contains(t, FormatPrettyASNSearchOutput(res, 0, 1, false), "Announced Prefixes: 2 (1 IPv4, 1 IPv6)")
}
