package format

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/flyingllama87/asname/internal/engine"
	"github.com/flyingllama87/asname/internal/sources"
)

func samplePrettyResult() engine.LookupResult {
	return engine.LookupResult{
		Target:   "8.8.8.8",
		IP:       net.ParseIP("8.8.8.8"),
		ASN:      "AS15169",
		Name:     "GOOGLE - Google LLC, US",
		Country:  "US, United States",
		City:     "Mountain View, California",
		Netblock: "GOGL (Google LLC)",
		Category: "cdn, hosting",
		RDNS:     "dns.google",
	}
}

func TestFormatPrettyLookupOutputPlain(t *testing.T) {
	res := samplePrettyResult()
	out := FormatPrettyLookupOutput(res, 0, 1, false)

	require.NotContains(t, out, "\033[")
	require.Contains(t, out, "Target: 8.8.8.8")
	require.Contains(t, out, "────────────────────────────────────────────────────────────")
	require.Contains(t, out, "Address Details:")
	require.Contains(t, out, "IP Address:        8.8.8.8 (IPv4)")
	require.Contains(t, out, "Reverse DNS:       dns.google")
	require.Contains(t, out, "Autonomous System:")
	require.Contains(t, out, "ASN:               AS15169")
	require.Contains(t, out, "Organization:      GOOGLE - Google LLC, US")
	require.Contains(t, out, "Location:")
	require.Contains(t, out, "Country:           United States (US)")
	require.Contains(t, out, "City:              Mountain View, California")
	require.Contains(t, out, "Registry Netblock:")
	require.Contains(t, out, "Netname / Org:     GOGL (Google LLC)")
	require.Contains(t, out, "Source:            Offline Index")
	require.Contains(t, out, "Network Classification:")
	require.Contains(t, out, "Category:          cdn, hosting")
}

func TestFormatPrettyLookupOutputSources(t *testing.T) {
	out := FormatPrettyLookupOutput(samplePrettyResult(), 0, 1, false)

	require.Contains(t, out, "Country:           United States (US) [RIR registration]")
	require.Contains(t, out, "City:              Mountain View, California [DB-IP geolocation]")
	require.Contains(t, out, "Data Sources:")
	require.Contains(t, out, "ASN:               "+srcRIB)
	require.Contains(t, out, "Organization:      "+srcASNames)
	require.Contains(t, out, "Country:           "+srcRIR)
	require.Contains(t, out, "City:              "+srcCity)
	require.Contains(t, out, "Netblock:          "+srcNetblock)
	require.Contains(t, out, "Category:          "+srcCategory)
	require.Contains(t, out, "Reverse DNS:       "+srcRDNS)
}

func TestFormatPrettyLookupOutputVPNList(t *testing.T) {
	res := samplePrettyResult()
	res.Category = "cloud:vultr, vpn:mullvad, vpn:private-internet-access"
	res.VPNLists = map[string]sources.VPNList{
		"vpn:private-internet-access": {Source: "PIA server list", Date: time.Date(2026, 10, 27, 4, 0, 0, 0, time.UTC)},
		"vpn:mullvad":                 {Source: "gluetun server list for mullvad"},
	}
	out := FormatPrettyLookupOutput(res, 0, 1, false)

	require.Contains(t, out, "VPN servers:       gluetun server list for mullvad, offline\n    VPN servers:       PIA server list, as of 2026-10-27, offline")
	require.NotContains(t, FormatPrettyLookupOutput(samplePrettyResult(), 0, 1, false), "VPN servers:")
}

func TestFormatPrettyLookupOutputSourcesOmitAbsentFields(t *testing.T) {
	res := samplePrettyResult()
	res.City, res.Netblock, res.Category, res.RDNS = "", "", "", ""
	out := FormatPrettyLookupOutput(res, 0, 1, false)

	require.Contains(t, out, "Country:           "+srcRIR)
	require.NotContains(t, out, srcCity)
	require.NotContains(t, out, srcNetblock)
	require.NotContains(t, out, srcCategory)
	require.NotContains(t, out, srcRDNS)
}

func TestFormatPrettyASNOutputSources(t *testing.T) {
	res := engine.LookupResult{
		ASN:          "AS15169",
		IsASN:        true,
		Name:         "GOOGLE - Google LLC, US",
		Country:      "US, United States",
		Prefixes:     []string{"8.8.8.0/24"},
		IPv4Prefixes: []string{"8.8.8.0/24"},
		PrefixSource: "ripe-stat",
	}
	out := FormatPrettyLookupOutput(res, 0, 1, false)

	require.Contains(t, out, "Country:           United States (US) [AS registration]")
	require.Contains(t, out, "Country:           "+srcASNames)
	require.Contains(t, out, "Prefixes:          "+srcRIPEStat)
}

func TestFormatPrettyLookupOutputColor(t *testing.T) {
	res := samplePrettyResult()
	out := FormatPrettyLookupOutput(res, 0, 1, true)

	require.Contains(t, out, ansiBoldCyan)
	require.Contains(t, out, ansiReset)
	require.Contains(t, out, ansiBoldMagenta)
	require.Contains(t, out, ansiGreen)
}

func TestFormatPrettyLookupOutputIPv6(t *testing.T) {
	res := engine.LookupResult{
		Target:  "2001:4860:4860::8888",
		IP:      net.ParseIP("2001:4860:4860::8888"),
		ASN:     "AS15169",
		Name:    "GOOGLE - Google LLC, US",
		Country: "US, United States",
	}

	out := FormatPrettyLookupOutput(res, 0, 1, false)
	require.Contains(t, out, "IP Address:        2001:4860:4860::8888 (IPv6)")
}

func TestFormatPrettyLookupOutputLiveWhois(t *testing.T) {
	res := samplePrettyResult()
	res.NetblockLive = true

	out := FormatPrettyLookupOutput(res, 0, 1, false)
	require.Contains(t, out, "Source:            Live WHOIS")
	require.Contains(t, out, "Netblock:          "+srcWhois)
}

func TestFormatLiveRDAP(t *testing.T) {
	res := samplePrettyResult()
	res.NetblockLive = true
	res.NetblockSource = sources.OnlineSourceRDAP

	out := FormatPrettyLookupOutput(res, 0, 1, false)
	require.Contains(t, out, "Source:            Live RDAP")
	require.Contains(t, out, "Netblock:          "+srcRDAP)

	j := ToJSONResult(res)
	require.Equal(t, "rdap", j.Netblock.Source)
	require.True(t, j.Netblock.LiveQuery)

	res.NetblockSource = ""
	require.Equal(t, "whois", ToJSONResult(res).Netblock.Source, "live results from before RDAP were whois")
}

func TestFormatPrettyLookupOutputMultiTargetIndex(t *testing.T) {
	res := samplePrettyResult()
	out := FormatPrettyLookupOutput(res, 1, 3, false)

	require.Contains(t, out, "Target: [2/3] 8.8.8.8")
}

func TestFormatCountryPretty(t *testing.T) {
	require.Equal(t, "United States (US)", FormatCountryPretty("US, United States"))
	require.Equal(t, "Australia (AU)", FormatCountryPretty("AU, Australia"))
	require.Equal(t, "Unknown", FormatCountryPretty("Unknown"))
	require.Equal(t, "Unknown", FormatCountryPretty(""))
	require.Equal(t, "US", FormatCountryPretty("US"))
}

func TestShouldColorize(t *testing.T) {
	require.False(t, ShouldColorize(nil, false, true))
	require.True(t, ShouldColorize(nil, true, false))
}

func TestFormatInferredCategory(t *testing.T) {
	res := samplePrettyResult()
	res.Category = "isp"
	res.Inferred = []engine.InferredTag{{Tag: "range:broadband", From: sources.InferredFromNetname}, {Tag: "finance", From: sources.InferredFromName}}

	out := FormatPrettyLookupOutput(res, 0, 1, false)
	require.Contains(t, out, "Category:          isp")
	require.Contains(t, out, "Inferred:          range:broadband [from the range's netname]")
	require.Contains(t, out, "                   finance [from the AS name]")
	require.Contains(t, out, "Inferred:          asname's rules on the registry netname; asname's rules on words in the AS name")

	require.Equal(t, "isp; inferred: range:broadband, finance", categoryWithInferred(res))
	j := ToJSONResult(res)
	require.Equal(t, []string{"isp"}, j.Category.Tags)
	require.Equal(t, []JSONInferredTag{{Tag: "range:broadband", From: "netname"}, {Tag: "finance", From: "name"}}, j.Category.Inferred)

	// Only inferred: the category says so rather than Unknown.
	res.Category = "Unknown"
	res.Inferred = []engine.InferredTag{{Tag: "hosting", From: sources.InferredFromList}}
	require.Equal(t, "inferred: hosting", categoryWithInferred(res))
	j = ToJSONResult(res)
	require.Equal(t, []string{}, j.Category.Tags)
	out = FormatPrettyLookupOutput(res, 0, 1, false)
	require.Contains(t, out, "[asname's list of known networks]")
}
