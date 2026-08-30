package main

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func samplePrettyResult() lookupResult {
	return lookupResult{
		target:   "8.8.8.8",
		ip:       net.ParseIP("8.8.8.8"),
		asn:      "AS15169",
		name:     "GOOGLE - Google LLC, US",
		country:  "US, United States",
		city:     "Mountain View, California",
		netblock: "GOGL (Google LLC)",
		category: "cdn, hosting",
		rdns:     "dns.google",
	}
}

func TestFormatPrettyLookupOutputPlain(t *testing.T) {
	res := samplePrettyResult()
	out := formatPrettyLookupOutput(res, 0, 1, false)

	// Verify absence of ANSI escape codes
	require.NotContains(t, out, "\033[")

	// Verify sections and structure
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

func TestFormatPrettyLookupOutputColor(t *testing.T) {
	res := samplePrettyResult()
	out := formatPrettyLookupOutput(res, 0, 1, true)

	// Verify presence of ANSI escape codes
	require.Contains(t, out, ansiBoldCyan)
	require.Contains(t, out, ansiReset)
	require.Contains(t, out, ansiBoldMagenta)
	require.Contains(t, out, ansiGreen)
}

func TestFormatPrettyLookupOutputIPv6(t *testing.T) {
	res := lookupResult{
		target:  "2001:4860:4860::8888",
		ip:      net.ParseIP("2001:4860:4860::8888"),
		asn:     "AS15169",
		name:    "GOOGLE - Google LLC, US",
		country: "US, United States",
	}

	out := formatPrettyLookupOutput(res, 0, 1, false)
	require.Contains(t, out, "IP Address:        2001:4860:4860::8888 (IPv6)")
}

func TestFormatPrettyLookupOutputLiveWhois(t *testing.T) {
	res := samplePrettyResult()
	res.netblockLive = true

	out := formatPrettyLookupOutput(res, 0, 1, false)
	require.Contains(t, out, "Source:            Live WHOIS")
}

func TestFormatPrettyLookupOutputMultiTargetIndex(t *testing.T) {
	res := samplePrettyResult()
	out := formatPrettyLookupOutput(res, 1, 3, false)

	require.Contains(t, out, "Target: [2/3] 8.8.8.8")
}

func TestFormatCountryPretty(t *testing.T) {
	require.Equal(t, "United States (US)", formatCountryPretty("US, United States"))
	require.Equal(t, "Australia (AU)", formatCountryPretty("AU, Australia"))
	require.Equal(t, "Unknown", formatCountryPretty("Unknown"))
	require.Equal(t, "Unknown", formatCountryPretty(""))
	require.Equal(t, "US", formatCountryPretty("US"))
}

func TestShouldColorize(t *testing.T) {
	require.False(t, shouldColorize(nil, false, true))
	require.True(t, shouldColorize(nil, true, false))
}
