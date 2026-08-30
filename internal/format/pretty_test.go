package format

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/flyingllama87/asname/internal/engine"
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
