package format

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/flyingllama87/asname/internal/engine"
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
	require.Equal(t, "IP: 8.8.8.8 → ASN: AS15169 → Name: GOOGLE - Google LLC, US → Country: US, United States\n", got)
}

func TestFormatLookupOutputUniform(t *testing.T) {
	got := FormatLookupOutput(googleResult(), true, false)
	require.Equal(t, fmt.Sprintf("IP: %-*s → ASN: %-*s → Name: %-*s → Country: %s\n",
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

	require.Equal(t, fmt.Sprintf("IP: %-*s → ASN: %-*s → Name: %-*s → Country: %-*s → Reverse DNS: %s\n",
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

	require.Equal(t, "Host: dns.google → IP: 8.8.8.8 → ASN: AS15169 → Name: GOOGLE - Google LLC, US → Country: US, United States\n", got)
}

func TestFormatLookupOutputUniformHostColumnIsAligned(t *testing.T) {
	withHost := googleResult()
	withHost.Host = "dns.google"

	got := FormatLookupOutput(withHost, true, true)
	require.Equal(t, fmt.Sprintf("Host: %-*s → IP: %-*s → ASN: %-*s → Name: %-*s → Country: %s\n",
		UniformHostWidth, "dns.google",
		UniformIPWidth, "8.8.8.8",
		UniformASNWidth, "AS15169",
		UniformNameWidth, "GOOGLE - Google LLC, US",
		"US, United States"), got)

	bare := FormatLookupOutput(googleResult(), true, true)
	require.True(t, strings.HasPrefix(bare, "Host: -"))
	require.Equal(t, strings.Index(got, " → IP:"), strings.Index(bare, " → IP:"))
}

func TestFormatLookupOutputOmitsEmptyHost(t *testing.T) {
	require.NotContains(t, FormatLookupOutput(googleResult(), false, true), "Host:")
}

func TestFormatLookupOutputCity(t *testing.T) {
	res := googleResult()
	require.NotContains(t, FormatLookupOutput(res, false, false), "City:")

	res.City = "Mountain View, California"
	require.Contains(t, FormatLookupOutput(res, false, false), "→ City: Mountain View, California\n")
}

func TestFormatLookupOutputCityUniform(t *testing.T) {
	res := googleResult()
	res.City = "Mountain View, California"
	res.RDNS = "dns.google"

	got := FormatLookupOutput(res, true, false)
	require.Contains(t, got, "→ City: Mountain View, California")
	require.Contains(t, got, "→ Reverse DNS: dns.google\n")
	require.Contains(t, got, "Mountain View, California          → Reverse DNS")
}
