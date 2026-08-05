package main

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func googleResult() lookupResult {
	return lookupResult{
		ip:      net.ParseIP("8.8.8.8"),
		asn:     "AS15169",
		name:    "GOOGLE - Google LLC, US",
		country: "US, United States",
	}
}

func TestFormatLookupOutputDefault(t *testing.T) {
	got := formatLookupOutput(googleResult(), false, false)

	require.Equal(t, "IP: 8.8.8.8 → ASN: AS15169 → Name: GOOGLE - Google LLC, US → Country: US, United States\n", got)
}

func TestFormatLookupOutputUniform(t *testing.T) {
	got := formatLookupOutput(googleResult(), true, false)

	require.Equal(t, fmt.Sprintf("IP: %-*s → ASN: %-*s → Name: %-*s → Country: %s\n",
		uniformIPWidth, "8.8.8.8",
		uniformASNWidth, "AS15169",
		uniformNameWidth, "GOOGLE - Google LLC, US",
		"US, United States"), got)
	require.NotContains(t, strings.TrimSuffix(got, "\n"), "\n")
}

func TestFormatLookupOutputUniformWithReverseDNS(t *testing.T) {
	res := googleResult()
	res.rdns = "dns.google"
	got := formatLookupOutput(res, true, false)

	require.Equal(t, fmt.Sprintf("IP: %-*s → ASN: %-*s → Name: %-*s → Country: %-*s → Reverse DNS: %s\n",
		uniformIPWidth, "8.8.8.8",
		uniformASNWidth, "AS15169",
		uniformNameWidth, "GOOGLE - Google LLC, US",
		uniformCountryWidth, "US, United States",
		"dns.google"), got)
	require.NotContains(t, strings.TrimSuffix(got, "\n"), "\n")
}

func TestFormatLookupOutputWithHost(t *testing.T) {
	res := googleResult()
	res.host = "dns.google"
	got := formatLookupOutput(res, false, true)

	require.Equal(t, "Host: dns.google → IP: 8.8.8.8 → ASN: AS15169 → Name: GOOGLE - Google LLC, US → Country: US, United States\n", got)
}

// A run that mixes hostnames and literal IPs keeps the host column on every
// uniform line so the fields stay aligned.
func TestFormatLookupOutputUniformHostColumnIsAligned(t *testing.T) {
	withHost := googleResult()
	withHost.host = "dns.google"

	got := formatLookupOutput(withHost, true, true)
	require.Equal(t, fmt.Sprintf("Host: %-*s → IP: %-*s → ASN: %-*s → Name: %-*s → Country: %s\n",
		uniformHostWidth, "dns.google",
		uniformIPWidth, "8.8.8.8",
		uniformASNWidth, "AS15169",
		uniformNameWidth, "GOOGLE - Google LLC, US",
		"US, United States"), got)

	bare := formatLookupOutput(googleResult(), true, true)
	require.True(t, strings.HasPrefix(bare, "Host: -"))
	require.Equal(t, strings.Index(got, " → IP:"), strings.Index(bare, " → IP:"))
}

// Without a host column, a literal-IP run prints exactly what it always has.
func TestFormatLookupOutputOmitsEmptyHost(t *testing.T) {
	require.NotContains(t, formatLookupOutput(googleResult(), false, true), "Host:")
}

func TestFormatReverseDNSNames(t *testing.T) {
	got := formatReverseDNSNames([]string{
		"dns.google.",
		"",
		"backup.example.net.",
		"resolver.example.com",
	})

	require.Equal(t, "backup.example.net, dns.google, resolver.example.com", got)
}
