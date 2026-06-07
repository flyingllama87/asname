package main

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFormatLookupOutputDefault(t *testing.T) {
	got := formatLookupOutput(
		net.ParseIP("8.8.8.8"),
		"AS15169",
		"GOOGLE - Google LLC, US",
		"US, United States",
		"",
		false,
	)

	require.Equal(t, "IP: 8.8.8.8 → ASN: AS15169 → Name: GOOGLE - Google LLC, US → Country: US, United States\n", got)
}

func TestFormatLookupOutputUniform(t *testing.T) {
	got := formatLookupOutput(
		net.ParseIP("8.8.8.8"),
		"AS15169",
		"GOOGLE - Google LLC, US",
		"US, United States",
		"",
		true,
	)

	require.Equal(t, fmt.Sprintf("IP: %-*s → ASN: %-*s → Name: %-*s → Country: %s\n",
		uniformIPWidth, "8.8.8.8",
		uniformASNWidth, "AS15169",
		uniformNameWidth, "GOOGLE - Google LLC, US",
		"US, United States"), got)
	require.NotContains(t, strings.TrimSuffix(got, "\n"), "\n")
}

func TestFormatLookupOutputUniformWithReverseDNS(t *testing.T) {
	got := formatLookupOutput(
		net.ParseIP("8.8.8.8"),
		"AS15169",
		"GOOGLE - Google LLC, US",
		"US, United States",
		"dns.google",
		true,
	)

	require.Equal(t, fmt.Sprintf("IP: %-*s → ASN: %-*s → Name: %-*s → Country: %-*s → Reverse DNS: %s\n",
		uniformIPWidth, "8.8.8.8",
		uniformASNWidth, "AS15169",
		uniformNameWidth, "GOOGLE - Google LLC, US",
		uniformCountryWidth, "US, United States",
		"dns.google"), got)
	require.NotContains(t, strings.TrimSuffix(got, "\n"), "\n")
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
