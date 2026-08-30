package main

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJSONLookupOutputSerialization(t *testing.T) {
	res := lookupResult{
		target:       "https://dns.google/resolve",
		host:         "dns.google",
		ip:           net.ParseIP("8.8.8.8"),
		asn:          "AS15169",
		name:         "GOOGLE - Google LLC, US",
		country:      "US, United States",
		city:         "Mountain View, California",
		netblock:     "GOGL (Google LLC)",
		netblockLive: false,
		category:     "cdn, cloud:gcp",
		rdns:         "dns.google",
	}

	line, err := formatJSONLookupOutput(res)
	require.NoError(t, err)

	var parsed jsonLookupResult
	err = json.Unmarshal([]byte(line), &parsed)
	require.NoError(t, err)

	require.Equal(t, "https://dns.google/resolve", parsed.Target)
	require.NotNil(t, parsed.Host)
	require.Equal(t, "dns.google", *parsed.Host)
	require.Equal(t, "8.8.8.8", parsed.IP)
	require.Equal(t, 4, parsed.Version)

	// ASN
	require.NotNil(t, parsed.ASN)
	require.Equal(t, uint32(15169), parsed.ASN.Number)
	require.Equal(t, "AS15169", parsed.ASN.ASNString)
	require.Equal(t, "GOOGLE - Google LLC, US", parsed.ASN.Name)
	require.True(t, parsed.ASN.Announced)

	// Country
	require.NotNil(t, parsed.Country)
	require.Equal(t, "US", parsed.Country.Code)
	require.Equal(t, "United States", parsed.Country.Name)

	// City
	require.NotNil(t, parsed.City)
	require.Equal(t, "Mountain View, California", parsed.City.Name)
	require.True(t, parsed.City.Present)

	// Netblock
	require.NotNil(t, parsed.Netblock)
	require.Equal(t, "GOGL", parsed.Netblock.Handle)
	require.Equal(t, "Google LLC", parsed.Netblock.Organization)
	require.Equal(t, "offline", parsed.Netblock.Source)
	require.False(t, parsed.Netblock.LiveQuery)

	// Category
	require.NotNil(t, parsed.Category)
	require.Equal(t, []string{"cdn", "cloud:gcp"}, parsed.Category.Tags)
	require.Equal(t, "cdn, cloud:gcp", parsed.Category.Raw)

	// Reverse DNS
	require.NotNil(t, parsed.ReverseDNS)
	require.Equal(t, []string{"dns.google"}, parsed.ReverseDNS.Names)
	require.Equal(t, "dns.google", parsed.ReverseDNS.Raw)
}

func TestJSONLookupOutputUnannouncedASN(t *testing.T) {
	res := lookupResult{
		target:  "192.0.2.1",
		ip:      net.ParseIP("192.0.2.1"),
		asn:     "N/A",
		name:    "Unknown",
		country: "Unknown",
	}

	line, err := formatJSONLookupOutput(res)
	require.NoError(t, err)

	var parsed jsonLookupResult
	err = json.Unmarshal([]byte(line), &parsed)
	require.NoError(t, err)

	require.Nil(t, parsed.Host)
	require.Equal(t, "192.0.2.1", parsed.IP)
	require.NotNil(t, parsed.ASN)
	require.Equal(t, uint32(0), parsed.ASN.Number)
	require.Equal(t, "N/A", parsed.ASN.ASNString)
	require.False(t, parsed.ASN.Announced)
	require.Nil(t, parsed.Country)
	require.Nil(t, parsed.City)
}

func TestFormatJSONError(t *testing.T) {
	line, err := formatJSONError("bad-host.test", "no such host")
	require.NoError(t, err)

	var parsed jsonLookupResult
	err = json.Unmarshal([]byte(line), &parsed)
	require.NoError(t, err)

	require.Equal(t, "bad-host.test", parsed.Target)
	require.Equal(t, "no such host", parsed.Error)
}
