package main

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/flyingllama87/asname/pkg/database"
)

func testDatabase(t *testing.T, prefix string, value uint32) database.Database {
	t.Helper()

	_, ipNet, err := net.ParseCIDR(prefix)
	require.NoError(t, err)

	b := database.NewBuilder()
	require.NoError(t, b.InsertMapping(ipNet, value))
	db, err := b.Build()
	require.NoError(t, err)
	return db
}

func testEngine(t *testing.T) *engine {
	t.Helper()

	return &engine{
		db:        testDatabase(t, "8.8.8.0/24", 15169),
		names:     map[uint32]string{15169: "GOOGLE - Google LLC, US"},
		countryDB: testDatabase(t, "8.8.8.0/24", encodeCC("US")),
	}
}

// The tries are built from the 16-byte form of an address, but the DNS resolver
// returns 4-byte slices for IPv4. Both forms must resolve identically.
func TestEngineLookupNormalizesFourByteIPv4(t *testing.T) {
	eng := testEngine(t)

	four, err := eng.lookup(net.IP{8, 8, 8, 8})
	require.NoError(t, err)
	require.Equal(t, "AS15169", four.asn)
	require.Equal(t, "GOOGLE - Google LLC, US", four.name)
	require.Equal(t, "US, United States", four.country)
	require.Equal(t, "8.8.8.8", four.ip.String())

	sixteen, err := eng.lookup(net.ParseIP("8.8.8.8"))
	require.NoError(t, err)
	require.Equal(t, four.asn, sixteen.asn)
	require.Equal(t, four.name, sixteen.name)
	require.Equal(t, four.country, sixteen.country)
}

func TestEngineLookupNotFound(t *testing.T) {
	res, err := testEngine(t).lookup(net.ParseIP("1.1.1.1"))

	require.NoError(t, err)
	require.Equal(t, "N/A", res.asn)
	require.Equal(t, "Unknown", res.name)
	require.Equal(t, "Unknown", res.country)
}

// A missing country database degrades one field rather than failing the lookup.
func TestEngineLookupWithoutCountryDB(t *testing.T) {
	eng := testEngine(t)
	eng.countryDB = nil

	res, err := eng.lookup(net.ParseIP("8.8.8.8"))
	require.NoError(t, err)
	require.Equal(t, "AS15169", res.asn)
	require.Equal(t, "Unknown", res.country)
}

// One hostname produces one line per address, each tagged with the hostname.
func TestEngineLookupTargetExpandsAddresses(t *testing.T) {
	results, err := testEngine(t).lookupTarget(target{
		raw:  "dns.google",
		host: "dns.google",
		ips:  []net.IP{{8, 8, 8, 8}, net.ParseIP("1.1.1.1")},
	})

	require.NoError(t, err)
	require.Len(t, results, 2)
	require.Equal(t, "dns.google", results[0].host)
	require.Equal(t, "AS15169", results[0].asn)
	require.Equal(t, "dns.google", results[1].host)
	require.Equal(t, "N/A", results[1].asn)
}

func TestEngineLookupTargetPropagatesResolveError(t *testing.T) {
	_, err := testEngine(t).lookupTarget(newTarget("///"))

	require.Error(t, err)
}
