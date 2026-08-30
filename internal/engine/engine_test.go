package engine

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEngineLookupNormalizesFourByteIPv4(t *testing.T) {
	eng := NewTestEngine(t)

	four, err := eng.Lookup(net.IP{8, 8, 8, 8})
	require.NoError(t, err)
	require.Equal(t, "AS15169", four.ASN)
	require.Equal(t, "GOOGLE - Google LLC, US", four.Name)
	require.Equal(t, "US, United States", four.Country)
	require.Equal(t, "8.8.8.8", four.IP.String())

	sixteen, err := eng.Lookup(net.ParseIP("8.8.8.8"))
	require.NoError(t, err)
	require.Equal(t, four.ASN, sixteen.ASN)
	require.Equal(t, four.Name, sixteen.Name)
	require.Equal(t, four.Country, sixteen.Country)
}

func TestEngineLookupNotFound(t *testing.T) {
	res, err := NewTestEngine(t).Lookup(net.ParseIP("1.1.1.1"))

	require.NoError(t, err)
	require.Equal(t, "N/A", res.ASN)
	require.Equal(t, "Unknown", res.Name)
	require.Equal(t, "Unknown", res.Country)
}

func TestEngineLookupWithoutCountryDB(t *testing.T) {
	eng := NewTestEngine(t)
	eng.countryDB = nil

	res, err := eng.Lookup(net.ParseIP("8.8.8.8"))
	require.NoError(t, err)
	require.Equal(t, "AS15169", res.ASN)
	require.Equal(t, "Unknown", res.Country)
}

func TestEngineLookupTargetExpandsAddresses(t *testing.T) {
	results, err := NewTestEngine(t).LookupTarget(Target{
		Raw:  "dns.google",
		Host: "dns.google",
		IPs:  []net.IP{{8, 8, 8, 8}, net.ParseIP("1.1.1.1")},
	})

	require.NoError(t, err)
	require.Len(t, results, 2)
	require.Equal(t, "dns.google", results[0].Host)
	require.Equal(t, "AS15169", results[0].ASN)
	require.Equal(t, "dns.google", results[1].Host)
	require.Equal(t, "N/A", results[1].ASN)
}

func TestEngineLookupTargetPropagatesResolveError(t *testing.T) {
	_, err := NewTestEngine(t).LookupTarget(NewTarget("///"))

	require.Error(t, err)
}
