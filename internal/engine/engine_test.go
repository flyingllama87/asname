package engine

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/flyingllama87/asname/internal/sources"
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

func TestEngineSearchASNs(t *testing.T) {
	eng := NewTestEngine(t)
	eng.names = map[uint32]string{
		15169:  "GOOGLE - Google LLC, US",
		396982: "GOOGLE-CLOUD-PLATFORM - Google LLC, US",
		13335:  "CLOUDFLARENET - Cloudflare, Inc., US",
		64500:  "NO-COUNTRY",
	}

	got := eng.SearchASNs("google llc", 0, false, false)
	require.Len(t, got, 2)
	require.Equal(t, ASNSearchResult{Number: 15169, ASN: "AS15169", Name: "GOOGLE - Google LLC, US", Country: "US, United States"}, got[0])
	require.Equal(t, uint32(396982), got[1].Number)

	require.Len(t, eng.SearchASNs("Google", 1, false, false), 1)
	require.Empty(t, eng.SearchASNs("us", 0, false, false), "the country code is not searched")
	require.Empty(t, eng.SearchASNs("  ", 0, false, false))

	nc := eng.SearchASNs("no-country", 0, false, false)
	require.Len(t, nc, 1)
	require.Equal(t, "Unknown", nc[0].Country)
}

func TestEngineSearchASNsFiltersPrefixFamily(t *testing.T) {
	b := sources.NewPrefixDBBuilder()
	for _, cidr := range []string{"8.8.8.0/24", "2001:4860::/32"} {
		_, n, err := net.ParseCIDR(cidr)
		require.NoError(t, err)
		b.Add(15169, n)
	}
	path := filepath.Join(t.TempDir(), "prefixes.db")
	_, err := b.Write(path)
	require.NoError(t, err)
	pdb, err := sources.OpenPrefixDB(path)
	require.NoError(t, err)
	defer pdb.Close()

	eng := NewTestEngine(t)
	eng.prefixDB = pdb

	all := eng.SearchASNs("google", 0, false, false)
	require.Equal(t, []string{"8.8.8.0/24", "2001:4860::/32"}, all[0].Prefixes)

	v4 := eng.SearchASNs("google", 0, true, false)
	require.Equal(t, []string{"8.8.8.0/24"}, v4[0].Prefixes)
	require.Empty(t, v4[0].IPv6Prefixes)

	v6 := eng.SearchASNs("google", 0, false, true)
	require.Equal(t, []string{"2001:4860::/32"}, v6[0].Prefixes)
	require.Empty(t, v6[0].IPv4Prefixes)
}
