package sources

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOrganisationFromASNameDropsTheHandleAndCountry(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"dash separator", "LVLT-1 - Level 3 Parent, LLC, US", "Level 3 Parent, LLC"},
		{"space separator", "DFVLR-SYS Deutsches Zentrum fuer Luft- und Raumfahrt e.V., DE", "Deutsches Zentrum fuer Luft- und Raumfahrt e.V."},
		{"handle only", "GOOGLE, US", "GOOGLE"},
		{"no country code", "GOGL - Google LLC", "Google LLC"},
		{"empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, organisationFromASName(tc.in))
		})
	}
}

func TestOrganisationNamePrefersTheMostCommonName(t *testing.T) {
	names := map[uint32]string{
		7018: "ATT-INTERNET4 - AT&T Services, Inc., US",
		2686: "ATGS-MMD - AT&T Global Network Services, LLC, US",
		2687: "ATGS-MMD - AT&T Global Network Services, LLC, US",
	}
	require.Equal(t, "AT&T Global Network Services, LLC", organisationName([]uint32{7018, 2687, 2686}, names))

	// With no majority the lowest-numbered ASN wins.
	require.Equal(t, "AT&T Global Network Services, LLC", organisationName([]uint32{7018, 2686}, names))

	require.Empty(t, organisationName([]uint32{64500}, names))
}

func TestDelegatedRangeCoversCountsAndPrefixes(t *testing.T) {
	// An IPv4 record's value is a host count, not a prefix length, and need
	// not be a power of two.
	start, end, ok := delegatedRange("ipv4", "1.178.0.0", "1536")
	require.True(t, ok)
	require.Equal(t, "1.178.0.0", start.String())
	require.Equal(t, "1.178.5.255", end.String())

	start, end, ok = delegatedRange("ipv6", "2001:400::", "32")
	require.True(t, ok)
	require.Equal(t, "2001:400::", start.String())
	require.Equal(t, "2001:400:ffff:ffff:ffff:ffff:ffff:ffff", end.String())

	_, _, ok = delegatedRange("ipv4", "255.255.255.255", "512")
	require.False(t, ok)

	_, _, ok = delegatedRange("asn", "1", "1")
	require.False(t, ok)
}

// seedCache writes body where fetchCached expects url's local copy, so an
// import runs against a fixture without contacting the server.
func seedCache(t *testing.T, url, body string) string {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, cacheName(url)), []byte(body), 0o644))
	return dir
}

func TestImportARINDelegatedJoinsNetblocksToASNamesByOpaqueID(t *testing.T) {
	cache := seedCache(t, arinDelegatedURL, `2.3|arin|1789045221395|4|19700101|20260910|-0400
arin|*|ipv4|*|3|summary
arin|US|asn|1|1|20010920|assigned|LVLT
arin|US|asn|15169|1|20000322|assigned|GOGL
arin|US|ipv4|8.0.0.0|16777216|19921201|allocated|LVLT
arin|US|ipv4|8.8.4.0|256|20231228|allocated|GOGL
arin|US|ipv6|2001:4860::|32|20050323|allocated|GOGL
arin|US|ipv4|198.51.100.0|256|20200101|allocated|NOASN
arin|US|ipv4|203.0.113.0|256|20200101|reserved|LVLT
`)
	names := map[uint32]string{
		1:     "LVLT-1 - Level 3 Parent, LLC, US",
		15169: "GOOGLE - Google LLC, US",
	}

	b := newNetblockBuilder()
	n, err := importARINDelegated(b, cache, names)
	require.NoError(t, err)
	// The reserved range and the range whose organisation holds no ASN are
	// both skipped.
	require.Equal(t, 3, n)

	path := filepath.Join(t.TempDir(), NetblockFilename)
	_, err = b.write(path)
	require.NoError(t, err)

	db, err := OpenNetblockDB(path)
	require.NoError(t, err)
	defer db.Close()

	// The more specific Google allocation wins inside the Level 3 /9.
	require.Equal(t, "Google LLC", lookupNetblock(t, db, "8.8.4.4"))
	require.Equal(t, "Level 3 Parent, LLC", lookupNetblock(t, db, "8.8.8.8"))
	require.Equal(t, "Google LLC", lookupNetblock(t, db, "2001:4860:4860::8888"))

	info, err := db.Lookup(net.ParseIP("198.51.100.1"))
	require.NoError(t, err)
	require.True(t, info.Empty())
}
