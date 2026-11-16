package engine

import (
	"net"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/flyingllama87/asname/internal/sources"
)

func a16(s string) [16]byte { return netip.MustParseAddr(s).As16() }

func span(start, end string, flags uint8, ipsum uint8, sbl string) repSpan {
	return repSpan{start: a16(start), end: a16(end), flags: flags, ipsum: ipsum, listed: ipsum > 0, sbl: sbl}
}

func TestScanSpansDropCoverage(t *testing.T) {
	lo, hi := a16("10.0.0.0"), a16("10.0.0.255")

	// One DROP block covering the prefix, split by an IPsum address in it.
	spans := []repSpan{
		span("10.0.0.0", "10.0.0.6", exDropInside, 0, "SBL1"),
		span("10.0.0.7", "10.0.0.7", exDropInside, 4, "SBL1"),
		span("10.0.0.8", "10.0.0.255", exDropInside, 0, "SBL1"),
	}
	flags, ipsum, listed, sbls := scanSpans(spans, lo, hi, true)
	require.NotZero(t, flags&exDrop, "all of it is DROP")
	require.EqualValues(t, 4, ipsum)
	require.EqualValues(t, 1, listed)
	require.Equal(t, []string{"SBL1"}, sbls)

	// A DROP block inside a larger prefix: contains DROP, not DROP.
	spans = []repSpan{span("10.0.0.128", "10.0.0.255", exDropInside, 0, "SBL2")}
	flags, _, listed, _ = scanSpans(spans, lo, hi, true)
	require.Zero(t, flags&exDrop)
	require.NotZero(t, flags&exDropInside)
	require.Zero(t, listed)

	// A gap between two DROP blocks.
	spans = []repSpan{
		span("10.0.0.0", "10.0.0.99", exDropInside, 0, "SBL3"),
		span("10.0.0.101", "10.0.0.255", exDropInside, 0, "SBL4"),
	}
	flags, _, _, sbls = scanSpans(spans, lo, hi, true)
	require.Zero(t, flags&exDrop)
	require.Equal(t, []string{"SBL3", "SBL4"}, sbls)

	// A DROP block larger than the prefix covers it; spans outside it are
	// not counted.
	spans = []repSpan{
		span("9.255.255.255", "9.255.255.255", 0, 2, ""),
		span("10.0.0.0", "10.0.255.255", exDropInside, 0, "SBL5"),
	}
	flags, ipsum, listed, _ = scanSpans(spans, lo, hi, true)
	require.NotZero(t, flags&exDrop)
	require.Zero(t, ipsum)
	require.Zero(t, listed)
}

func TestLastAddr(t *testing.T) {
	require.Equal(t, "10.0.0.255", lastAddr(netip.MustParsePrefix("10.0.0.0/24")).String())
	require.Equal(t, "255.255.255.255", lastAddr(netip.MustParsePrefix("0.0.0.0/0")).String())
	require.Equal(t, "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", lastAddr(netip.MustParsePrefix("2001:db8::/32")).String())
}

func testExploreEngine(t *testing.T) *Engine {
	t.Helper()
	b := sources.NewPrefixDBBuilder()
	for cidr, asn := range map[string]uint32{
		"8.0.0.0/8":      3356,
		"8.8.8.0/24":     15169,
		"1.1.1.0/24":     13335,
		"2001:4860::/32": 15169,
	} {
		_, n, err := net.ParseCIDR(cidr)
		require.NoError(t, err)
		b.Add(asn, n)
	}
	path := filepath.Join(t.TempDir(), "prefixes.db")
	_, err := b.Write(path)
	require.NoError(t, err)
	pdb, err := sources.OpenPrefixDB(path)
	require.NoError(t, err)
	t.Cleanup(func() { pdb.Close() })

	eng := NewTestEngine(t)
	eng.prefixDB = pdb
	eng.names[3356] = "LEVEL3 - Level 3 Parent, LLC, US"
	eng.names[13335] = "CLOUDFLARENET - Cloudflare, Inc., US"
	return eng
}

func TestExploreFilters(t *testing.T) {
	eng := testExploreEngine(t)
	prefixes := func(o ExploreOptions) []string {
		t.Helper()
		res, err := eng.Explore(o)
		require.NoError(t, err)
		var out []string
		for _, p := range res.Prefixes {
			out = append(out, p.Prefix)
		}
		return out
	}

	require.Equal(t, []string{"1.1.1.0/24", "8.0.0.0/8", "8.8.8.0/24", "2001:4860::/32"}, prefixes(ExploreOptions{}))
	require.Equal(t, []string{"8.0.0.0/8"}, prefixes(ExploreOptions{MinLen: 8, MaxLen: 8}))
	require.Equal(t, []string{"2001:4860::/32"}, prefixes(ExploreOptions{V6Only: true}))
	require.Equal(t, []string{"8.8.8.0/24", "2001:4860::/32"}, prefixes(ExploreOptions{ASN: 15169}))
	// The test country database places only 8.8.8.0/24, in the US.
	require.Equal(t, []string{"8.8.8.0/24"}, prefixes(ExploreOptions{Country: "us"}))
	require.Equal(t, []string{"8.0.0.0/8", "1.1.1.0/24", "8.8.8.0/24", "2001:4860::/32"}, prefixes(ExploreOptions{Sort: "size", V4Only: false}))
	require.Equal(t, []string{"8.8.8.0/24"}, prefixes(ExploreOptions{Country: "US", Limit: 1}))
	require.Equal(t, []string{"8.0.0.0/8"}, prefixes(ExploreOptions{Limit: 1, Offset: 1}))

	res, err := eng.Explore(ExploreOptions{V4Only: true})
	require.NoError(t, err)
	require.Equal(t, 3, res.Total)
	require.EqualValues(t, 1<<24+512, res.Addresses)

	_, err = eng.Explore(ExploreOptions{Reputation: "bogus"})
	require.Error(t, err)
}

func TestSearchByASNumber(t *testing.T) {
	eng := testExploreEngine(t)
	asns := eng.SearchASNsWith("AS13335", ASNSearchOptions{})
	require.Len(t, asns, 1)
	require.Equal(t, "AS13335", asns[0].ASN)
	require.Empty(t, eng.SearchASNsWith("AS13335", ASNSearchOptions{Country: "AU"}))
}

func TestC2Families(t *testing.T) {
	spans := []repSpan{
		{start: a16("10.0.0.5"), end: a16("10.0.0.5"), flags: exC2, listed: true, c2: []string{"Sliver"}},
		{start: a16("10.0.0.9"), end: a16("10.0.0.9"), flags: exC2, listed: true, c2: []string{"Cobalt Strike", "Sliver"}},
		{start: a16("10.0.1.9"), end: a16("10.0.1.9"), flags: exC2, listed: true, c2: []string{"QakBot"}},
	}
	require.Equal(t, []string{"Cobalt Strike", "Sliver"}, c2Families(spans, a16("10.0.0.0"), a16("10.0.0.255")))
	flags, _, listed, _ := scanSpans(spans, a16("10.0.0.0"), a16("10.0.0.255"), true)
	require.NotZero(t, flags&exC2)
	require.Equal(t, uint32(2), listed)
	require.True(t, ValidExploreReputation("c2"))
}
