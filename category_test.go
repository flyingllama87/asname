package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// buildTestCategoryDB serialises a builder and opens it back.
func buildTestCategoryDB(t *testing.T, add func(*categoryBuilder)) *categoryDB {
	t.Helper()

	b := newCategoryBuilder()
	add(b)
	data, err := b.marshal()
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), categoryFilename)
	require.NoError(t, os.WriteFile(path, data, 0o644))
	db, err := openCategoryDB(path)
	require.NoError(t, err)
	return db
}

func TestCategoryLookupPrefixAndASN(t *testing.T) {
	db := buildTestCategoryDB(t, func(b *categoryBuilder) {
		b.addPrefix("13.32.0.0/15", "cloud:aws", "cdn")
		b.addASN(1221, "isp", "mobile")
	})

	// A prefix names the address directly.
	require.Equal(t, "cdn, cloud:aws", db.Lookup(net.ParseIP("13.32.0.1"), 16509, true))
	// With no prefix, the AS says what the operator does.
	require.Equal(t, "isp, mobile", db.Lookup(net.ParseIP("139.130.4.5"), 1221, true))
	// Neither: nothing known.
	require.Equal(t, "", db.Lookup(net.ParseIP("192.0.2.1"), 64496, true))
	require.Equal(t, "", db.Lookup(net.ParseIP("192.0.2.1"), 0, false))
}

// The AS-level tags describe the operator, so a hyperscaler carries a little of
// everything. Where the provider has named the prefix itself, that settles it
// and the AS tags must not leak in — otherwise every EC2 address is a "vpn".
func TestCategoryLookupPrefixWinsOverASN(t *testing.T) {
	db := buildTestCategoryDB(t, func(b *categoryBuilder) {
		b.addPrefix("52.95.110.0/24", "cloud:aws")
		b.addASN(16509, "vpn", "hosting", "enterprise")
	})

	require.Equal(t, "cloud:aws", db.Lookup(net.ParseIP("52.95.110.1"), 16509, true))
	// An address of the same AS outside any published prefix still gets them.
	require.Equal(t, "enterprise, hosting, vpn", db.Lookup(net.ParseIP("18.0.0.1"), 16509, true))
}

func TestCategoryLookupMostSpecificPrefixWins(t *testing.T) {
	db := buildTestCategoryDB(t, func(b *categoryBuilder) {
		b.addPrefix("13.32.0.0/15", "cloud:aws")
		b.addPrefix("13.32.1.0/24", "cloud:aws", "cdn")
	})

	require.Equal(t, "cdn, cloud:aws", db.Lookup(net.ParseIP("13.32.1.5"), 0, false))
	require.Equal(t, "cloud:aws", db.Lookup(net.ParseIP("13.32.2.5"), 0, false))
}

func TestCategoryLookupIPv6(t *testing.T) {
	db := buildTestCategoryDB(t, func(b *categoryBuilder) {
		b.addPrefix("2606:4700::/32", "cdn", "cloud:cloudflare")
	})

	require.Equal(t, "cdn, cloud:cloudflare", db.Lookup(net.ParseIP("2606:4700::1111"), 0, false))
	require.Equal(t, "", db.Lookup(net.ParseIP("2606:4701::1"), 0, false))
}

// Sources overlap: AWS lists the same prefix under several services, and an ASN
// can be tagged by bgp.tools and PeeringDB at once.
func TestCategoryBuilderMergesRepeatedEntries(t *testing.T) {
	db := buildTestCategoryDB(t, func(b *categoryBuilder) {
		b.addPrefix("13.32.0.0/15", "cloud:aws")
		b.addPrefix("13.32.0.0/15", "cdn")
		b.addASN(15169, "content")
		b.addASN(15169, "vpn")
	})

	require.Equal(t, "cdn, cloud:aws", db.Lookup(net.ParseIP("13.32.0.1"), 0, false))
	require.Equal(t, "content, vpn", db.Lookup(net.ParseIP("192.0.2.1"), 15169, true))
}

// The Tor exit list is bare addresses rather than prefixes.
func TestCategoryBuilderAcceptsBareAddresses(t *testing.T) {
	db := buildTestCategoryDB(t, func(b *categoryBuilder) {
		b.addPrefix("171.25.193.25", "tor-exit")
		b.addPrefix("2001:db8::1", "tor-exit")
	})

	require.Equal(t, "tor-exit", db.Lookup(net.ParseIP("171.25.193.25"), 0, false))
	require.Equal(t, "", db.Lookup(net.ParseIP("171.25.193.26"), 0, false))
	require.Equal(t, "tor-exit", db.Lookup(net.ParseIP("2001:db8::1"), 0, false))
}

func TestCategoryBuilderRejectsJunk(t *testing.T) {
	b := newCategoryBuilder()
	b.addPrefix("not a prefix", "cloud:aws")
	b.addPrefix("999.1.1.1/24", "cloud:aws")
	b.addPrefix("", "cloud:aws")
	b.addPrefix("8.8.8.0/24") // no tags
	b.addASN(0, "isp")        // AS0 is not a real AS
	b.addASN(1234)            // no tags
	require.Empty(t, b.prefixes)
	require.Empty(t, b.asns)
}

func TestOpenCategoryDBRejectsForeignFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), categoryFilename)
	require.NoError(t, os.WriteFile(path, make([]byte, 64), 0o644))

	_, err := openCategoryDB(path)
	require.ErrorContains(t, err, "not an asname category database")
}

// bgp.tools' tags say the AS is associated with a thing, not that it is one.
// These three are excluded because that reading makes them actively wrong here,
// and it would be easy to add them back without noticing why they went.
func TestNoisyBGPToolsTagsStayOut(t *testing.T) {
	for _, name := range []string{"tor", "anycast", "biznet"} {
		require.NotContains(t, bgpToolsTagNames, name,
			"%q describes what an AS contains, not what it is", name)
	}
	// The exact, address-level Tor data is kept; it is a different source.
	require.Contains(t, bgpToolsTagNames, "vpn")
	require.Contains(t, bgpToolsTagNames, "dsl")
}

func TestJoinTags(t *testing.T) {
	require.Equal(t, "cdn,cloud:aws", joinTags(map[string]bool{"cloud:aws": true, "cdn": true}))
	require.Equal(t, "", joinTags(map[string]bool{}))
	require.Equal(t, "", joinTags(map[string]bool{"": true}))
}

func TestParseASN(t *testing.T) {
	for _, in := range []string{"AS15169", "as15169", "15169", " AS15169 "} {
		asn, ok := parseASN(in)
		require.True(t, ok, in)
		require.Equal(t, uint32(15169), asn)
	}
	for _, in := range []string{"", "AS", "Cloudflare", "AS-1", "AS99999999999"} {
		_, ok := parseASN(in)
		require.False(t, ok, in)
	}
}

// serveFixture stands in for a provider so the importers can be exercised
// without reaching the network.
func serveFixture(t *testing.T, body string) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-User-Agent", r.UserAgent())
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestImportCIDRList(t *testing.T) {
	srv := serveFixture(t, `# a geofeed, per RFC 8805
5.101.96.0/21,NL,NL-NH,Amsterdam,1098 XH

192.0.2.0/24,US,US-CA,San Jose,
not-a-prefix
`)
	b := newCategoryBuilder()
	n, err := b.importCIDRList(srv.URL, "", "cloud:digitalocean")
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.Contains(t, b.prefixes, "5.101.96.0/21")
	require.Contains(t, b.prefixes, "192.0.2.0/24")
}

// The service name is what separates a CDN from somebody's virtual machine.
func TestImportAWSSeparatesCloudFront(t *testing.T) {
	srv := serveFixture(t, `{"prefixes":[
		{"ip_prefix":"13.32.0.0/15","service":"CLOUDFRONT"},
		{"ip_prefix":"52.95.110.0/24","service":"EC2"},
		{"ip_prefix":"52.95.110.0/24","service":"AMAZON"},
		{"ip_prefix":"3.2.34.0/26","service":"GLOBALACCELERATOR"}
	],"ipv6_prefixes":[{"ipv6_prefix":"2600:9000::/28","service":"CLOUDFRONT"}]}`)

	b := newCategoryBuilder()
	n, err := b.importAWSFrom(srv.URL)
	require.NoError(t, err)
	require.Equal(t, 5, n)

	require.Equal(t, map[string]bool{"cloud:aws": true, "cdn": true}, b.prefixes["13.32.0.0/15"])
	require.Equal(t, map[string]bool{"cloud:aws": true}, b.prefixes["52.95.110.0/24"])
	require.Equal(t, map[string]bool{"cloud:aws": true, "anycast": true}, b.prefixes["3.2.34.0/26"])
	require.Equal(t, map[string]bool{"cloud:aws": true, "cdn": true}, b.prefixes["2600:9000::/28"])
}

func TestImportBGPToolsTagSendsTheContactAddress(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.UserAgent()
		w.Write([]byte("AS44684,Mythic Beasts Ltd\nAS13335,\"Cloudflare, Inc.\"\njunk\n"))
	}))
	defer srv.Close()

	b := newCategoryBuilder()
	n, err := b.importBGPToolsTagFrom(srv.URL, []string{"vpn"}, bgpToolsUserAgent("me@example.com"))
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.Contains(t, seen, "me@example.com", "bgp.tools asks to know who is calling")
	require.Equal(t, map[string]bool{"vpn": true}, b.asns[44684])
	// A quoted name containing a comma must not break the ASN out of the line.
	require.Equal(t, map[string]bool{"vpn": true}, b.asns[13335])
}

func TestImportPeeringDBMapsReportedTypes(t *testing.T) {
	srv := serveFixture(t, `{"data":[
		{"asn":1221,"info_type":"Cable/DSL/ISP"},
		{"asn":15169,"info_type":"Content"},
		{"asn":6939,"info_type":"NSP"},
		{"asn":64496,"info_type":"Not A Type"},
		{"asn":64497,"info_type":""}
	]}`)

	b := newCategoryBuilder()
	n, err := b.importPeeringDBFrom(srv.URL)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, map[string]bool{"isp": true}, b.asns[1221])
	require.Equal(t, map[string]bool{"content": true}, b.asns[15169])
	require.Equal(t, map[string]bool{"transit": true}, b.asns[6939])
	require.NotContains(t, b.asns, uint32(64496))
}
