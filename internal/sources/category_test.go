package sources

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func buildTestCategoryDB(t *testing.T, add func(*categoryBuilder)) *CategoryDB {
	t.Helper()

	b := newCategoryBuilder(context.Background())
	add(b)
	data, err := b.Marshal()
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), CategoryFilename)
	require.NoError(t, os.WriteFile(path, data, 0o644))
	db, err := OpenCategoryDB(path)
	require.NoError(t, err)
	return db
}

func TestCategoryLookupPrefixAndASN(t *testing.T) {
	db := buildTestCategoryDB(t, func(b *categoryBuilder) {
		b.addPrefix("13.32.0.0/15", "cloud:aws", "cdn")
		b.addASN(1221, "isp", "mobile")
	})

	require.Equal(t, "cdn, cloud:aws", db.Lookup(net.ParseIP("13.32.0.1"), 16509, true))
	require.Equal(t, "isp, mobile", db.Lookup(net.ParseIP("139.130.4.5"), 1221, true))
	require.Equal(t, "", db.Lookup(net.ParseIP("192.0.2.1"), 64496, true))
	require.Equal(t, "", db.Lookup(net.ParseIP("192.0.2.1"), 0, false))
}

func TestCategoryLookupPrefixWinsOverASN(t *testing.T) {
	db := buildTestCategoryDB(t, func(b *categoryBuilder) {
		b.addPrefix("52.95.110.0/24", "cloud:aws")
		b.addASN(16509, "vpn", "hosting", "enterprise")
	})

	require.Equal(t, "cloud:aws", db.Lookup(net.ParseIP("52.95.110.1"), 16509, true))
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
	b := newCategoryBuilder(context.Background())
	b.addPrefix("not a prefix", "cloud:aws")
	b.addPrefix("999.1.1.1/24", "cloud:aws")
	b.addPrefix("", "cloud:aws")
	b.addPrefix("8.8.8.0/24")
	b.addASN(0, "isp")
	b.addASN(1234)
	require.Empty(t, b.prefixes)
	require.Empty(t, b.asns)
}

func TestOpenCategoryDBRejectsForeignFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), CategoryFilename)
	require.NoError(t, os.WriteFile(path, make([]byte, 64), 0o644))

	_, err := OpenCategoryDB(path)
	require.ErrorContains(t, err, "not an asname category database")
}

func TestNoisyBGPToolsTagsStayOut(t *testing.T) {
	for _, name := range []string{"tor", "anycast", "biznet"} {
		require.NotContains(t, bgpToolsTagNames, name,
			"%q describes what an AS contains, not what it is", name)
	}
	require.Contains(t, bgpToolsTagNames, "vpn")
	require.Contains(t, bgpToolsTagNames, "dsl")
}

func TestJoinTags(t *testing.T) {
	require.Equal(t, "cdn,cloud:aws", JoinTags(map[string]bool{"cloud:aws": true, "cdn": true}))
	require.Equal(t, "", JoinTags(map[string]bool{}))
	require.Equal(t, "", JoinTags(map[string]bool{"": true}))
}

func TestParseASN(t *testing.T) {
	for _, in := range []string{"AS15169", "as15169", "15169", " AS15169 "} {
		asn, ok := ParseASN(in)
		require.True(t, ok, in)
		require.Equal(t, uint32(15169), asn)
	}
	for _, in := range []string{"", "AS", "Cloudflare", "AS-1", "AS99999999999"} {
		_, ok := ParseASN(in)
		require.False(t, ok, in)
	}
}

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
	b := newCategoryBuilder(context.Background())
	n, err := b.ImportCIDRList(srv.URL, "", "cloud:digitalocean")
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.Contains(t, b.prefixes, "5.101.96.0/21")
	require.Contains(t, b.prefixes, "192.0.2.0/24")
}

func TestImportAWSSeparatesCloudFront(t *testing.T) {
	srv := serveFixture(t, `{"prefixes":[
		{"ip_prefix":"13.32.0.0/15","service":"CLOUDFRONT"},
		{"ip_prefix":"52.95.110.0/24","service":"EC2"},
		{"ip_prefix":"52.95.110.0/24","service":"AMAZON"},
		{"ip_prefix":"3.2.34.0/26","service":"GLOBALACCELERATOR"}
	],"ipv6_prefixes":[{"ipv6_prefix":"2600:9000::/28","service":"CLOUDFRONT"}]}`)

	b := newCategoryBuilder(context.Background())
	n, err := b.ImportAWSFrom(srv.URL)
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

	b := newCategoryBuilder(context.Background())
	n, err := b.ImportBGPToolsTagFrom(srv.URL, []string{"vpn"}, BGPToolsUserAgent("me@example.com"))
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.Contains(t, seen, "me@example.com", "bgp.tools asks to know who is calling")
	require.Equal(t, map[string]bool{"vpn": true}, b.asns[44684])
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

	b := newCategoryBuilder(context.Background())
	n, err := b.ImportPeeringDBFrom(srv.URL)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, map[string]bool{"isp": true}, b.asns[1221])
	require.Equal(t, map[string]bool{"content": true}, b.asns[15169])
	require.Equal(t, map[string]bool{"transit": true}, b.asns[6939])
	require.NotContains(t, b.asns, uint32(64496))
}
