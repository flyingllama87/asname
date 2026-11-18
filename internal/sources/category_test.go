package sources

import (
	"context"
	"fmt"
	"github.com/flyingllama87/asname/pkg/database"
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

func TestCategoryLookupKeepsCoveringTags(t *testing.T) {
	db := buildTestCategoryDB(t, func(b *categoryBuilder) {
		b.addPrefix("45.32.0.0/16", "cloud:vultr")
		b.addPrefix("45.32.1.1", "vpn:mullvad")
		b.addPrefix("45.32.1.2", "tor-exit")
	})

	require.Equal(t, "cloud:vultr, vpn:mullvad", db.Lookup(net.ParseIP("45.32.1.1"), 0, false))
	require.Equal(t, "cloud:vultr, tor-exit", db.Lookup(net.ParseIP("45.32.1.2"), 0, false))
	require.Equal(t, "cloud:vultr", db.Lookup(net.ParseIP("45.32.1.3"), 0, false))
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

func TestCategoryInferredTagsRoundTrip(t *testing.T) {
	names := filepath.Join(t.TempDir(), NamesFilename)
	require.NoError(t, os.WriteFile(names, []byte(
		"AS21928       T-MOBILE-AS21928 - T-Mobile USA, Inc., US\n"+
			"AS11481       AS-UTRGV - University of Texas Rio Grande Valley, US\n"+
			"AS64500       EXAMPLE - Example Widgets Ltd, GB\n"), 0o644))

	var n int
	db := buildTestCategoryDB(t, func(b *categoryBuilder) {
		b.addASN(21928, "isp")
		b.addVPNServers("mullvad", VPNList{Source: "Mullvad relay API"}, []string{"192.0.2.1"})
		var err error
		n, err = b.importInferred(names)
		require.NoError(t, err)
	})
	require.Equal(t, 2, n)
	require.Equal(t, InferredTags{Tags: []string{"isp", "mobile"}, From: InferredFromList}, db.Inferred(21928))
	require.Equal(t, InferredTags{Tags: []string{"education"}, From: InferredFromName}, db.Inferred(11481))
	require.Empty(t, db.Inferred(64500).Tags)
	// The sources' own tags and VPN lists are unaffected.
	require.Equal(t, "isp", db.LookupASN(21928))
	require.Len(t, db.VPNLists("vpn:mullvad"), 1)
}

func TestCategoryInferredNeedsNames(t *testing.T) {
	b := newCategoryBuilder(context.Background())
	_, err := b.importInferred(filepath.Join(t.TempDir(), "missing.txt"))
	require.ErrorContains(t, err, "AS names list")
}

func TestCategoryNetnameRangeTags(t *testing.T) {
	dir := t.TempDir()
	nbPath := buildTestNetblockDB(t, func(b *netblockBuilder) {
		b.add(net.ParseIP("10.0.0.0"), net.ParseIP("10.0.3.255"), "ACME-NET", "Acme Telecom", NetblockMeta{})
		b.add(net.ParseIP("10.0.1.0"), net.ParseIP("10.0.1.255"), "ACME-ADSL-POOL", "Acme Telecom", NetblockMeta{})
		b.add(net.ParseIP("10.0.2.0"), net.ParseIP("10.0.2.255"), "LISMORECITYCOUNCIL", "LISMORE CITY COUNCIL", NetblockMeta{})
		b.add(net.ParseIP("10.1.0.0"), net.ParseIP("10.1.0.255"), "US_broadband_Internet", "Customer", NetblockMeta{})
		start, end, _ := ParseNetRange("2001:db8::/48")
		b.add(start, end, "ACME-LTE-POOL", "Acme Telecom", NetblockMeta{})
	})

	asns := database.NewBuilder()
	for cidr, asn := range map[string]uint32{"10.0.0.0/16": 64500, "10.1.0.0/16": 64501, "2001:db8::/32": 64500} {
		_, n, err := net.ParseCIDR(cidr)
		require.NoError(t, err)
		require.NoError(t, asns.InsertMapping(n, asn))
	}
	asnDB, err := asns.Build()
	require.NoError(t, err)
	asnBytes, err := asnDB.MarshalBinary()
	require.NoError(t, err)
	asnPath := filepath.Join(dir, DBFilename)
	require.NoError(t, os.WriteFile(asnPath, asnBytes, 0o644))

	db := buildTestCategoryDB(t, func(b *categoryBuilder) {
		b.addASN(64500, "isp")
		b.addASN(64501, "hosting") // only hosts servers: its "broadband" is a customer's name
		st, err := b.importNetnames(nbPath, asnPath)
		require.NoError(t, err)
		require.Equal(t, 1, st.ranges["range:broadband"])
		require.Equal(t, 1, st.skipped["range:broadband"])
		require.Equal(t, 1, st.ranges["range:mobile"])
	})

	require.Equal(t, []RangeTag{{"range:broadband", InferredFromNetname}}, db.InferredRange(net.ParseIP("10.0.1.7")))
	require.Nil(t, db.InferredRange(net.ParseIP("10.0.0.7")), "the ISP's own range: its owner's isp adds nothing")
	require.Nil(t, db.InferredRange(net.ParseIP("10.0.3.0")), "the parent resumes after the council's block")
	require.Equal(t, []RangeTag{{"government", InferredFromOwner}}, db.InferredRange(net.ParseIP("10.0.2.9")),
		"a council's block inside an ISP is the council's")
	require.Nil(t, db.InferredRange(net.ParseIP("10.1.0.1")), "netnames are not trusted inside a hosting network")
	require.Equal(t, []RangeTag{{"range:mobile", InferredFromNetname}}, db.InferredRange(net.ParseIP("2001:db8::1")))
}

func TestNetblockEachRangeMatchesLookup(t *testing.T) {
	path := buildTestNetblockDB(t, func(b *netblockBuilder) {
		b.add(net.ParseIP("183.177.52.0"), net.ParseIP("183.177.55.255"), "EQUINIX-AU", "Equinix", NetblockMeta{})
		b.add(net.ParseIP("183.177.54.128"), net.ParseIP("183.177.54.135"), "SISS-SY4", "SISS", NetblockMeta{})
		b.add(net.ParseIP("255.255.255.0"), net.ParseIP("255.255.255.255"), "LAST-V4", "", NetblockMeta{})
	})
	nb, err := OpenNetblockDB(path)
	require.NoError(t, err)
	defer nb.Close()

	var got []string
	require.NoError(t, nb.EachRange(func(r NetblockRange) error {
		name, err := nb.str(r.NetnameOff)
		require.NoError(t, err)
		got = append(got, fmt.Sprintf("%s-%s %s", r.Start, r.End, name))
		return nil
	}))
	require.Equal(t, []string{
		"183.177.52.0-183.177.54.127 EQUINIX-AU",
		"183.177.54.128-183.177.54.135 SISS-SY4",
		"183.177.54.136-183.177.55.255 EQUINIX-AU",
		"255.255.255.0-255.255.255.255 LAST-V4",
	}, got)
}

func TestCategorySelfReportedRoundTrip(t *testing.T) {
	srv := serveFixture(t, `{"data":[
		{"asn":55933,"info_type":"Cable/DSL/ISP"},
		{"asn":1221,"info_type":"Cable/DSL/ISP"},
		{"asn":11481,"info_type":"Educational/Research"}
	]}`)
	db := buildTestCategoryDB(t, func(b *categoryBuilder) {
		b.addASN(55933, "hosting") // bgp.tools: a host calling itself an ISP
		b.addASN(1221, "isp")      // bgp.tools agrees with PeeringDB
		_, err := b.ImportPeeringDBFrom(srv.URL)
		require.NoError(t, err)
	})
	require.Equal(t, "hosting, isp", db.LookupASN(55933))
	require.Equal(t, []string{"isp"}, db.SelfReported(55933), "only PeeringDB says ISP")
	require.Empty(t, db.SelfReported(1221), "another source confirms it")
	require.Equal(t, []string{"education"}, db.SelfReported(11481))
	require.Empty(t, db.SelfReported(64500))
}
