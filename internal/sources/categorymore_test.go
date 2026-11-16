package sources

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestImportAzure(t *testing.T) {
	srv := serveFixture(t, `{"changeNumber":426,"cloud":"Public","values":[
		{"name":"AzureCloud","properties":{"addressPrefixes":["4.144.0.0/12","2603:1000::/24"]}},
		{"name":"AzureFrontDoor.Frontend","properties":{"addressPrefixes":["13.107.246.0/24"]}},
		{"name":"Storage","properties":{"addressPrefixes":["20.38.96.0/20"]}}]}`)
	b := newCategoryBuilder(context.Background())
	n, err := b.ImportAzureFrom(srv.URL)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, map[string]bool{"cloud:azure": true}, b.prefixes["4.144.0.0/12"])
	require.Equal(t, map[string]bool{"cloud:azure": true, "cdn": true}, b.prefixes["13.107.246.0/24"])
	require.NotContains(t, b.prefixes, "20.38.96.0/20")
}

func TestICloudRelayRoundTrip(t *testing.T) {
	srv := serveFixture(t, "172.224.226.0/27,GB,GB-EN,London,\n2a02:26f7:b3c0:4000::/64,AU,AU-NSW,Sydney,\nbad,XX,,,\n")
	db := buildTestCategoryDB(t, func(b *categoryBuilder) {
		n, err := b.ImportICloudRelayFrom(srv.URL)
		require.NoError(t, err)
		require.Equal(t, 2, n)
		b.addASN(36183, "cdn")
	})
	loc, ok := db.RelayLocation(net.ParseIP("172.224.226.5"))
	require.True(t, ok)
	require.Equal(t, RelayLocation{Country: "GB", Region: "GB-EN", City: "London"}, loc)
	loc, ok = db.RelayLocation(net.ParseIP("2a02:26f7:b3c0:4000::1"))
	require.True(t, ok)
	require.Equal(t, "Sydney", loc.City)
	_, ok = db.RelayLocation(net.ParseIP("8.8.8.8"))
	require.False(t, ok)
	// relay:icloud says what the address is, so the AS's cdn tag stays out.
	require.Equal(t, "relay:icloud", db.Lookup(net.ParseIP("172.224.226.5"), 36183, true))
}

func TestSupplementaryTagsKeepTheNetworksTags(t *testing.T) {
	db := buildTestCategoryDB(t, func(b *categoryBuilder) {
		b.addPrefix("162.142.125.0/24", "scanner:censys")
		b.addPrefix("1.2.3.4/32", "public-dns")
		b.addASN(398324, "hosting")
		b.addASN(64500, "isp")
	})
	require.Equal(t, "hosting, scanner:censys", db.Lookup(net.ParseIP("162.142.125.9"), 398324, true))
	require.Equal(t, "isp, public-dns", db.Lookup(net.ParseIP("1.2.3.4"), 64500, true))
}

func TestMISPListTags(t *testing.T) {
	require.Equal(t, []string{"scanner:censys"}, MISPListTags("censys-scanning"))
	require.Equal(t, []string{"scanner:shodan"}, MISPListTags("shodan-nt-scanning"))
	require.Equal(t, []string{"scanner:modat"}, MISPListTags("modat-scanner"))
	require.Equal(t, []string{"cloud:ibm"}, MISPListTags("ibm-cloud"))
	require.Equal(t, []string{"cdn", "cloud:akamai"}, MISPListTags("akamai"))
	require.Nil(t, MISPListTags("amazon-aws"))
	require.Nil(t, MISPListTags("rfc1918"))
	require.Nil(t, MISPListTags("some-new-list"))
}

func mispTarball(t *testing.T, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}))
		_, err := tw.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.String()
}

func TestImportMISP(t *testing.T) {
	srv := serveFixture(t, mispTarball(t, map[string]string{
		"misp-warninglists-main/lists/censys-scanning/list.json": `{"name":"Censys IP Ranges Used for Scanning","type":"cidr","list":["162.142.125.0/24","2602:80d:1000::/44"]}`,
		"misp-warninglists-main/lists/ibm-cloud/list.json":       `{"name":"IBM","type":"cidr","list":["5.10.64.0/20"]}`,
		"misp-warninglists-main/lists/amazon-aws/list.json":      `{"name":"AWS","type":"cidr","list":["3.0.0.0/8"]}`,
		"misp-warninglists-main/lists/google-domains/list.json":  `{"name":"Google domains","type":"hostname","list":["google.com"]}`,
		"misp-warninglists-main/lists/sinkholes/list.json":       `{"name":"Sinkholes","type":"string","list":["sinkhole.example"]}`,
		"misp-warninglists-main/README.md":                       "# lists",
	}))
	b := newCategoryBuilder(context.Background())
	n, err := b.ImportMISPFrom(srv.URL)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, map[string]bool{"scanner:censys": true}, b.prefixes["162.142.125.0/24"])
	require.Equal(t, map[string]bool{"cloud:ibm": true}, b.prefixes["5.10.64.0/20"])
	require.NotContains(t, b.prefixes, "3.0.0.0/8")
	require.Equal(t, "MISP warninglist: Censys IP Ranges Used for Scanning", b.vpnLists["scanner:censys"].Source)
}

func TestImportFeodo(t *testing.T) {
	srv := serveFixture(t, `[{"ip_address":"50.16.16.211","port":443,"malware":"QakBot"},{"ip_address":"162.243.103.246","malware":"Emotet"},{"ip_address":"nope","malware":"X"}]`)
	b := newReputationBuilder(context.Background())
	n, err := b.ImportFeodoFrom(srv.URL)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	p, _ := parsePrefix("50.16.16.211")
	require.True(t, b.prefixes[p]["feodo:QakBot"])
	require.True(t, b.listed[p])
}

func TestIPv6PrefixesStayOutOfIPv4(t *testing.T) {
	db := buildTestCategoryDB(t, func(b *categoryBuilder) {
		b.addPrefix("::/10", "bogon")                                          // Team Cymru's IPv6 list
		b.addPrefix("::ffff:146.112.61.104/128", "service:umbrella-blockpage") // MISP writes IPv4 this way
		b.addPrefix("5.10.96.0/19", "cloud:ibm")
		b.addASN(36351, "hosting")
	})
	require.Equal(t, "hosting", db.Lookup(net.ParseIP("5.10.64.1"), 36351, true))
	require.Equal(t, "cloud:ibm", db.Lookup(net.ParseIP("5.10.96.1"), 36351, true))
	require.Equal(t, "service:umbrella-blockpage", db.Lookup(net.ParseIP("146.112.61.104"), 0, false))
	require.Equal(t, "bogon", db.Lookup(net.ParseIP("::1:2"), 0, false))
	require.Equal(t, "bogon", db.Lookup(net.ParseIP("1::"), 0, false))
}
