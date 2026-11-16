package sources

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseGeofeed(t *testing.T) {
	feed := "\xef\xbb\xbf# RFC 8805 feed\n" +
		"192.0.2.0/24,NL,NL-LI,Kerkrade,6461\n" +
		"198.51.100.7,au,AU-NSW,  Sydney  ,\n" +
		"2001:db8::/32,DE,DE-BE,Berlin\n" +
		"203.0.113.0/24,,,\n" +
		"\"203.0.113.128/25\",\"US\",\"US-CA\",\"Los Angeles\"\n" +
		"10.0.0.0/8,US,CA-ON,Toronto\n" + // region of another country: dropped
		"10.1.0.0/16,GB,GB-ENG,12345\n" + // a number is not a city: dropped
		"not-a-prefix,US,,\n" +
		"10.2.0.0/16,USA,,\n" +
		"\n"
	entries, bad, err := parseGeofeed(strings.NewReader(feed))
	require.NoError(t, err)
	require.Equal(t, 2, bad)
	require.Equal(t, []geofeedEntry{
		{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Country: "NL", Region: "NL-LI", City: "Kerkrade"},
		{Prefix: netip.MustParsePrefix("198.51.100.7/32"), Country: "AU", Region: "AU-NSW", City: "Sydney"},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Country: "DE", Region: "DE-BE", City: "Berlin"},
		{Prefix: netip.MustParsePrefix("203.0.113.0/24")},
		{Prefix: netip.MustParsePrefix("203.0.113.128/25"), Country: "US", Region: "US-CA", City: "Los Angeles"},
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Country: "US"},
		{Prefix: netip.MustParsePrefix("10.1.0.0/16"), Country: "GB", Region: "GB-ENG"},
	}, entries)
}

func TestCleanGeofeedURL(t *testing.T) {
	require.Equal(t, "https://example.net/geofeed.csv", cleanGeofeedURL(" https://example.net/geofeed.csv # comment"))
	require.Equal(t, "", cleanGeofeedURL("http://example.net/geofeed.csv"), "RFC 9092 requires HTTPS")
	require.Equal(t, "", cleanGeofeedURL("https://user:pw@example.net/feed.csv"))
	require.Equal(t, "", cleanGeofeedURL("example.net/feed.csv"))
	require.Equal(t, "https://example.net/f.csv", geofeedRemark("Geofeed https://example.net/f.csv"))
	require.Equal(t, "", geofeedRemark("Geofeed data is at https://example.net/f.csv"))
}

func TestScanDumpReadsGeofeedRemarks(t *testing.T) {
	path := writeDumpFixture(t, `inetnum:        192.0.2.0 - 192.0.2.255
netname:        EXAMPLE
remarks:        Contact noc@example.net
remarks:        Geofeed https://example.net/geofeed.csv

inetnum:        198.51.100.0 - 198.51.100.255
netname:        OTHER
geofeed:        https://other.example/feed.csv
remarks:        Geofeed https://ignored.example/feed.csv
`)
	var got []string
	require.NoError(t, scanDump(path, func(attrs []attr) error {
		got = append(got, attrValue(attrs, "geofeed"))
		return nil
	}, "inetnum", "netname", "geofeed"))
	require.Equal(t, []string{"https://example.net/geofeed.csv", "https://other.example/feed.csv"}, got)
}

func TestGeofeedRefsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), GeofeedRefsFilename)
	b := newNetblockBuilder()
	b.addGeofeedRef(net.ParseIP("192.0.2.0"), net.ParseIP("192.0.2.255"), "https://a.example/f.csv")
	b.addGeofeedRef(net.ParseIP("2001:db8::"), net.ParseIP("2001:db8::ffff"), "https://a.example/f.csv")
	b.addGeofeedRef(net.ParseIP("192.0.2.9"), net.ParseIP("192.0.2.1"), "https://bad.example/") // reversed
	require.NoError(t, writeGeofeedRefs(path, b.geofeeds))
	refs, err := readGeofeedRefs(path)
	require.NoError(t, err)
	require.Equal(t, []geofeedRef{
		{Start: netip.MustParseAddr("192.0.2.0"), End: netip.MustParseAddr("192.0.2.255"), URL: "https://a.example/f.csv"},
		{Start: netip.MustParseAddr("2001:db8::"), End: netip.MustParseAddr("2001:db8::ffff"), URL: "https://a.example/f.csv"},
	}, refs)
}

// TestUpdateGeofeedDB builds from feeds on a local HTTPS server: each feed
// counts only inside the ranges naming it, the most specific range deciding.
func TestUpdateGeofeedDB(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a.csv", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("192.0.2.0/24,NL,NL-LI,Kerkrade\n" +
			"198.51.100.0/25,AU,AU-NSW,Sydney\n" +
			"198.51.100.64/26,,,\n" + // withheld inside the /25
			"203.0.113.0/24,US,US-CA,Los Angeles\n" + // not A's to place
			"2001:db8:1::/48,DE,DE-BE,Berlin\n" +
			"junk\n"))
	})
	mux.HandleFunc("/b.csv", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("192.0.2.0/24,GB,GB-ENG,London\n"))
	})
	mux.HandleFunc("/page.html", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>Not here</body></html>\n"))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	old := geofeedHTTPClient
	geofeedHTTPClient = srv.Client()
	defer func() { geofeedHTTPClient = old }()

	dir := t.TempDir()
	cfg := Config{NetblockPath: filepath.Join(dir, NetblockFilename), GeofeedPath: filepath.Join(dir, GeofeedFilename)}
	ref := func(start, end, path string) geofeedRef {
		return geofeedRef{Start: netip.MustParseAddr(start), End: netip.MustParseAddr(end), URL: srv.URL + path}
	}
	require.NoError(t, writeGeofeedRefs(GeofeedRefsPath(cfg.NetblockPath), []geofeedRef{
		ref("192.0.2.0", "192.0.2.255", "/a.csv"),
		ref("192.0.2.128", "192.0.2.255", "/b.csv"), // more specific: B speaks for the upper half
		ref("198.51.100.0", "198.51.100.255", "/a.csv"),
		ref("2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "/a.csv"),
		ref("203.0.113.0", "203.0.113.255", "/missing.csv"),
		ref("100.64.0.0", "100.64.0.255", "/page.html"),
	}))
	require.NoError(t, UpdateGeofeedDB(context.Background(), cfg))

	db, err := OpenGeofeedDB(cfg.GeofeedPath)
	require.NoError(t, err)
	for ip, want := range map[string]string{
		"192.0.2.10":        "Kerkrade, NL-LI, Netherlands",
		"192.0.2.200":       "London, GB-ENG, United Kingdom",
		"198.51.100.10":     "Sydney, AU-NSW, Australia",
		"198.51.100.70":     "",
		"198.51.100.200":    "",
		"203.0.113.5":       "",
		"2001:db8:1::1":     "Berlin, DE-BE, Germany",
		"2001:db8:2::1":     "",
		"100.64.0.1":        "",
		"192.0.2.127":       "Kerkrade, NL-LI, Netherlands",
		"192.0.2.128":       "London, GB-ENG, United Kingdom",
		"198.51.100.127":    "",
		"198.51.100.63":     "Sydney, AU-NSW, Australia",
		"203.0.113.255":     "",
		"192.0.2.255":       "London, GB-ENG, United Kingdom",
		"198.51.100.0":      "Sydney, AU-NSW, Australia",
		"2001:db8:1:ffff::": "Berlin, DE-BE, Germany",
	} {
		loc, ok := db.Lookup(net.ParseIP(ip))
		if want == "" {
			require.False(t, ok, "%s: got %v", ip, loc)
			continue
		}
		require.True(t, ok, ip)
		require.Equal(t, want, loc.String(), ip)
	}
	loc, _ := db.Lookup(net.ParseIP("192.0.2.200"))
	require.Equal(t, srv.URL+"/b.csv", loc.Feed)
}

func TestUpdateGeofeedDBNeedsReferences(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{NetblockPath: filepath.Join(dir, NetblockFilename), GeofeedPath: filepath.Join(dir, GeofeedFilename)}
	err := UpdateGeofeedDB(context.Background(), cfg)
	require.ErrorContains(t, err, "--netblock-only")
	require.False(t, GeofeedDBPresent(cfg.GeofeedPath))
}

func TestHostGateRetriesWhenAskedToSlowDown(t *testing.T) {
	var hits int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits == 1 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		w.Write([]byte("192.0.2.0/24,NL,NL-LI,Kerkrade\n"))
	}))
	defer srv.Close()
	old := geofeedHTTPClient
	geofeedHTTPClient = srv.Client()
	defer func() { geofeedHTTPClient = old }()

	g := &hostGate{}
	entries, _, err := g.fetch(context.Background(), srv.URL+"/f.csv")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, 2, hits)
	require.Equal(t, time.Second, g.gap, "the host is paced from then on")
}

func TestHostGateGivesUpOnADeadHost(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing listens any more
	g := &hostGate{misses: geofeedHostMisses - 1}
	_, _, err := g.fetch(context.Background(), url+"/f.csv")
	require.Error(t, err)
	require.True(t, g.down())
	_, _, err = g.fetch(context.Background(), url+"/g.csv")
	require.ErrorContains(t, err, "host unreachable")
}
