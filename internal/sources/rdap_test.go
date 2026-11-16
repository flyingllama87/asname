package sources

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func readRDAPFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "rdap", name))
	require.NoError(t, err)
	return data
}

// The fixtures are real responses from each registry, trimmed to the fields
// asname reads, with individuals' names replaced.
func TestParseRDAPNetworkEachRegistry(t *testing.T) {
	cases := []struct {
		fixture string
		want    NetblockInfo
	}{
		{"arin-8.8.8.8.json", NetblockInfo{Netname: "GOGL", Org: "Google LLC",
			NetblockMeta: NetblockMeta{Created: "2023-12-28"}}},
		// RIPE lists its maintainer (RIPE-NCC-MNT) as a registrant too; the
		// organisation wins.
		{"ripe-193.0.6.139.json", NetblockInfo{Netname: "RIPE-NCC", Org: "Reseaux IP Europeens Network Coordination Centre (RIPE NCC)",
			NetblockMeta: NetblockMeta{Country: "NL", Created: "2003-03-17"}}},
		{"apnic-1.1.1.1.json", NetblockInfo{Netname: "APNIC-LABS", Org: "APNIC Research and Development",
			NetblockMeta: NetblockMeta{Country: "AU", Created: "2011-08-10"}}},
		{"afrinic-196.216.2.1.json", NetblockInfo{Netname: "ORG-AFNC1-AFRINIC", Org: "African Network Information Center - (AfriNIC) Ltd",
			NetblockMeta: NetblockMeta{Country: "ZA", Created: "2005-02-21"}}},
		// LACNIC redirects Brazilian space to registro.br. Its accents come
		// through intact, unlike LACNIC's port-43 whois; the numeric name
		// is dropped.
		{"registro.br-200.160.2.3.json", NetblockInfo{Org: "Núcleo de Inf. e Coord. do Ponto BR - NIC.BR",
			NetblockMeta: NetblockMeta{Country: "BR", Created: "2001-10-16"}}},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			got, err := ParseRDAPNetwork(readRDAPFixture(t, tc.fixture))
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestParseRDAPNetworkDescriptionFallback(t *testing.T) {
	got, err := ParseRDAPNetwork([]byte(`{"objectClassName":"ip network","name":"EXAMPLE-NET",
		"remarks":[{"title":"description","description":["Example Hosting Ltd","Second line"]}],
		"entities":[{"roles":["technical"],"vcardArray":["vcard",[["fn",{},"text","Someone"]]]}]}`))
	require.NoError(t, err)
	require.Equal(t, NetblockInfo{Netname: "EXAMPLE-NET", Org: "Example Hosting Ltd"}, got)
}

func TestParseRDAPNetworkRejectsOtherObjects(t *testing.T) {
	_, err := ParseRDAPNetwork([]byte(`{"objectClassName":"autnum","name":"X"}`))
	require.Error(t, err)
	_, err = ParseRDAPNetwork([]byte(`not json`))
	require.Error(t, err)
}

func TestRDAPBootstrapPicksTheRegistry(t *testing.T) {
	c := &RDAPClient{boot: map[string]*rdapBootstrap{}}
	for _, family := range []string{"ipv4", "ipv6"} {
		b, err := parseRDAPBootstrap(readRDAPFixture(t, "bootstrap-"+family+".json"))
		require.NoError(t, err)
		b.fetched = time.Now()
		c.boot[family] = b
	}
	for addr, want := range map[string]string{
		"8.8.8.8":         "https://rdap.arin.net/registry/",
		"193.0.6.139":     "https://rdap.db.ripe.net/",
		"1.1.1.1":         "https://rdap.apnic.net/",
		"200.160.2.3":     "https://rdap.lacnic.net/rdap/",
		"196.216.2.1":     "https://rdap.afrinic.net/rdap/",
		"2001:4860::8888": "https://rdap.arin.net/registry/",
		"2a00:1450::1":    "https://rdap.db.ripe.net/",
	} {
		got, err := c.serverFor(context.Background(), netip.MustParseAddr(addr))
		require.NoError(t, err, addr)
		require.Equal(t, want, got, addr)
	}
}

func TestParseRDAPBootstrapKeepsHTTPSOnly(t *testing.T) {
	_, err := parseRDAPBootstrap([]byte(`{"services":[[["10.0.0.0/8"],["http://insecure.example/"]]]}`))
	require.Error(t, err)
	b, err := parseRDAPBootstrap([]byte(`{"services":[[["10.0.0.0/8"],["http://a.example/","https://a.example/"]]]}`))
	require.NoError(t, err)
	require.Equal(t, "https://a.example/", b.services[0].base)
}

// fakeRDAP serves a bootstrap that sends every address to itself, and the
// network responses in nets (by address), counting requests.
type fakeRDAP struct {
	srv        *httptest.Server
	bootstraps atomic.Int32
	queries    atomic.Int32
	status     int // non-zero: answer every /ip/ query with this status
}

func newFakeRDAP(t *testing.T, nets map[string]string) *fakeRDAP {
	t.Helper()
	f := &fakeRDAP{}
	mux := http.NewServeMux()
	mux.HandleFunc("/bootstrap/", func(w http.ResponseWriter, r *http.Request) {
		f.bootstraps.Add(1)
		prefix := "0.0.0.0/0"
		if strings.HasSuffix(r.URL.Path, "ipv6.json") {
			prefix = "::/0"
		}
		_, _ = w.Write([]byte(`{"services":[[["` + prefix + `"],["` + f.srv.URL + `/rdap/"]]]}`))
	})
	mux.HandleFunc("/rdap/ip/", func(w http.ResponseWriter, r *http.Request) {
		f.queries.Add(1)
		if f.status != 0 {
			w.WriteHeader(f.status)
			return
		}
		addr := strings.TrimPrefix(r.URL.Path, "/rdap/ip/")
		if addr == "200.160.2.3" && r.URL.Query().Get("moved") == "" {
			// LACNIC's hand-off to registro.br.
			http.Redirect(w, r, f.srv.URL+"/rdap/ip/200.160.2.3?moved=1", http.StatusTemporaryRedirect)
			return
		}
		body, ok := nets[addr]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errorCode":404,"title":"Not Found"}`))
			return
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(body))
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRDAP) client(dir string) *RDAPClient {
	c := NewRDAPClient(dir)
	c.BootstrapURL = f.srv.URL + "/bootstrap/"
	c.HTTP = f.srv.Client()
	c.HTTP.CheckRedirect = httpsRedirectsOnly
	c.HTTPv4 = nil
	c.Whois = func(net.IP) (NetblockInfo, error) { return NetblockInfo{}, errors.New("whois not expected") }
	return c
}

func TestRDAPLookupNetblock(t *testing.T) {
	f := newFakeRDAP(t, map[string]string{
		"8.8.8.8":     string(readRDAPFixture(t, "arin-8.8.8.8.json")),
		"200.160.2.3": string(readRDAPFixture(t, "registro.br-200.160.2.3.json")),
	})
	dir := t.TempDir()
	c := f.client(dir)

	info, err := c.LookupNetblock(context.Background(), net.ParseIP("8.8.8.8"))
	require.NoError(t, err)
	require.Equal(t, "GOGL (Google LLC)", info.String())

	info, err = c.LookupNetblock(context.Background(), net.ParseIP("200.160.2.3"))
	require.NoError(t, err, "follows the redirect")
	require.Equal(t, "Núcleo de Inf. e Coord. do Ponto BR - NIC.BR", info.Org)

	_, err = c.LookupNetblock(context.Background(), net.ParseIP("9.9.9.9"))
	require.ErrorIs(t, err, ErrRDAPNotFound)

	require.EqualValues(t, 1, f.bootstraps.Load(), "the bootstrap is fetched once per run")
	_, err = os.Stat(filepath.Join(dir, "rdap-ipv4.json"))
	require.NoError(t, err, "and cached in the data directory")

	// A new client (the next run) reads the cache instead of IANA.
	_, err = f.client(dir).LookupNetblock(context.Background(), net.ParseIP("8.8.8.8"))
	require.NoError(t, err)
	require.EqualValues(t, 1, f.bootstraps.Load())
}

func TestRDAPBootstrapStaleCacheIsRefreshed(t *testing.T) {
	f := newFakeRDAP(t, map[string]string{"8.8.8.8": string(readRDAPFixture(t, "arin-8.8.8.8.json"))})
	dir := t.TempDir()
	_, err := f.client(dir).LookupNetblock(context.Background(), net.ParseIP("8.8.8.8"))
	require.NoError(t, err)
	old := time.Now().Add(-RDAPBootstrapTTL - time.Hour)
	require.NoError(t, os.Chtimes(filepath.Join(dir, "rdap-ipv4.json"), old, old))

	_, err = f.client(dir).LookupNetblock(context.Background(), net.ParseIP("8.8.8.8"))
	require.NoError(t, err)
	require.EqualValues(t, 2, f.bootstraps.Load(), "a stale cache is fetched again")

	// When IANA cannot be reached, the stale copy is still used.
	require.NoError(t, os.Chtimes(filepath.Join(dir, "rdap-ipv4.json"), old, old))
	c := f.client(dir)
	c.BootstrapURL = f.srv.URL + "/missing/"
	_, err = c.LookupNetblock(context.Background(), net.ParseIP("8.8.8.8"))
	require.NoError(t, err)
}

func TestRDAPRateLimitAndErrors(t *testing.T) {
	f := newFakeRDAP(t, nil)
	f.status = http.StatusTooManyRequests
	_, err := f.client("").LookupNetblock(context.Background(), net.ParseIP("8.8.8.8"))
	require.ErrorContains(t, err, "rate-limiting")

	f.status = http.StatusInternalServerError
	_, err = f.client("").LookupNetblock(context.Background(), net.ParseIP("8.8.8.8"))
	require.ErrorContains(t, err, "HTTP 500")
}

func TestLookupOnlineNetblockFallsBackToWhois(t *testing.T) {
	f := newFakeRDAP(t, map[string]string{"8.8.8.8": string(readRDAPFixture(t, "arin-8.8.8.8.json"))})
	whoisCalls := 0
	whois := func(net.IP) (NetblockInfo, error) {
		whoisCalls++
		return NetblockInfo{Netname: "FROM-WHOIS"}, nil
	}

	// RDAP answers: whois is not asked.
	c := f.client("")
	c.Whois = whois
	info, src, rdapErr, err := c.LookupOnlineNetblock(context.Background(), net.ParseIP("8.8.8.8"))
	require.NoError(t, err)
	require.NoError(t, rdapErr)
	require.Equal(t, OnlineSourceRDAP, src)
	require.Equal(t, "GOGL", info.Netname)
	require.Zero(t, whoisCalls)

	// RDAP fails: whois answers, and RDAP's error is passed back to log.
	f.status = http.StatusServiceUnavailable
	info, src, rdapErr, err = c.LookupOnlineNetblock(context.Background(), net.ParseIP("8.8.8.8"))
	require.NoError(t, err)
	require.ErrorContains(t, rdapErr, "HTTP 503")
	require.Equal(t, OnlineSourceWhois, src)
	require.Equal(t, "FROM-WHOIS", info.Netname)
	require.Equal(t, 1, whoisCalls)

	// Both fail: one error naming both.
	c.Whois = func(net.IP) (NetblockInfo, error) { return NetblockInfo{}, errors.New("whois down") }
	_, _, _, err = c.LookupOnlineNetblock(context.Background(), net.ParseIP("8.8.8.8"))
	require.ErrorContains(t, err, "RDAP: ")
	require.ErrorContains(t, err, "whois: whois down")
}

func TestRDAPRedirectsStayOnHTTPS(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://rdap.example/ip/1.2.3.4", nil)
	require.NoError(t, err)
	require.Error(t, httpsRedirectsOnly(req, []*http.Request{{}}))

	req, err = http.NewRequest(http.MethodGet, "https://rdap.example/ip/1.2.3.4", nil)
	require.NoError(t, err)
	require.NoError(t, httpsRedirectsOnly(req, []*http.Request{{}}))
	require.Error(t, httpsRedirectsOnly(req, make([]*http.Request, rdapRedirect)))
}

type failingTransport struct{ calls atomic.Int32 }

func (f *failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.calls.Add(1)
	return nil, errors.New("connection reset by peer")
}

func TestRDAPRetriesOverIPv4AndRemembers(t *testing.T) {
	f := newFakeRDAP(t, map[string]string{"8.8.8.8": string(readRDAPFixture(t, "arin-8.8.8.8.json"))})
	c := f.client("")
	broken := &failingTransport{}
	c.HTTPv4 = f.srv.Client() // the server listens on 127.0.0.1
	c.HTTP = &http.Client{Transport: broken}

	for range 3 {
		info, err := c.LookupNetblock(context.Background(), net.ParseIP("8.8.8.8"))
		require.NoError(t, err)
		require.Equal(t, "GOGL", info.Netname)
	}
	require.EqualValues(t, 1, broken.calls.Load(), "after one failure the host is asked over IPv4 directly")
}
