package engine

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/flyingllama87/asname/internal/sources"
)

// rdapTestEngine is NewTestEngine with AS64500's name missing offline and
// an RDAP server that knows it. queries counts autnum requests.
func rdapTestEngine(t *testing.T, mode sources.WhoisMode) (*Engine, *atomic.Int32) {
	t.Helper()
	var queries atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/asn.json"):
			_, _ = io.WriteString(w, `{"services":[[["1-4294967295"],["`+srv.URL+`/"]]]}`)
		case r.URL.Path == "/autnum/64500":
			queries.Add(1)
			_, _ = io.WriteString(w, `{"objectClassName":"autnum","name":"EXAMPLE-AS","country":"GB",
				"entities":[{"roles":["registrant"],"vcardArray":["vcard",[["kind",{},"text","org"],["fn",{},"text","Example Networks Ltd"]]]}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	e := NewTestEngine(t)
	e.db = BuildTestDatabase(t, "192.0.2.0/24", 64500)
	e.log = io.Discard
	e.whois = sources.NewWhoisAsker("", mode)
	e.whois.Out = io.Discard
	e.rdap = sources.NewRDAPClient("")
	e.rdap.BootstrapURL = srv.URL + "/"
	e.rdap.HTTP = srv.Client()
	e.rdap.HTTPv4 = nil
	e.rdapASNames = &sync.Map{}
	return e, &queries
}

func TestOnlineASNameFillsAMissingName(t *testing.T) {
	e, queries := rdapTestEngine(t, sources.WhoisAlways)

	res, err := e.LookupASN(64500)
	require.NoError(t, err)
	require.Equal(t, "EXAMPLE-AS - Example Networks Ltd, GB", res.Name)
	require.Equal(t, sources.OnlineSourceRDAP, res.NameSource)
	require.Equal(t, "GB, United Kingdom", res.Country)

	ip, err := e.Lookup(net.ParseIP("192.0.2.1"))
	require.NoError(t, err)
	require.Equal(t, "EXAMPLE-AS - Example Networks Ltd, GB", ip.Name)
	require.Equal(t, sources.OnlineSourceRDAP, ip.NameSource)
	require.EqualValues(t, 1, queries.Load(), "a name found once is reused")

	// A name the offline list has is never looked up.
	res, err = e.LookupASN(15169)
	require.NoError(t, err)
	require.Empty(t, res.NameSource)
}

func TestOnlineASNameNeedsOptIn(t *testing.T) {
	e, queries := rdapTestEngine(t, sources.WhoisNever)
	res, err := e.LookupASN(64500)
	require.NoError(t, err)
	require.Equal(t, "Unknown", res.Name)
	require.Empty(t, res.NameSource)
	require.Zero(t, queries.Load())

	// A view with online lookups on asks; one with them off does not even
	// reuse what the other found.
	on := e.WithOnline(Online{Whois: true})
	res, err = on.LookupASN(64500)
	require.NoError(t, err)
	require.Equal(t, sources.OnlineSourceRDAP, res.NameSource)
	res, err = e.WithOnline(Online{}).LookupASN(64500)
	require.NoError(t, err)
	require.Equal(t, "Unknown", res.Name)
}
