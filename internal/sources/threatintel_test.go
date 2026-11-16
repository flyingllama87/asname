package sources

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestImportC2Intel(t *testing.T) {
	srv := serveFixture(t, "#ip,ioc\n1.117.74.144,Possible Cobaltstrike C2 IP\n203.0.113.5,Possible Sliver C2 IP\nbad,x\n")
	b := newReputationBuilder(context.Background())
	n, err := b.ImportC2IntelFrom(srv.URL)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	p, _ := parsePrefix("1.117.74.144")
	require.True(t, b.prefixes[p]["c2intel:Cobalt Strike"])
	p, _ = parsePrefix("203.0.113.5")
	require.True(t, b.prefixes[p]["c2intel:Sliver"])
}

func TestImportThreatFoxKeepsIPsAndSendsTheKey(t *testing.T) {
	var gotKey, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("Auth-Key")
		body, _ := io.ReadAll(r.Body)
		var q map[string]any
		json.Unmarshal(body, &q)
		gotQuery, _ = q["query"].(string)
		w.Write([]byte(`{"query_status":"ok","data":[
			{"ioc":"45.61.1.2:443","ioc_type":"ip:port","malware_printable":"Cobalt Strike"},
			{"ioc":"[2001:db8::5]:8080","ioc_type":"ip:port","malware_printable":"Sliver"},
			{"ioc":"evil.example","ioc_type":"domain","malware_printable":"Lumma"},
			{"ioc":"http://evil.example/x","ioc_type":"url","malware_printable":"Lumma"}]}`))
	}))
	t.Cleanup(srv.Close)
	b := newReputationBuilder(context.Background())
	n, err := b.ImportThreatFoxFrom(srv.URL, "secret-key")
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.Equal(t, "secret-key", gotKey)
	require.Equal(t, "get_iocs", gotQuery)
	p, _ := parsePrefix("45.61.1.2")
	require.True(t, b.prefixes[p]["threatfox:Cobalt Strike"])
	p, _ = parsePrefix("2001:db8::5")
	require.True(t, b.prefixes[p]["threatfox:Sliver"])
	require.Len(t, b.prefixes, 2)
}

func TestImportThreatFoxReportsABadKeyWithoutIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	b := newReputationBuilder(context.Background())
	_, err := b.ImportThreatFoxFrom(srv.URL, "secret-key")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "secret-key")
}
