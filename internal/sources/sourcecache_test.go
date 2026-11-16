package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSourceCacheServesRetriesFromCache(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("192.0.2.0/24\n198.51.100.0/24\n"))
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	build := func() int {
		ctx, _ := withSourceCache(context.Background(), dir)
		n, err := newCategoryBuilder(ctx).ImportCIDRList(srv.URL+"/ranges", "", "cloud:test")
		require.NoError(t, err)
		return n
	}
	require.Equal(t, 2, build())
	require.Equal(t, 2, build(), "a retry reads the same data")
	require.EqualValues(t, 1, hits.Load(), "a retry within the cache window contacted the provider again")
}

func TestSourceCacheDiscardsWhatASourceFailedToParse(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("not json"))
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	// No discard: a VPN API that fails inside a source that succeeds overall
	// relies on fetchJSON dropping the bad payload itself.
	for i := 0; i < 2; i++ {
		ctx, _ := withSourceCache(context.Background(), dir)
		var doc struct{}
		require.Error(t, fetchJSON(ctx, srv.URL+"/api", "", &doc))
	}
	require.EqualValues(t, 2, hits.Load(), "an unparseable payload was served from the cache")
}

func TestHTTPGetUAWithoutSourceCacheIsUncached(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	t.Cleanup(srv.Close)
	for i := 0; i < 2; i++ {
		resp, err := httpGetUA(context.Background(), srv.URL, "")
		require.NoError(t, err)
		resp.Body.Close()
	}
	require.EqualValues(t, 2, hits.Load())
}
