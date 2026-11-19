package sources

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFetchCachedReusesADownloadedFile(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write([]byte("payload"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		path, err := fetchCached(context.Background(), dir, srv.URL+"/rib.bz2", "")
		require.NoError(t, err)
		body, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, "payload", string(body))
	}
	require.Equal(t, 1, hits, "a cached file must not be downloaded again")
}

func TestFetchCachedResumesAnInterruptedDownload(t *testing.T) {
	const body = "0123456789abcdef"

	var ranges []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rng := r.Header.Get("Range")
		ranges = append(ranges, rng)
		if rng == "" {
			// Claim the full length, then cut the connection halfway through.
			w.Header().Set("Content-Length", "16")
			w.Write([]byte(body[:8]))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			panic(http.ErrAbortHandler)
		}
		off := 0
		require.Equal(t, 1, mustScan(t, rng, &off))
		w.Header().Set("Content-Range", "bytes 8-15/16")
		w.WriteHeader(http.StatusPartialContent)
		w.Write([]byte(body[off:]))
	}))
	defer srv.Close()

	dir := t.TempDir()
	url := srv.URL + "/dump.gz"

	_, err := fetchCached(context.Background(), dir, url, "")
	require.Error(t, err, "the interrupted download must be reported as a failure")

	part := filepath.Join(dir, cacheName(url)+partSuffix)
	info, err := os.Stat(part)
	require.NoError(t, err, "the bytes already received must be kept")
	require.Equal(t, int64(8), info.Size())

	path, err := fetchCached(context.Background(), dir, url, "")
	require.NoError(t, err)
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, body, string(got))
	require.Equal(t, []string{"", "bytes=8-"}, ranges, "the retry must ask only for the missing bytes")

	_, err = os.Stat(part)
	require.True(t, os.IsNotExist(err), "the partial file must be replaced by the complete one")
}

func TestFetchCachedRefetchesAfterTheTTL(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write([]byte("payload"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	url := srv.URL + "/asn.txt"
	path, err := fetchCached(context.Background(), dir, url, "")
	require.NoError(t, err)

	stale := time.Now().Add(-CacheTTL - time.Minute)
	require.NoError(t, os.Chtimes(path, stale, stale))

	_, err = fetchCached(context.Background(), dir, url, "")
	require.NoError(t, err)
	require.Equal(t, 2, hits, "an entry older than the TTL must be downloaded again")
}

func TestCacheNameKeepsURLsApart(t *testing.T) {
	a := cacheName("https://ftp.ripe.net/ripe/asnames/asn.txt")
	b := cacheName("https://example.org/other/asn.txt")
	require.NotEqual(t, a, b)
	require.True(t, strings.HasSuffix(a, "-asn.txt"), a)
	require.Equal(t, a, cacheName("https://ftp.ripe.net/ripe/asnames/asn.txt"))
}

// mustScan reads "bytes=<n>-" into off and reports how many values it parsed.
func mustScan(t *testing.T, rng string, off *int) int {
	t.Helper()
	n, err := fmtSscanf(rng, off)
	require.NoError(t, err)
	return n
}

func fmtSscanf(rng string, off *int) (int, error) {
	return fmt.Sscanf(rng, "bytes=%d-", off)
}

func TestFetchCachedRejectsAWrongRange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Range", "bytes 0-15/16")
		w.WriteHeader(http.StatusPartialContent)
		w.Write([]byte("0123456789abcdef"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	url := srv.URL + "/dump.gz"
	part := filepath.Join(dir, cacheName(url)+partSuffix)
	require.NoError(t, os.WriteFile(part, []byte("01234567"), 0o644))

	_, err := fetchCached(context.Background(), dir, url, "")
	require.ErrorContains(t, err, "Content-Range")

	_, err = os.Stat(part)
	require.True(t, os.IsNotExist(err), "a partial file the server will not resume must be discarded")
}

func TestFetchCachedFallsBackToTheLastGoodCopy(t *testing.T) {
	up := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("payload"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	url := srv.URL + "/list.txt"
	path, err := fetchCached(context.Background(), dir, url, "")
	require.NoError(t, err)
	old := time.Now().Add(-CacheTTL - time.Hour)
	require.NoError(t, os.Chtimes(path, old, old))

	up = false
	ctx, stale := withStaleTracker(context.Background())
	got, err := fetchCached(ctx, dir, url, "")
	require.NoError(t, err, "the last good copy stands in for the failed download")
	body, err := os.ReadFile(got)
	require.NoError(t, err)
	require.Equal(t, "payload", string(body))
	require.WithinDuration(t, old, stale.since(), time.Second, "the fallback is dated by the copy")

	_, err = fetchCached(context.Background(), t.TempDir(), url, "")
	require.Error(t, err, "with no good copy ever, the failure stands")
}

func TestFeedCacheLastGood(t *testing.T) {
	c := newFeedCache(t.TempDir())
	url := "https://example.net/geofeed.csv"
	_, ok := c.lastGood(url)
	require.False(t, ok, "nothing kept yet")
	c.keep(url, []byte("192.0.2.0/24,AU,AU-QLD,Brisbane,\n"))
	body, ok := c.lastGood(url)
	require.True(t, ok)
	require.Contains(t, string(body), "Brisbane")
	n, oldest := c.staleUse()
	require.Equal(t, 1, n)
	require.False(t, oldest.IsZero())

	lg := filepath.Join(c.dir, LastGoodDirName, cacheName(url))
	old := time.Now().Add(-LastGoodMaxAge - time.Hour)
	require.NoError(t, os.Chtimes(lg, old, old))
	_, ok = c.lastGood(url)
	require.False(t, ok, "too old to stand in")
}
