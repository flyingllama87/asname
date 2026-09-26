package sources

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fastRetries shrinks the backoff for the duration of a test.
func fastRetries(t *testing.T) {
	t.Helper()
	base, maxDelay := retryBaseDelay, retryMaxDelay
	retryBaseDelay, retryMaxDelay = time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { retryBaseDelay, retryMaxDelay = base, maxDelay })
}

func TestHTTPGetRetriesAThrottledRequest(t *testing.T) {
	fastRetries(t)
	var hits atomic.Int32
	var agent atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agent.Store(r.UserAgent())
		if hits.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	resp, err := httpGetUA(context.Background(), srv.URL, "")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, int32(2), hits.Load())
	assert.Contains(t, agent.Load(), "asname/", "requests should name asname, not Go's default agent")
}

func TestHTTPGetGivesUpAfterTheLastAttempt(t *testing.T) {
	fastRetries(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, err := httpGetUA(context.Background(), srv.URL, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "503")
	assert.Equal(t, int32(retryAttempts), hits.Load())

	// A status that asking again cannot fix is not retried.
	hits.Store(0)
	missing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	defer missing.Close()
	_, err = httpGetUA(context.Background(), missing.URL, "")
	require.Error(t, err)
	assert.Equal(t, int32(1), hits.Load())
}

func TestRetryWaitHonoursCancellation(t *testing.T) {
	base := retryBaseDelay
	retryBaseDelay = time.Hour
	t.Cleanup(func() { retryBaseDelay = base })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := httpGetUA(ctx, srv.URL, "")
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 5*time.Second)
}

func TestRetryAfter(t *testing.T) {
	d, ok := retryAfter("7")
	assert.True(t, ok)
	assert.Equal(t, 7*time.Second, d)

	d, ok = retryAfter(time.Now().Add(-time.Minute).UTC().Format(http.TimeFormat))
	assert.True(t, ok)
	assert.Equal(t, time.Duration(0), d, "a date in the past means retry now")

	for _, bad := range []string{"", "soon", "-3"} {
		_, ok := retryAfter(bad)
		assert.False(t, ok, bad)
	}
}

// TestUpdateCountryDBKeepsTheOldFileWhenARegistryFails pins that a country
// database is never rebuilt without one of the registries: each covers a
// whole region, so a partial build would silently blind it.
func TestUpdateCountryDBKeepsTheOldFileWhenARegistryFails(t *testing.T) {
	fastRetries(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/throttled" {
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		w.Write([]byte("2|ripencc|20260925|1|19830705|20260925|+0100\n" +
			"ripencc|DE|ipv4|185.220.101.0|256|20100101|allocated\n"))
	}))
	defer srv.Close()

	urls := rirDelegatedURLs
	t.Cleanup(func() { rirDelegatedURLs = urls })
	rirDelegatedURLs = []string{srv.URL + "/ok", srv.URL + "/throttled"}

	dir := t.TempDir()
	cfg := Config{CountryPath: filepath.Join(dir, CountryFilename), CachePath: filepath.Join(dir, CacheDirName)}
	require.NoError(t, os.WriteFile(cfg.CountryPath, []byte("previous"), 0o644))

	err := UpdateCountryDB(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1 of 2 registries failed")
	kept, readErr := os.ReadFile(cfg.CountryPath)
	require.NoError(t, readErr)
	assert.Equal(t, "previous", string(kept))

	// Once every registry answers, the database is rebuilt.
	rirDelegatedURLs = []string{srv.URL + "/ok"}
	require.NoError(t, UpdateCountryDB(context.Background(), cfg))
	db, err := LoadCountryDB(cfg.CountryPath)
	require.NoError(t, err)
	assert.Equal(t, "DE, Germany", LookupCountry(db, net.ParseIP("185.220.101.1")))
}
