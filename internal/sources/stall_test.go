package sources

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFetchCachedAbandonsStalledDownload(t *testing.T) {
	old := idleTimeout
	idleTimeout = 200 * time.Millisecond
	t.Cleanup(func() { idleTimeout = old })

	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.Write(make([]byte, 100))
		w.(http.Flusher).Flush()
		select { // go silent with the connection open
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); srv.Close() })

	dir := t.TempDir()
	start := time.Now()
	_, err := fetchCached(context.Background(), dir, srv.URL+"/dump.gz", "")
	if !errors.Is(err, errStalled) {
		t.Fatalf("err = %v, want a stall", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %s to give up", d)
	}
	info, err := os.Stat(filepath.Join(dir, cacheName(srv.URL+"/dump.gz")+partSuffix))
	if err != nil || info.Size() != 100 {
		t.Errorf("partial file = %v, %v; want 100 bytes kept", info, err)
	}
}

func TestStallGuardSilentServer(t *testing.T) {
	old := idleTimeout
	idleTimeout = 200 * time.Millisecond
	t.Cleanup(func() { idleTimeout = old })

	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select { // never answer
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); srv.Close() })

	_, err := httpGetUA(context.Background(), srv.URL, "")
	if !errors.Is(err, errStalled) {
		t.Fatalf("err = %v, want a stall", err)
	}
}

func TestStallGuardSlowButSteady(t *testing.T) {
	old := idleTimeout
	idleTimeout = 300 * time.Millisecond
	t.Cleanup(func() { idleTimeout = old })

	// Ten chunks 100ms apart: a full second in all, but never idle for long.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 10; i++ {
			w.Write([]byte("0123456789"))
			w.(http.Flusher).Flush()
			time.Sleep(100 * time.Millisecond)
		}
	}))
	t.Cleanup(srv.Close)

	path, err := fetchCached(context.Background(), t.TempDir(), srv.URL+"/slow", "")
	if err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Size() != 100 {
		t.Errorf("size = %d, want 100", info.Size())
	}
}
