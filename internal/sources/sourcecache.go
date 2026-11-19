package sources

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// The category and reputation databases are built from many small API
// responses and lists. Within an update their downloads go through the same
// 24-hour cache as the registry dumps, so a retry soon after (`asname update
// --incremental`) contacts only the providers that failed, not every one.

type sourceCacheKey struct{}

// sourceCache routes httpGetUA through the download cache and remembers which
// URLs the current source used, so a source whose payload will not parse can
// drop them and fetch afresh next time.
type sourceCache struct {
	dir  string
	mu   sync.Mutex
	used []string
	// stale is the oldest last good copy the current source fell back to.
	stale *staleTracker
}

func withSourceCache(ctx context.Context, dir string) (context.Context, *sourceCache) {
	sc := &sourceCache{dir: dir, stale: &staleTracker{}}
	ctx = context.WithValue(ctx, sourceCacheKey{}, sc)
	return context.WithValue(ctx, staleKey{}, sc.stale), sc
}

// begin starts a new source.
func (sc *sourceCache) begin() {
	sc.mu.Lock()
	sc.used = sc.used[:0]
	sc.mu.Unlock()
	sc.stale.reset()
}

// keep makes every copy the current source used its last good one: it has
// parsed. It returns the date of the oldest last good copy the source fell
// back to, zero when every download worked.
func (sc *sourceCache) keep() time.Time {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	for _, url := range sc.used {
		if path := filepath.Join(sc.dir, cacheName(url)); fileExists(path) {
			keepLastGood(sc.dir, url, path)
		}
	}
	return sc.stale.since()
}

// discard drops the cached copies of everything the current source fetched.
func (sc *sourceCache) discard() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	for _, url := range sc.used {
		dropCached(sc.dir, url)
	}
	sc.used = sc.used[:0]
}

// get serves url from the cache, downloading it when there is no fresh copy.
func (sc *sourceCache) get(ctx context.Context, url, userAgent string) (*http.Response, error) {
	path, err := fetchCached(ctx, sc.dir, url, userAgent)
	if err != nil {
		return nil, err
	}
	sc.mu.Lock()
	sc.used = append(sc.used, url)
	sc.mu.Unlock()
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &http.Response{Status: "200 OK", StatusCode: http.StatusOK, Body: f, ContentLength: info.Size()}, nil
}

// staleTracker remembers the oldest last good copy a source fell back to
// because its download failed.
type staleTracker struct {
	mu     sync.Mutex
	oldest time.Time
}

type staleKey struct{}

// withStaleTracker starts tracking fallbacks to last good copies under ctx.
func withStaleTracker(ctx context.Context) (context.Context, *staleTracker) {
	t := &staleTracker{}
	return context.WithValue(ctx, staleKey{}, t), t
}

func (t *staleTracker) reset() {
	t.mu.Lock()
	t.oldest = time.Time{}
	t.mu.Unlock()
}

func (t *staleTracker) since() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.oldest
}

// noteStaleCopy records, for the tracker under ctx, a fallback to a last
// good copy written at when.
func noteStaleCopy(ctx context.Context, when time.Time) {
	t, ok := ctx.Value(staleKey{}).(*staleTracker)
	if !ok {
		return
	}
	t.mu.Lock()
	if t.oldest.IsZero() || when.Before(t.oldest) {
		t.oldest = when
	}
	t.mu.Unlock()
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
