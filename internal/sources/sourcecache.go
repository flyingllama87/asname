package sources

import (
	"context"
	"net/http"
	"os"
	"sync"
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
}

func withSourceCache(ctx context.Context, dir string) (context.Context, *sourceCache) {
	sc := &sourceCache{dir: dir}
	return context.WithValue(ctx, sourceCacheKey{}, sc), sc
}

// begin starts a new source.
func (sc *sourceCache) begin() {
	sc.mu.Lock()
	sc.used = sc.used[:0]
	sc.mu.Unlock()
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
