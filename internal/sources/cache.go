package sources

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// CacheDirName is the subdirectory of the data directory holding downloaded source files.
	CacheDirName = "cache"
	// CacheTTL is how long a downloaded source file is reused before it is fetched again.
	CacheTTL = 24 * time.Hour

	partSuffix = ".part"
)

// CacheDir returns the directory holding downloaded source files.
func (c Config) CacheDir() string {
	if c.CachePath != "" {
		return c.CachePath
	}
	if c.DBPath != "" {
		return filepath.Join(filepath.Dir(c.DBPath), CacheDirName)
	}
	return filepath.Join(DefaultDir(), CacheDirName)
}

// cacheName maps a URL to a stable filename: a readable basename plus a hash of
// the full URL, so that two sources sharing a basename cannot collide.
func cacheName(url string) string {
	sum := sha256.Sum256([]byte(url))
	base := url
	if i := strings.IndexAny(base, "?#"); i >= 0 {
		base = base[:i]
	}
	base = strings.Trim(base, "/")
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	base = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.', r == '-', r == '_':
			return r
		}
		return '_'
	}, base)
	if len(base) > 64 {
		base = base[len(base)-64:]
	}
	if base == "" {
		base = "download"
	}
	return hex.EncodeToString(sum[:6]) + "-" + base
}

// LastGoodDirName is the subdirectory of the cache holding the last copy of
// each source that downloaded successfully (and, for the category and
// reputation lists, also parsed). Age-based pruning never touches it, so a
// source that cannot be reached is built from its last good copy instead of
// being left out of the database.
const LastGoodDirName = "last-good"

// LastGoodMaxAge is how long a last good copy may stand in for a source that
// cannot be downloaded. Past it the source is left out, as one that never
// worked is, rather than served from ever older data.
const LastGoodMaxAge = 90 * 24 * time.Hour

func lastGoodPath(dir, url string) string {
	return filepath.Join(dir, LastGoodDirName, cacheName(url))
}

// keepLastGood records path, a good copy of url, as its last good copy: a
// hard link, so it costs no space while the cached copy lasts, or else a
// copy.
func keepLastGood(dir, url, path string) {
	lg := lastGoodPath(dir, url)
	if path == lg {
		return
	}
	if err := os.MkdirAll(filepath.Dir(lg), 0o755); err != nil {
		return
	}
	tmp := lg + ".new"
	os.Remove(tmp)
	if err := os.Link(path, tmp); err != nil {
		if err := copyFileTo(path, tmp); err != nil {
			os.Remove(tmp)
			return
		}
	}
	if err := os.Rename(tmp, lg); err != nil {
		os.Remove(tmp)
	}
}

func copyFileTo(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// fetchCached returns the path of a local copy of url in dir: a cached copy
// younger than CacheTTL, else a fresh download (resuming one a network
// failure interrupted), else, when the download fails, the last good copy,
// logged and recorded as stale. Outside a source cache each fresh copy
// becomes the last good one at once; a source cache promotes its copies
// only once they have parsed (sourceCache.keep).
func fetchCached(ctx context.Context, dir, url, userAgent string) (string, error) {
	path, err := downloadCached(ctx, dir, url, userAgent)
	if err == nil {
		if _, deferred := ctx.Value(sourceCacheKey{}).(*sourceCache); !deferred {
			keepLastGood(dir, url, path)
		}
		return path, nil
	}
	if ctx.Err() != nil {
		return "", err
	}
	lg := lastGoodPath(dir, url)
	info, serr := os.Stat(lg)
	if serr != nil || time.Since(info.ModTime()) > LastGoodMaxAge {
		return "", err
	}
	logf(ctx, "asname: %v; using the last good copy, from %s\n", err, info.ModTime().Local().Format("2 Jan 2006 15:04"))
	noteStaleCopy(ctx, info.ModTime())
	return lg, nil
}

// downloadCached is fetchCached without the fallback to the last good copy.
func downloadCached(ctx context.Context, dir, url, userAgent string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	pruneCache(dir)
	path := filepath.Join(dir, cacheName(url))

	if info, err := os.Stat(path); err == nil {
		if age := time.Since(info.ModTime()); age < CacheTTL {
			logf(ctx, "asname: using cached %s (%s old, %d bytes)\n",
				redactURL(url), age.Truncate(time.Second), info.Size())
			return path, nil
		}
		os.Remove(path)
	}

	part := path + partSuffix
	var have int64
	if info, err := os.Stat(part); err == nil {
		if time.Since(info.ModTime()) < CacheTTL {
			have = info.Size()
		} else {
			os.Remove(part)
		}
	}

	resp, err := httpGetFrom(ctx, url, userAgent, have)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusPartialContent:
		start, err := rangeStart(resp.Header.Get("Content-Range"))
		if err != nil || start != have {
			// The server answered with a range we did not ask for; start again.
			os.Remove(part)
			return "", fmt.Errorf("downloading %s: unusable Content-Range %q", redactURL(url), resp.Header.Get("Content-Range"))
		}
		logf(ctx, "asname: resuming %s at %d bytes\n", redactURL(url), have)
	case http.StatusRequestedRangeNotSatisfiable:
		// The partial file already holds the whole object.
		if err := os.Rename(part, path); err != nil {
			return "", err
		}
		logf(ctx, "asname: using cached %s (%d bytes)\n", redactURL(url), have)
		return path, nil
	case http.StatusOK:
		if have > 0 {
			logf(ctx, "asname: %s does not support resuming, downloading in full\n", redactURL(url))
		} else {
			logf(ctx, "asname: downloading %s\n", redactURL(url))
		}
		have = 0
	default:
		return "", fmt.Errorf("GET %s: %s", redactURL(url), resp.Status)
	}

	f, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return "", err
	}
	if err := f.Truncate(have); err != nil {
		f.Close()
		return "", err
	}
	if _, err := f.Seek(have, io.SeekStart); err != nil {
		f.Close()
		return "", err
	}
	n, copyErr := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if copyErr != nil {
		return "", fmt.Errorf("downloading %s: %w (%d bytes kept for the next attempt)", redactURL(url), copyErr, have+n)
	}
	if closeErr != nil {
		return "", closeErr
	}
	if want := resp.ContentLength; want >= 0 && n != want {
		return "", fmt.Errorf("downloading %s: got %d bytes, expected %d (partial file kept for the next attempt)",
			redactURL(url), n, want)
	}
	if err := os.Rename(part, path); err != nil {
		return "", err
	}
	return path, nil
}

type basicAuthKey struct{}

type basicAuth struct{ user, pass string }

// withBasicAuth makes the downloads under ctx log in to their host.
func withBasicAuth(ctx context.Context, user, pass string) context.Context {
	return context.WithValue(ctx, basicAuthKey{}, basicAuth{user, pass})
}

// openCached is fetchCached followed by opening the result for reading.
func openCached(ctx context.Context, dir, url, userAgent string) (*os.File, error) {
	path, err := fetchCached(ctx, dir, url, userAgent)
	if err != nil {
		return nil, err
	}
	return os.Open(path)
}

// dropCached removes the cached copy of url. It is called when the payload
// downloaded cleanly but will not parse, so that the next run fetches it again.
func dropCached(dir, url string) {
	os.Remove(filepath.Join(dir, cacheName(url)))
	os.Remove(filepath.Join(dir, cacheName(url)+partSuffix))
}

// pruneCache deletes cache entries older than CacheTTL.
func pruneCache(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if time.Since(info.ModTime()) > CacheTTL {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// rangeStart reads the first byte offset out of a "bytes <start>-<end>/<total>" header.
func rangeStart(header string) (int64, error) {
	var start, end, total int64
	if _, err := fmt.Sscanf(strings.TrimSpace(header), "bytes %d-%d/%d", &start, &end, &total); err != nil {
		return 0, err
	}
	return start, nil
}

// httpGetFrom issues a GET, asking for the bytes from offset onwards when offset is positive.
// A throttled or failing server is retried (see doWithRetry).
func httpGetFrom(ctx context.Context, url, userAgent string, offset int64) (*http.Response, error) {
	auth, _ := ctx.Value(basicAuthKey{}).(basicAuth)
	return doWithRetry(ctx, url, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", orDefaultAgent(userAgent))
		// Go drops the header when a redirect leaves the host, so the
		// credentials go to that host only.
		if auth.user != "" {
			req.SetBasicAuth(auth.user, auth.pass)
		}
		if offset > 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
		}
		return req, nil
	})
}
