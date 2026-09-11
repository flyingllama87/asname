package sources

import (
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

// fetchCached downloads url into dir and returns the path of the local copy. A
// copy younger than CacheTTL is reused without contacting the server, and a
// download interrupted by a network failure is resumed where it stopped rather
// than started again.
func fetchCached(dir, url, userAgent string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	pruneCache(dir)
	path := filepath.Join(dir, cacheName(url))

	if info, err := os.Stat(path); err == nil {
		if age := time.Since(info.ModTime()); age < CacheTTL {
			fmt.Fprintf(os.Stderr, "asname: using cached %s (%s old, %d bytes)\n",
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

	resp, err := httpGetFrom(url, userAgent, have)
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
		fmt.Fprintf(os.Stderr, "asname: resuming %s at %d bytes\n", redactURL(url), have)
	case http.StatusRequestedRangeNotSatisfiable:
		// The partial file already holds the whole object.
		if err := os.Rename(part, path); err != nil {
			return "", err
		}
		fmt.Fprintf(os.Stderr, "asname: using cached %s (%d bytes)\n", redactURL(url), have)
		return path, nil
	case http.StatusOK:
		if have > 0 {
			fmt.Fprintf(os.Stderr, "asname: %s does not support resuming, downloading in full\n", redactURL(url))
		} else {
			fmt.Fprintf(os.Stderr, "asname: downloading %s\n", redactURL(url))
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
		return "", fmt.Errorf("downloading %s: %v (%d bytes kept for the next attempt)", redactURL(url), copyErr, have+n)
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

// openCached is fetchCached followed by opening the result for reading.
func openCached(dir, url, userAgent string) (*os.File, error) {
	path, err := fetchCached(dir, url, userAgent)
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
func httpGetFrom(url, userAgent string, offset int64) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	return http.DefaultClient.Do(req)
}
