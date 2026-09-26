package sources

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

// Registries and cloud providers throttle their download hosts, and a refusal
// is usually brief: APNIC has answered a single request for its delegation
// statistics with 429 Too Many Requests, then served the same file moments
// later. One refusal must not cost a whole region of a database, so a GET that
// is refused or fails on the server side is retried with backoff.
var (
	// retryAttempts is the total number of tries, the first included. With
	// the base delay that waits 5s then 10s: enough to ride out a brief
	// throttle, short enough that a source which is really down is abandoned
	// for the next one promptly.
	retryAttempts = 3
	// retryBaseDelay is the wait before the first retry; each later retry
	// doubles it.
	retryBaseDelay = 5 * time.Second
	// retryMaxDelay caps any single wait, including one a server asks for
	// with Retry-After, so a hostile or mistaken header cannot stall an update.
	retryMaxDelay = 2 * time.Minute
)

// retryable reports whether a response status is worth asking again for:
// throttling, and server-side failures that are typically transient.
func retryable(status int) bool {
	switch status {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

// doWithRetry sends the request newReq builds, retrying a retryable status
// with backoff. It returns the first response that is not retryable, or the
// last response once the attempts run out, for the caller to judge; a
// transport error is returned at once, since fetchCached already resumes an
// interrupted download on the next run. Waiting honours ctx.
func doWithRetry(ctx context.Context, url string, newReq func() (*http.Request, error)) (*http.Response, error) {
	delay := retryBaseDelay
	for attempt := 1; ; attempt++ {
		req, err := newReq()
		if err != nil {
			return nil, err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil || !retryable(resp.StatusCode) || attempt == retryAttempts {
			return resp, err
		}

		wait := delay
		if ra, ok := retryAfter(resp.Header.Get("Retry-After")); ok {
			wait = ra
		}
		wait = min(wait, retryMaxDelay)
		resp.Body.Close()
		logf(ctx, "asname: %s: %s, retrying in %s (attempt %d of %d)\n",
			redactURL(url), resp.Status, wait, attempt+1, retryAttempts)

		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
		delay *= 2
	}
}

// retryAfter parses a Retry-After header, given either as seconds or as an
// HTTP date.
func retryAfter(v string) (time.Duration, bool) {
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second, true
	}
	if at, err := http.ParseTime(v); err == nil {
		return max(time.Until(at), 0), true
	}
	return 0, false
}

// orDefaultAgent returns userAgent, or defaultUserAgent when it is empty.
func orDefaultAgent(userAgent string) string {
	if userAgent != "" {
		return userAgent
	}
	return defaultUserAgent()
}

// defaultUserAgent names asname to the servers it downloads from when a source
// asks for no particular agent, instead of Go's generic default.
func defaultUserAgent() string {
	return "asname/" + Version + " (+https://github.com/flyingllama87/asname)"
}
