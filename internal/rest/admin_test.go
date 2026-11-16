package rest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/flyingllama87/asname/internal/engine"
)

func postUpdate(t *testing.T, h http.Handler, body string, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8086/v1/update", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func waitForUpdate(t *testing.T, s *Server) jobState {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st := s.job.snapshot(); !st.Running {
			return st
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("update did not finish")
	return jobState{}
}

func TestUpdateDisabledByDefault(t *testing.T) {
	s := NewServer(engine.NewTestEngine(t), "", false, false, "test")
	w := postUpdate(t, s.Routes(), `{}`, nil)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "--allow-updates")
}

func TestUpdateRunsAndReloads(t *testing.T) {
	first := engine.NewTestEngine(t)
	second := engine.NewTestEngine(t)
	var got UpdateRequest
	s := NewServerWithOptions(first, Options{
		Update: func(ctx context.Context, req UpdateRequest, log io.Writer) error {
			got = req
			fmt.Fprintf(log, "asname: refreshing reputation database...\npartial line")
			return nil
		},
		Reload: func() (*engine.Engine, error) { return second, nil },
	})
	h := s.Routes()

	w := postUpdate(t, h, `{"databases":["reputation"]}`, map[string]string{"Origin": "http://127.0.0.1:8086"})
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	st := waitForUpdate(t, s)

	assert.Equal(t, []string{"reputation"}, got.Databases)
	assert.True(t, st.Reloaded)
	assert.Empty(t, st.Error)
	assert.Equal(t, "api", st.Trigger)
	assert.Equal(t, []string{"asname: refreshing reputation database...", "partial line"}, st.Log)
	assert.Same(t, second, s.engine(), "lookups use the reopened databases")

	// GET /v1/status reports the finished update.
	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var status statusResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &status))
	assert.True(t, status.UpdatesEnabled)
	assert.True(t, status.Loaded["asn"])
	assert.False(t, status.Update.Running)
}

func TestUpdateFailureIsReported(t *testing.T) {
	s := NewServerWithOptions(engine.NewTestEngine(t), Options{
		Update: func(ctx context.Context, req UpdateRequest, log io.Writer) error {
			return errors.New("download failed")
		},
	})
	require.Equal(t, http.StatusAccepted, postUpdate(t, s.Routes(), ``, nil).Code)
	st := waitForUpdate(t, s)
	assert.Equal(t, "download failed", st.Error)
	assert.False(t, st.Reloaded)
}

func TestUpdateRejectsUnknownDatabase(t *testing.T) {
	s := NewServerWithOptions(engine.NewTestEngine(t), Options{
		Update: func(context.Context, UpdateRequest, io.Writer) error { return nil },
	})
	w := postUpdate(t, s.Routes(), `{"databases":["bogus"]}`, nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateConflictWhileRunning(t *testing.T) {
	release := make(chan struct{})
	s := NewServerWithOptions(engine.NewTestEngine(t), Options{
		Update: func(ctx context.Context, req UpdateRequest, log io.Writer) error {
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		},
	})
	h := s.Routes()
	require.Equal(t, http.StatusAccepted, postUpdate(t, h, `{}`, nil).Code)
	assert.Equal(t, http.StatusConflict, postUpdate(t, h, `{}`, nil).Code)

	// DELETE cancels it.
	req := httptest.NewRequest(http.MethodDelete, "http://127.0.0.1:8086/v1/update", nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusAccepted, w.Code)
	st := waitForUpdate(t, s)
	assert.Contains(t, st.Error, "context canceled")
	close(release)
}

func TestUpdateRefusesCrossSiteRequests(t *testing.T) {
	s := NewServerWithOptions(engine.NewTestEngine(t), Options{
		CORS:   true,
		Update: func(context.Context, UpdateRequest, io.Writer) error { return nil },
	})
	h := s.Routes()

	cases := map[string]func(*http.Request){
		"form post":        func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") },
		"other origin":     func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		"cross-site fetch": func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		"rebound domain": func(r *http.Request) {
			r.Host = "evil.example:8086"
			r.Header.Set("Origin", "http://evil.example:8086")
		},
		"rebound no origin": func(r *http.Request) { r.Host = "attacker.test" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8086/v1/update", strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			mutate(req)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
		})
	}
	assert.False(t, s.job.snapshot().Running, "nothing was started")
}

func TestLocalHostName(t *testing.T) {
	name, err := os.Hostname()
	require.NoError(t, err)
	for _, h := range []string{"127.0.0.1:8086", "[::1]:8086", "localhost:8086", "LOCALHOST", "192.168.1.5", name, name + ":8086"} {
		assert.True(t, localHostName(h), h)
	}
	short, _, _ := strings.Cut(name, ".")
	assert.True(t, localHostName(short+".lan:8086"), "the short name on the LAN")
	for _, h := range []string{"", "evil.example", "evil.example:8086", "localhost.evil.example", short + ".evil.example", short + ".evil.example:8086"} {
		assert.False(t, localHostName(h), h)
	}
}

func TestWebUIServedWithoutListing(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte("<title>asname</title>"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "assets"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte("1"), 0o644))

	h := NewServerWithOptions(engine.NewTestEngine(t), Options{WebDir: dir}).Routes()
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w
	}

	w := get("/")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "asname")
	assert.Contains(t, w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'")
	assert.Equal(t, http.StatusOK, get("/assets/app.js").Code)
	assert.Equal(t, http.StatusNotFound, get("/assets/").Code, "no directory listing")
	assert.Equal(t, http.StatusOK, get("/health").Code, "the API still answers")
}

func putSettings(t *testing.T, h http.Handler, body string, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "http://127.0.0.1:8086/v1/settings", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestSettings(t *testing.T) {
	noop := func(context.Context, UpdateRequest, io.Writer) error { return nil }

	t.Run("disabled without --allow-updates", func(t *testing.T) {
		s := NewServerWithOptions(engine.NewTestEngine(t), Options{SaveSettings: func(SettingsRequest) error { return nil }})
		assert.Equal(t, http.StatusForbidden, putSettings(t, s.Routes(), `{"ipv6_routes":true}`, nil).Code)
	})

	t.Run("saves and reports the status", func(t *testing.T) {
		var got SettingsRequest
		s := NewServerWithOptions(engine.NewTestEngine(t), Options{
			Update:       noop,
			SaveSettings: func(r SettingsRequest) error { got = r; return nil },
		})
		w := putSettings(t, s.Routes(), `{"max_age_hours":168,"ipv6_routes":true}`, map[string]string{"Origin": "http://127.0.0.1:8086"})
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.NotNil(t, got.MaxAgeHours)
		assert.Equal(t, 168.0, *got.MaxAgeHours)
		require.NotNil(t, got.IPv6Routes)
		assert.True(t, *got.IPv6Routes)
		var st statusResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &st))
		assert.True(t, st.SettingsEditable)
	})

	t.Run("a fixed setting is a conflict", func(t *testing.T) {
		s := NewServerWithOptions(engine.NewTestEngine(t), Options{
			Update:       noop,
			SaveSettings: func(SettingsRequest) error { return ErrSettingFixed("set by --max-age") },
		})
		w := putSettings(t, s.Routes(), `{"max_age_hours":1}`, nil)
		assert.Equal(t, http.StatusConflict, w.Code)
		assert.Contains(t, w.Body.String(), "--max-age")
	})

	t.Run("cross-site requests are refused", func(t *testing.T) {
		called := false
		s := NewServerWithOptions(engine.NewTestEngine(t), Options{
			Update:       noop,
			SaveSettings: func(SettingsRequest) error { called = true; return nil },
		})
		w := putSettings(t, s.Routes(), `{"ipv6_routes":true}`, map[string]string{"Origin": "https://evil.example"})
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.False(t, called)
	})
}

func TestOnlineLookupsPerRequest(t *testing.T) {
	get := func(s *Server, url string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.Routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, url, nil))
		return w
	}

	off := NewServerWithOptions(engine.NewTestEngine(t), Options{})
	w := get(off, "/v1/lookup?q=8.8.8.8&whois=true")
	assert.Equal(t, http.StatusForbidden, w.Code, "whois turned off on the server")
	assert.Contains(t, w.Body.String(), "whois")
	assert.Equal(t, http.StatusOK, get(off, "/v1/lookup?q=8.8.8.8&whois=false").Code, "asking for it off is fine")

	on := NewServerWithOptions(engine.NewTestEngine(t), Options{Online: OnlineOptions{WhoisAvailable: true, PrefixesAvailable: true}})
	got, err := on.online("", "", "true")
	require.NoError(t, err)
	assert.Equal(t, engine.Online{Whois: true, Prefixes: true}, got, "online=true asks for both")
	got, err = on.online("false", "", "true")
	require.NoError(t, err)
	assert.Equal(t, engine.Online{Whois: false, Prefixes: true}, got, "a specific answer beats online")
	got, err = on.online("", "", "")
	require.NoError(t, err)
	assert.Equal(t, engine.Online{}, got, "off by default")

	var st statusResponse
	require.NoError(t, json.Unmarshal(get(on, "/v1/status").Body.Bytes(), &st))
	assert.True(t, st.Online.WhoisAvailable)
	assert.False(t, st.Online.WhoisDefault)
}

func TestUpdateProgressIsEchoed(t *testing.T) {
	var echoed strings.Builder
	s := NewServerWithOptions(engine.NewTestEngine(t), Options{
		Update: func(ctx context.Context, req UpdateRequest, log io.Writer) error {
			fmt.Fprintf(log, "asname: downloading reputation lists\nlast line")
			return nil
		},
	})
	s.job.echo = &echoed
	require.Equal(t, http.StatusAccepted, postUpdate(t, s.Routes(), `{"databases":["reputation"]}`, nil).Code)
	waitForUpdate(t, s)
	got := echoed.String()
	assert.Contains(t, got, "[REST] api update started: reputation")
	assert.Contains(t, got, "[update] asname: downloading reputation lists\n")
	assert.Contains(t, got, "[update] last line\n", "the unterminated last line too")
}

func TestRequestLogDetail(t *testing.T) {
	assert.True(t, quietPath("/v1/status"))
	assert.True(t, quietPath("/assets/index.js"), "the web UI's files")
	assert.False(t, quietPath("/v1/lookup"))
	assert.False(t, quietPath("/v1/search"))

	assert.Equal(t, "targets=8.8.8.8,AS13335", targetsNote([]string{"8.8.8.8", "AS13335"}))
	many := make([]string, 25)
	for i := range many {
		many[i] = fmt.Sprintf("10.0.0.%d", i)
	}
	assert.True(t, strings.HasSuffix(targetsNote(many), "10.0.0.19 (+5 more)"))
}
