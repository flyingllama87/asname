package rest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/flyingllama87/asname/internal/engine"
	"github.com/flyingllama87/asname/internal/sources"
)

// Options configures a Server beyond the lookup and search endpoints.
type Options struct {
	ListenAddr string
	CORS       bool
	ReverseDNS bool
	Version    string

	// WebDir, when set, is served at / so the web UI shares the API's origin.
	WebDir string

	// Status returns the on-disk database status for GET /v1/status, as
	// `asname version -j` reports it. Nil leaves it out.
	Status func() any

	// Update rebuilds databases for POST /v1/update, writing progress to log.
	// Nil disables updates through the API.
	Update func(ctx context.Context, req UpdateRequest, log io.Writer) error

	// Reload opens the databases afresh after an update, so lookups use
	// the new files. Nil keeps the engine the server started with.
	Reload func() (*engine.Engine, error)

	// RefreshEvery, when Update is set, checks this often for databases
	// older than --max-age and refreshes them, as a lookup on the command
	// line would. Zero turns it off.
	RefreshEvery time.Duration
}

// UpdateRequest is the body of POST /v1/update.
type UpdateRequest struct {
	// Databases lists the databases to rebuild by key (asn, names, country,
	// city, netblock, category, reputation), building any that are absent.
	// Empty means the core databases plus every optional one present, as a
	// plain `asname update` does.
	Databases []string `json:"databases,omitempty"`
	// Incremental rebuilds only what the last update left incomplete.
	Incremental bool `json:"incremental,omitempty"`
	// StaleOnly refreshes only databases older than --max-age.
	StaleOnly bool `json:"stale_only,omitempty"`
}

// jobState is the last or running update, as GET /v1/update reports it.
type jobState struct {
	Running  bool           `json:"running"`
	Trigger  string         `json:"trigger,omitempty"`
	Request  *UpdateRequest `json:"request,omitempty"`
	Started  *time.Time     `json:"started,omitempty"`
	Finished *time.Time     `json:"finished,omitempty"`
	Error    string         `json:"error,omitempty"`
	Reloaded bool           `json:"reloaded,omitempty"`
	Log      []string       `json:"log"`
}

// maxJobLogLines bounds the progress kept for one update.
const maxJobLogLines = 2000

type updateJob struct {
	mu      sync.Mutex
	state   jobState
	partial string
	cancel  context.CancelFunc
}

// Write collects progress messages line by line, so the UI can show them.
func (j *updateJob) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	text := j.partial + string(p)
	lines := strings.Split(text, "\n")
	j.partial = lines[len(lines)-1]
	for _, line := range lines[:len(lines)-1] {
		if line = strings.TrimRight(line, "\r"); line != "" {
			j.state.Log = append(j.state.Log, line)
		}
	}
	if over := len(j.state.Log) - maxJobLogLines; over > 0 {
		j.state.Log = append([]string(nil), j.state.Log[over:]...)
	}
	return len(p), nil
}

func (j *updateJob) snapshot() jobState {
	j.mu.Lock()
	defer j.mu.Unlock()
	st := j.state
	st.Log = append([]string{}, j.state.Log...)
	if j.partial != "" {
		st.Log = append(st.Log, j.partial)
	}
	return st
}

func (j *updateJob) cancelRunning() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.cancel != nil {
		j.cancel()
	}
}

// startUpdate runs req in the background unless an update is already
// running, and reports whether it started.
func (s *Server) startUpdate(trigger string, req UpdateRequest) bool {
	j := &s.job
	j.mu.Lock()
	if j.state.Running {
		j.mu.Unlock()
		return false
	}
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Now()
	j.state = jobState{Running: true, Trigger: trigger, Request: &req, Started: &now, Log: []string{}}
	j.partial = ""
	j.cancel = cancel
	j.mu.Unlock()

	go func() {
		defer cancel()
		err := s.opts.Update(ctx, req, j)
		// Rebuilt files replace the old ones atomically, so even a failed
		// or cancelled update may have refreshed some; reopen them all.
		reloaded := false
		if s.opts.Reload != nil {
			if eng, rerr := s.opts.Reload(); rerr != nil {
				fmt.Fprintf(j, "asname: reopening the databases failed, still serving the previous ones: %v\n", rerr)
			} else {
				s.swapEngine(eng)
				reloaded = true
			}
		}
		fmt.Fprintf(os.Stdout, "[REST] %s update finished (err=%v, reloaded=%v)\n", trigger, err, reloaded)

		j.mu.Lock()
		defer j.mu.Unlock()
		done := time.Now()
		j.state.Running, j.state.Finished, j.state.Reloaded = false, &done, reloaded
		if err != nil {
			j.state.Error = err.Error()
		}
		if j.partial != "" {
			j.state.Log = append(j.state.Log, j.partial)
			j.partial = ""
		}
		j.cancel = nil
	}()
	return true
}

// engineCloseDelay lets requests still using a replaced engine finish
// before its files are closed; it outlasts the server's write timeout.
const engineCloseDelay = time.Minute

func (s *Server) swapEngine(eng *engine.Engine) {
	s.engMu.Lock()
	old := s.eng
	s.eng = eng
	s.engMu.Unlock()
	if old != nil && old != eng {
		time.AfterFunc(engineCloseDelay, old.Close)
	}
}

// Close closes the engine currently answering lookups.
func (s *Server) Close() {
	s.engMu.Lock()
	defer s.engMu.Unlock()
	if s.eng != nil {
		s.eng.Close()
		s.eng = nil
	}
}

// autoRefresh refreshes stale databases every RefreshEvery until ctx ends,
// so a long-running server does not keep serving month-old data.
func (s *Server) autoRefresh(ctx context.Context) {
	t := time.NewTicker(s.opts.RefreshEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.startUpdate("auto", UpdateRequest{StaleOnly: true})
		}
	}
}

type statusResponse struct {
	Version        string          `json:"version"`
	UpdatesEnabled bool            `json:"updates_enabled"`
	Loaded         map[string]bool `json:"loaded"`
	Store          any             `json:"store,omitempty"`
	Update         jobState        `json:"update"`
}

// handleStatus answers GET /v1/status: the databases on disk, which ones
// the server has loaded, and the last or running update.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed, use GET")
		return
	}
	eng := s.engine()
	resp := statusResponse{
		Version:        s.version,
		UpdatesEnabled: s.opts.Update != nil,
		Loaded: map[string]bool{
			"asn":        eng != nil,
			"names":      eng != nil,
			"country":    eng != nil && eng.HasCountryDB(),
			"prefixes":   eng != nil && eng.HasPrefixDB(),
			"city":       eng != nil && eng.HasCityDB(),
			"netblock":   eng != nil && eng.HasNetblockDB(),
			"category":   eng != nil && eng.HasCategoryDB(),
			"reputation": eng != nil && eng.HasReputationDB(),
		},
		Update: s.job.snapshot(),
	}
	if s.opts.Status != nil {
		resp.Store = s.opts.Status()
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleUpdate answers GET (the last or running update), POST (start one)
// and DELETE (cancel the running one) on /v1/update.
func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.job.snapshot())
		return
	case http.MethodPost, http.MethodDelete:
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed, use GET, POST or DELETE")
		return
	}
	if s.opts.Update == nil {
		writeJSONError(w, http.StatusForbidden, "database updates through the API are disabled; start the server with --allow-updates")
		return
	}
	if err := checkLocalWrite(r); err != nil {
		writeJSONError(w, http.StatusForbidden, err.Error())
		return
	}

	if r.Method == http.MethodDelete {
		s.job.cancelRunning()
		writeJSON(w, http.StatusAccepted, s.job.snapshot())
		return
	}

	var req UpdateRequest
	body := http.MaxBytesReader(w, r.Body, 64*1024)
	if err := json.NewDecoder(body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON payload: %v", err))
		return
	}
	valid := map[string]bool{}
	for _, key := range sources.UpdateKeys {
		valid[key] = true
	}
	for _, db := range req.Databases {
		if !valid[db] {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("unknown database %q; use %s", db, strings.Join(sources.UpdateKeys, ", ")))
			return
		}
	}
	if !s.startUpdate("api", req) {
		writeJSONError(w, http.StatusConflict, "an update is already running")
		return
	}
	writeJSON(w, http.StatusAccepted, s.job.snapshot())
}

// checkLocalWrite refuses a request that changes the server unless it came
// from a page on the server's own origin. A JSON body forces browsers to ask
// before sending it cross-origin; the Origin check stops a page on another
// site from sending it anyway (CSRF), and the Host check stops a site that
// re-points its own name at this address (DNS rebinding).
func checkLocalWrite(r *http.Request) error {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(ct), "application/json") {
		return errors.New("Content-Type must be application/json")
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return errors.New("cross-site requests may not change the server")
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			return errors.New("cross-origin requests may not change the server")
		}
	}
	if !localHostName(r.Host) {
		return fmt.Errorf("host %q may not change the server; use an IP address, localhost or this machine's name", r.Host)
	}
	return nil
}

// localHostName reports whether a Host header names this machine without
// going through a domain someone else controls: an IP address, localhost,
// or the machine's own hostname.
func localHostName(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	name, err := os.Hostname()
	if err != nil {
		return false
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	short, _, _ := strings.Cut(name, ".")
	if host == name || host == short {
		return true
	}
	// The short name under a suffix that only a local resolver answers.
	// Any other domain may belong to someone else, who could point it here.
	for _, suffix := range localSuffixes {
		if host == short+suffix {
			return true
		}
	}
	return false
}

// localSuffixes are the domains a home or office network names its own
// machines under; no public registry delegates them.
var localSuffixes = []string{".local", ".lan", ".home.arpa", ".internal", ".localdomain"}

// webHandler serves the web UI from dir with headers that keep it from
// being framed or loading code from elsewhere. Directories without an
// index.html are not listed.
func webHandler(dir string) http.Handler {
	files := http.FileServer(noListFS{http.Dir(dir)})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' http: https:; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		files.ServeHTTP(w, r)
	})
}

type noListFS struct{ fs http.FileSystem }

func (n noListFS) Open(name string) (http.File, error) {
	f, err := n.fs.Open(name)
	if err != nil {
		return nil, err
	}
	if st, err := f.Stat(); err == nil && st.IsDir() {
		index, err := n.fs.Open(strings.TrimSuffix(name, "/") + "/index.html")
		if err != nil {
			f.Close()
			return nil, os.ErrNotExist
		}
		index.Close()
	}
	return f, nil
}
