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

	// NeedsRefresh reports whether any database is due for a refresh, so
	// the periodic check starts an update only when one is. Nil means
	// always try.
	NeedsRefresh func() bool

	// SaveSettings changes the settings kept in the data directory, for
	// PUT /v1/settings. Nil disables it; it also needs Update.
	SaveSettings func(SettingsRequest) error

	// Online says whether lookups may query whois and RIPEstat.
	Online OnlineOptions
}

// OnlineOptions says which online lookups a request may ask for (with
// whois=true or online_prefixes=true), and which it gets by default.
type OnlineOptions struct {
	WhoisAvailable    bool `json:"whois_available"`
	WhoisDefault      bool `json:"whois_default"`
	PrefixesAvailable bool `json:"prefixes_available"`
	PrefixesDefault   bool `json:"prefixes_default"`
}

// SettingsRequest is the body of PUT /v1/settings; absent fields are left
// as they are.
type SettingsRequest struct {
	// MaxAgeHours is the age at which databases are refreshed; 0 is never.
	MaxAgeHours *float64 `json:"max_age_hours,omitempty"`
	// IPv6Routes says whether ASN updates import IPv6 routes.
	IPv6Routes *bool `json:"ipv6_routes,omitempty"`
}

// settingError is a SaveSettings failure that is the request's fault.
type settingError struct {
	code int
	msg  string
}

func (e settingError) Error() string { return e.msg }

// ErrSettingFixed reports a setting the server's command line fixes.
func ErrSettingFixed(msg string) error { return settingError{http.StatusConflict, msg} }

// ErrSettingInvalid reports a setting value out of range.
func ErrSettingInvalid(msg string) error { return settingError{http.StatusBadRequest, msg} }

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
	// echo, when set, also gets each line of progress, so the server's own
	// log (the journal, under systemd) keeps every update's.
	echo    io.Writer
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
			if j.echo != nil {
				fmt.Fprintf(j.echo, "[update] %s\n", line)
			}
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
	if j.echo != nil {
		fmt.Fprintf(j.echo, "[REST] %s update started: %s\n", trigger, describeUpdate(req))
	}

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
			if j.echo != nil {
				fmt.Fprintf(j.echo, "[update] %s\n", j.partial)
			}
			j.partial = ""
		}
		j.cancel = nil
	}()
	return true
}

// describeUpdate says what an update request rebuilds, for the log.
func describeUpdate(req UpdateRequest) string {
	switch {
	case len(req.Databases) > 0:
		return strings.Join(req.Databases, ", ")
	case req.StaleOnly:
		return "databases older than the refresh age"
	case req.Incremental:
		return "what the last update left out"
	}
	return "every database on disk"
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
			if s.opts.NeedsRefresh == nil || s.opts.NeedsRefresh() {
				s.startUpdate("auto", UpdateRequest{StaleOnly: true})
			}
		}
	}
}

type statusResponse struct {
	Version          string          `json:"version"`
	UpdatesEnabled   bool            `json:"updates_enabled"`
	Loaded           map[string]bool `json:"loaded"`
	Store            any             `json:"store,omitempty"`
	Update           jobState        `json:"update"`
	Online           OnlineOptions   `json:"online"`
	SettingsEditable bool            `json:"settings_editable"`
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
		Update:           s.job.snapshot(),
		Online:           s.opts.Online,
		SettingsEditable: s.opts.Update != nil && s.opts.SaveSettings != nil,
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

// handleSettings answers PUT /v1/settings, which changes the settings kept
// in the data directory, and replies with the new status.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed, use PUT")
		return
	}
	if s.opts.Update == nil || s.opts.SaveSettings == nil {
		writeJSONError(w, http.StatusForbidden, "settings cannot be changed through the API; start the server with --allow-updates")
		return
	}
	if err := checkLocalWrite(r); err != nil {
		writeJSONError(w, http.StatusForbidden, err.Error())
		return
	}
	var req SettingsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON payload: %v", err))
		return
	}
	if err := s.opts.SaveSettings(req); err != nil {
		var se settingError
		if errors.As(err, &se) {
			writeJSONError(w, se.code, se.msg)
		} else {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	s.handleStatus(w, &http.Request{Method: http.MethodGet})
}

// online decides which online lookups one request makes: whois=true and
// online_prefixes=true (or online=true for both) ask for them, false turns
// them off, and absent leaves the server's default. Asking for one the
// server has turned off is an error.
func (s *Server) online(whois, prefixes, both string) (engine.Online, error) {
	o := s.opts.Online
	out := engine.Online{Whois: o.WhoisDefault, Prefixes: o.PrefixesDefault}
	if both != "" {
		whois, prefixes = firstNonEmpty(whois, both), firstNonEmpty(prefixes, both)
	}
	for _, p := range []struct {
		name, val string
		avail     bool
		dst       *bool
	}{
		{"whois", whois, o.WhoisAvailable, &out.Whois},
		{"online_prefixes", prefixes, o.PrefixesAvailable, &out.Prefixes},
	} {
		if p.val == "" {
			continue
		}
		on := p.val == "1" || strings.EqualFold(p.val, "true")
		if on && !p.avail {
			return out, fmt.Errorf("%s lookups are turned off on this server", p.name)
		}
		*p.dst = on
	}
	return out, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
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
		// The page itself must be revalidated, so a reload after `make web`
		// gets the new build; its scripts and styles have hashed names.
		if !strings.HasPrefix(r.URL.Path, "/assets/") {
			h.Set("Cache-Control", "no-cache")
		}
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
