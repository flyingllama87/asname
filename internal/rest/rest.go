package rest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/flyingllama87/asname/internal/engine"
	"github.com/flyingllama87/asname/internal/format"
	"github.com/flyingllama87/asname/internal/sources"
)

type Server struct {
	engMu      sync.RWMutex
	eng        *engine.Engine
	listenAddr string
	cors       bool
	reverseDNS bool
	version    string
	opts       Options
	job        updateJob
	httpServer *http.Server
}

func NewServer(eng *engine.Engine, listenAddr string, cors, reverseDNS bool, version string) *Server {
	return NewServerWithOptions(eng, Options{ListenAddr: listenAddr, CORS: cors, ReverseDNS: reverseDNS, Version: version})
}

// NewServerWithOptions is NewServer with the web UI, status and update
// endpoints configured by opts.
func NewServerWithOptions(eng *engine.Engine, opts Options) *Server {
	if opts.ListenAddr == "" {
		opts.ListenAddr = "127.0.0.1:8086"
	}
	return &Server{
		eng:        eng,
		listenAddr: opts.ListenAddr,
		cors:       opts.CORS,
		reverseDNS: opts.ReverseDNS,
		version:    opts.Version,
		opts:       opts,
		job:        updateJob{echo: os.Stdout},
	}
}

// engine returns the engine answering lookups. An update replaces it.
func (s *Server) engine() *engine.Engine {
	s.engMu.RLock()
	defer s.engMu.RUnlock()
	return s.eng
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/ready", s.handleHealth)
	mux.HandleFunc("/v1/lookup", s.handleLookupQueryOrPost)
	mux.HandleFunc("/v1/lookup/", s.handleLookupPath)
	mux.HandleFunc("/v1/search", s.handleSearch)
	mux.HandleFunc("/v1/explore", s.handleExplore)
	mux.HandleFunc("/v1/bulk", s.handleBulk)
	mux.HandleFunc("/v1/status", s.handleStatus)
	mux.HandleFunc("/v1/update", s.handleUpdate)
	mux.HandleFunc("/v1/settings", s.handleSettings)
	if s.opts.WebDir != "" {
		mux.Handle("/", webHandler(s.opts.WebDir))
	}

	handler := http.Handler(mux)
	if s.cors {
		handler = s.corsMiddleware(handler)
	}
	return s.loggingMiddleware(handler)
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs each request with its query string, so the log
// shows what was looked up and searched for; a bulk lookup adds its targets.
// The web UI's polling of /v1/status and /v1/update, and the UI's own
// files, are left out when they succeed, or they would drown the rest.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriterTracker{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)
		if rw.statusCode < 400 && r.Method == http.MethodGet && quietPath(r.URL.Path) {
			return
		}
		note := ""
		if rw.note != "" {
			note = " " + rw.note
		}
		fmt.Fprintf(os.Stdout, "[REST] %s %s %d %v (%s)%s\n",
			r.Method, r.URL.RequestURI(), rw.statusCode, time.Since(start), r.RemoteAddr, note)
	})
}

// quietPath reports whether a successful GET of path goes unlogged.
func quietPath(path string) bool {
	switch path {
	case "/v1/status", "/v1/update", "/health":
		return true
	}
	return !strings.HasPrefix(path, "/v1/")
}

// logNote adds detail to a request's log line, such as a bulk lookup's
// targets, which are in its body rather than its URL.
func logNote(w http.ResponseWriter, note string) {
	if rw, ok := w.(*responseWriterTracker); ok {
		rw.note = note
	}
}

// targetsNote lists the first targets of a bulk lookup for the log.
func targetsNote(targets []string) string {
	const shown = 20
	if len(targets) <= shown {
		return "targets=" + strings.Join(targets, ",")
	}
	return fmt.Sprintf("targets=%s (+%d more)", strings.Join(targets[:shown], ","), len(targets)-shown)
}

type responseWriterTracker struct {
	http.ResponseWriter
	statusCode int
	note       string
}

func (w *responseWriterTracker) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (s *Server) Start(ctx context.Context) error {
	s.httpServer = &http.Server{
		Addr:         s.listenAddr,
		Handler:      s.Routes(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 20 * time.Second,
	}

	shutdownCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	serverErr := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stdout, "asname REST API listening on http://%s\n", s.listenAddr)
		fmt.Fprintf(os.Stdout, "Databases: ASN (yes), Names (yes), Country (%v), City (%v), Netblock (%v), Category (%v), Reputation (%v)\n",
			s.eng.HasCountryDB(), s.eng.HasCityDB(), s.eng.HasNetblockDB(), s.eng.HasCategoryDB(), s.eng.HasReputationDB())
		fmt.Fprintf(os.Stdout, "Ready to handle requests. Press Ctrl+C to shut down.\n")
		if s.opts.WebDir != "" {
			fmt.Fprintf(os.Stdout, "Web UI: http://%s/\n", s.listenAddr)
		}
		if s.opts.Update != nil {
			fmt.Fprintf(os.Stdout, "Database updates through the API: enabled\n")
		}
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	if s.opts.Update != nil && s.opts.RefreshEvery > 0 {
		go s.autoRefresh(shutdownCtx)
	}

	select {
	case <-shutdownCtx.Done():
		s.job.cancelRunning()
		fmt.Fprintf(os.Stdout, "\nShutting down REST server gracefully...\n")
		timeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(timeoutCtx)
	case err := <-serverErr:
		return err
	}
}

type healthResponse struct {
	Status    string          `json:"status"`
	Version   string          `json:"version"`
	Databases map[string]bool `json:"databases"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	eng := s.engine()
	resp := healthResponse{
		Status:  "healthy",
		Version: s.version,
		Databases: map[string]bool{
			"asn":        true,
			"names":      true,
			"country":    eng.HasCountryDB(),
			"city":       eng.HasCityDB(),
			"netblock":   eng.HasNetblockDB(),
			"category":   eng.HasCategoryDB(),
			"reputation": eng.HasReputationDB(),
			"geofeed":    eng.HasGeofeedDB(),
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleLookupQueryOrPost(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		query := r.URL.Query().Get("q")
		if query == "" {
			query = r.URL.Query().Get("target")
		}
		if query == "" {
			writeJSONError(w, http.StatusBadRequest, "missing query parameter 'q' or 'target'")
			return
		}
		wantRDNS := s.wantsReverseDNS(r)
		s.lookupSingle(w, r, query, wantRDNS)
	case http.MethodPost:
		s.handleBulk(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleLookupPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/v1/lookup/")
	if path == "" {
		writeJSONError(w, http.StatusBadRequest, "empty target in path")
		return
	}

	var targetStr string
	if strings.HasPrefix(path, "b64/") {
		rawB64 := strings.TrimPrefix(path, "b64/")
		decoded, err := decodeBase64Target(rawB64)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid base64 target: %v", err))
			return
		}
		targetStr = decoded
	} else {
		targetStr = path
	}

	wantRDNS := s.wantsReverseDNS(r)
	s.lookupSingle(w, r, targetStr, wantRDNS)
}

type lookupResponse struct {
	Query   string                    `json:"query"`
	Count   int                       `json:"count"`
	Results []format.JSONLookupResult `json:"results"`
}

type bulkResponse struct {
	Count   int                       `json:"count"`
	Results []format.JSONLookupResult `json:"results"`
	Errors  []jsonErrorDetail         `json:"errors,omitempty"`
}

type jsonErrorDetail struct {
	Target string `json:"target"`
	Error  string `json:"error"`
}

type bulkRequestBody struct {
	Targets    []string `json:"targets"`
	Target     string   `json:"target,omitempty"`
	ReverseDNS *bool    `json:"reverse_dns,omitempty"`
	// Whois and OnlinePrefixes ask for, or turn off, the online lookups;
	// Online sets both. Absent leaves the server's default.
	Whois          *bool `json:"whois,omitempty"`
	OnlinePrefixes *bool `json:"online_prefixes,omitempty"`
	Online         *bool `json:"online,omitempty"`
	// V4Only and V6Only keep one address family of each hostname's
	// addresses; addresses given as such are always looked up.
	V4Only bool `json:"v4_only,omitempty"`
	V6Only bool `json:"v6_only,omitempty"`
}

// hostFamily keeps only the addresses of one family that a hostname
// resolved to, as v4_only or v6_only ask; an address given as such is left
// alone.
func hostFamily(t engine.Target, v4Only, v6Only bool) engine.Target {
	if t.Host == "" {
		return t
	}
	return t.OnlyFamily(v4Only, v6Only)
}

func boolParam(b *bool) string {
	if b == nil {
		return ""
	}
	return strconv.FormatBool(*b)
}

func (s *Server) lookupSingle(w http.ResponseWriter, r *http.Request, rawTarget string, wantRDNS bool) {
	ctx := r.Context()
	q := r.URL.Query()
	withText := wantsText(r)
	online, err := s.online(q.Get("whois"), q.Get("online_prefixes"), q.Get("online"))
	if err != nil {
		writeJSONError(w, http.StatusForbidden, err.Error())
		return
	}
	t := engine.NewTarget(rawTarget)
	if t.Err != nil {
		writeJSONError(w, http.StatusBadRequest, t.Err.Error())
		return
	}

	if t.Host != "" && len(t.IPs) == 0 {
		var err error
		t.IPs, err = engine.LookupHostIPsWithRetry(ctx, t.Host)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("dns resolution failed: %v", err))
			return
		}
		t.Served = engine.DetectCDN(ctx, t.Host)
	}
	t = hostFamily(t, q.Get("v4_only") == "true", q.Get("v6_only") == "true")
	if t.Err != nil {
		writeJSONError(w, http.StatusBadRequest, t.Err.Error())
		return
	}

	results, err := s.engine().WithOnline(online).LookupTargetContext(ctx, t)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if wantRDNS {
		engine.ResolveReverseDNS(ctx, results)
	}

	jsonResults := make([]format.JSONLookupResult, 0, len(results))
	for _, res := range results {
		j := format.ToJSONResult(res)
		if withText {
			j.Text = format.FormatPrettyLookupOutput(res, 0, 1, false, true)
		}
		jsonResults = append(jsonResults, j)
	}

	resp := lookupResponse{
		Query:   rawTarget,
		Count:   len(jsonResults),
		Results: jsonResults,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	contentType := r.Header.Get("Content-Type")
	var targetStrings []string
	wantRDNS := s.wantsReverseDNS(r)
	withText := wantsText(r)
	q := r.URL.Query()
	whoisParam, prefixesParam, onlineParam := q.Get("whois"), q.Get("online_prefixes"), q.Get("online")
	v4Only, v6Only := q.Get("v4_only") == "true", q.Get("v6_only") == "true"

	bodyReader := http.MaxBytesReader(w, r.Body, 10*1024*1024)
	bodyBytes, err := io.ReadAll(bodyReader)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	if strings.Contains(contentType, "application/json") {
		var req bulkRequestBody
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON payload: %v", err))
			return
		}
		if req.Target != "" {
			targetStrings = append(targetStrings, req.Target)
		}
		targetStrings = append(targetStrings, req.Targets...)
		if req.ReverseDNS != nil {
			wantRDNS = *req.ReverseDNS
		}
		whoisParam = firstNonEmpty(boolParam(req.Whois), whoisParam)
		prefixesParam = firstNonEmpty(boolParam(req.OnlinePrefixes), prefixesParam)
		onlineParam = firstNonEmpty(boolParam(req.Online), onlineParam)
		v4Only, v6Only = v4Only || req.V4Only, v6Only || req.V6Only
	} else {
		// Every target in the text, repeats kept, so results line up with
		// what was sent.
		for _, l := range strings.Split(string(bodyBytes), "\n") {
			targetStrings = append(targetStrings, engine.EntriesFromLine(l)...)
		}
	}

	if len(targetStrings) == 0 {
		writeJSONError(w, http.StatusBadRequest, "no targets provided in request body")
		return
	}
	logNote(w, targetsNote(targetStrings))

	targets := make([]engine.Target, 0, len(targetStrings))
	for _, raw := range targetStrings {
		targets = append(targets, engine.NewTarget(raw))
	}

	engine.ResolveTargets(r.Context(), targets)

	online, err := s.online(whoisParam, prefixesParam, onlineParam)
	if err != nil {
		writeJSONError(w, http.StatusForbidden, err.Error())
		return
	}

	var allResults []engine.LookupResult
	var errorDetails []jsonErrorDetail
	// One view for the whole batch, so its whois queries share one
	// allowance (MaxWhoisQueries).
	eng := s.engine().WithOnline(online)

	for _, t := range targets {
		t = hostFamily(t, v4Only, v6Only)
		if t.Err != nil {
			errorDetails = append(errorDetails, jsonErrorDetail{Target: t.Raw, Error: t.Err.Error()})
			continue
		}
		found, err := eng.LookupTargetContext(r.Context(), t)
		if err != nil {
			errorDetails = append(errorDetails, jsonErrorDetail{Target: t.Raw, Error: err.Error()})
			continue
		}
		allResults = append(allResults, found...)
	}

	if wantRDNS && len(allResults) > 0 {
		engine.ResolveReverseDNS(r.Context(), allResults)
	}

	jsonResults := make([]format.JSONLookupResult, 0, len(allResults))
	for _, res := range allResults {
		j := format.ToJSONResult(res)
		if withText {
			j.Text = format.FormatPrettyLookupOutput(res, 0, 1, false, true)
		}
		jsonResults = append(jsonResults, j)
	}

	resp := bulkResponse{
		Count:   len(jsonResults),
		Results: jsonResults,
		Errors:  errorDetails,
	}
	writeJSON(w, http.StatusOK, resp)
}

// wantsText reports whether a lookup asked, with text=true, for each result
// as the command line prints it too.
func wantsText(r *http.Request) bool {
	v := r.URL.Query().Get("text")
	return v == "1" || strings.EqualFold(v, "true")
}

func (s *Server) wantsReverseDNS(r *http.Request) bool {
	rdnsParam := r.URL.Query().Get("reverse_dns")
	if rdnsParam == "" {
		rdnsParam = r.URL.Query().Get("rdns")
	}
	if rdnsParam != "" {
		return rdnsParam == "1" || strings.EqualFold(rdnsParam, "true")
	}
	return s.reverseDNS
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeJSONError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, map[string]string{
		"error": message,
	})
}

func decodeBase64Target(s string) (string, error) {
	s = strings.TrimSpace(s)
	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	for _, enc := range encodings {
		data, err := enc.DecodeString(s)
		if err == nil && len(data) > 0 {
			return string(data), nil
		}
	}
	return "", fmt.Errorf("unable to decode base64 string")
}

// searchResponse keeps the netblocks in results, and their number in count,
// as before AS names were searched; the AS name matches come in asns.
type searchResponse struct {
	Query    string                            `json:"query"`
	Country  string                            `json:"country,omitempty"`
	Count    int                               `json:"count"`
	Results  []format.JSONNetblockSearchResult `json:"results"`
	ASNCount int                               `json:"asn_count"`
	ASNs     []format.JSONASNSearchResult      `json:"asns"`
}

// searchCountry reads a search's country parameter: a two-letter code or
// an English name; empty, "all", "any" or "worldwide" is every country.
func searchCountry(v string) (string, error) {
	v = strings.TrimSpace(v)
	switch strings.ToLower(v) {
	case "", "all", "any", "worldwide":
		return "", nil
	}
	return sources.ParseCountry(v)
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed, use GET")
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		query = r.URL.Query().Get("org")
	}
	if strings.TrimSpace(query) == "" {
		writeJSONError(w, http.StatusBadRequest, "missing search query parameter (e.g. ?q=google or ?org=google)")
		return
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsedLimit, err := strconv.Atoi(l); err == nil && parsedLimit >= 0 {
			limit = parsedLimit
		}
	}

	v4Only := r.URL.Query().Get("v4_only") == "true"
	v6Only := r.URL.Query().Get("v6_only") == "true"

	scope := r.URL.Query().Get("scope")
	if scope != "" && scope != "all" && scope != "asns" && scope != "netblocks" {
		writeJSONError(w, http.StatusBadRequest, "scope must be all, asns or netblocks")
		return
	}

	fuzzyParam := r.URL.Query().Get("fuzzy")
	fuzzy := fuzzyParam == "1" || strings.EqualFold(fuzzyParam, "true")

	country, err := searchCountry(r.URL.Query().Get("country"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	eng := s.engine()
	asnResults := make([]format.JSONASNSearchResult, 0)
	if scope != "netblocks" {
		for _, res := range eng.SearchASNsWith(query, engine.ASNSearchOptions{Limit: limit, V4Only: v4Only, V6Only: v6Only, Fuzzy: fuzzy, Country: country}) {
			asnResults = append(asnResults, format.NewJSONASNSearchResult(res, ""))
		}
	}

	// A combined search answers from the AS names alone when the server has
	// no netblock database; asking for netblocks only still reports it.
	jsonResults := make([]format.JSONNetblockSearchResult, 0)
	if scope == "netblocks" || (scope != "asns" && eng.HasNetblockDB()) {
		results, err := eng.SearchNetblocks(query, sources.NetblockSearchOptions{
			Limit:   limit,
			V4Only:  v4Only,
			V6Only:  v6Only,
			Fuzzy:   fuzzy,
			Country: country,
		})
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, res := range results {
			jsonResults = append(jsonResults, format.NewJSONNetblockSearchResult(res, ""))
		}
	}

	writeJSON(w, http.StatusOK, searchResponse{
		Query:    query,
		Country:  country,
		Count:    len(jsonResults),
		Results:  jsonResults,
		ASNCount: len(asnResults),
		ASNs:     asnResults,
	})
}
