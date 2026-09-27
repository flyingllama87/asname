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
	"syscall"
	"time"

	"github.com/flyingllama87/asname/internal/engine"
	"github.com/flyingllama87/asname/internal/format"
	"github.com/flyingllama87/asname/internal/sources"
)

type Server struct {
	eng        *engine.Engine
	listenAddr string
	cors       bool
	reverseDNS bool
	version    string
	httpServer *http.Server
}

func NewServer(eng *engine.Engine, listenAddr string, cors, reverseDNS bool, version string) *Server {
	if listenAddr == "" {
		listenAddr = "127.0.0.1:8086"
	}
	return &Server{
		eng:        eng,
		listenAddr: listenAddr,
		cors:       cors,
		reverseDNS: reverseDNS,
		version:    version,
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/ready", s.handleHealth)
	mux.HandleFunc("/v1/lookup", s.handleLookupQueryOrPost)
	mux.HandleFunc("/v1/lookup/", s.handleLookupPath)
	mux.HandleFunc("/v1/search", s.handleSearch)
	mux.HandleFunc("/v1/bulk", s.handleBulk)

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

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriterTracker{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)
		duration := time.Since(start)
		fmt.Fprintf(os.Stdout, "[REST] %s %s %d %v (%s)\n",
			r.Method, r.URL.Path, rw.statusCode, duration, r.RemoteAddr)
	})
}

type responseWriterTracker struct {
	http.ResponseWriter
	statusCode int
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
		fmt.Fprintf(os.Stdout, "Databases: ASN (yes), Names (yes), Country (%v), City (%v), Netblock (%v), Category (%v)\n",
			s.eng.HasCountryDB(), s.eng.HasCityDB(), s.eng.HasNetblockDB(), s.eng.HasCategoryDB())
		fmt.Fprintf(os.Stdout, "Ready to handle requests. Press Ctrl+C to shut down.\n")
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case <-shutdownCtx.Done():
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
	resp := healthResponse{
		Status:  "healthy",
		Version: s.version,
		Databases: map[string]bool{
			"asn":      true,
			"names":    true,
			"country":  s.eng.HasCountryDB(),
			"city":     s.eng.HasCityDB(),
			"netblock": s.eng.HasNetblockDB(),
			"category": s.eng.HasCategoryDB(),
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
		s.lookupSingle(w, r.Context(), query, wantRDNS)
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
	s.lookupSingle(w, r.Context(), targetStr, wantRDNS)
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
}

func (s *Server) lookupSingle(w http.ResponseWriter, ctx context.Context, rawTarget string, wantRDNS bool) {
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
	}

	results, err := s.eng.LookupTarget(t)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if wantRDNS {
		engine.ResolveReverseDNS(ctx, results)
	}

	jsonResults := make([]format.JSONLookupResult, 0, len(results))
	for _, res := range results {
		jsonResults = append(jsonResults, format.ToJSONResult(res))
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
	} else {
		lines := strings.Split(string(bodyBytes), "\n")
		for _, l := range lines {
			entry, ok := engine.EntryFromLine(l)
			if ok && entry != "" {
				targetStrings = append(targetStrings, entry)
			}
		}
	}

	if len(targetStrings) == 0 {
		writeJSONError(w, http.StatusBadRequest, "no targets provided in request body")
		return
	}

	targets := make([]engine.Target, 0, len(targetStrings))
	for _, raw := range targetStrings {
		targets = append(targets, engine.NewTarget(raw))
	}

	engine.ResolveTargets(r.Context(), targets)

	var allResults []engine.LookupResult
	var errorDetails []jsonErrorDetail

	for _, t := range targets {
		if t.Err != nil {
			errorDetails = append(errorDetails, jsonErrorDetail{Target: t.Raw, Error: t.Err.Error()})
			continue
		}
		found, err := s.eng.LookupTarget(t)
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
		jsonResults = append(jsonResults, format.ToJSONResult(res))
	}

	resp := bulkResponse{
		Count:   len(jsonResults),
		Results: jsonResults,
		Errors:  errorDetails,
	}
	writeJSON(w, http.StatusOK, resp)
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
	Count    int                               `json:"count"`
	Results  []format.JSONNetblockSearchResult `json:"results"`
	ASNCount int                               `json:"asn_count"`
	ASNs     []format.JSONASNSearchResult      `json:"asns"`
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

	asnResults := make([]format.JSONASNSearchResult, 0)
	if scope != "netblocks" {
		for _, res := range s.eng.SearchASNs(query, limit, v4Only, v6Only) {
			asnResults = append(asnResults, format.NewJSONASNSearchResult(res))
		}
	}

	// A combined search answers from the AS names alone when the server has
	// no netblock database; asking for netblocks only still reports it.
	jsonResults := make([]format.JSONNetblockSearchResult, 0)
	if scope == "netblocks" || (scope != "asns" && s.eng.HasNetblockDB()) {
		results, err := s.eng.SearchNetblocks(query, sources.NetblockSearchOptions{
			Limit:  limit,
			V4Only: v4Only,
			V6Only: v6Only,
		})
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, res := range results {
			jsonResults = append(jsonResults, format.NewJSONNetblockSearchResult(res))
		}
	}

	writeJSON(w, http.StatusOK, searchResponse{
		Query:    query,
		Count:    len(jsonResults),
		Results:  jsonResults,
		ASNCount: len(asnResults),
		ASNs:     asnResults,
	})
}
