package main

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
	"strings"
	"syscall"
	"time"
)

type restServer struct {
	eng        *engine
	listenAddr string
	cors       bool
	reverseDNS bool
	server     *http.Server
}

func newRESTServer(eng *engine, listenAddr string, cors, reverseDNS bool) *restServer {
	if listenAddr == "" {
		listenAddr = "127.0.0.1:8086"
	}
	return &restServer{
		eng:        eng,
		listenAddr: listenAddr,
		cors:       cors,
		reverseDNS: reverseDNS,
	}
}

// routes sets up the HTTP router.
func (s *restServer) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/ready", s.handleHealth)
	mux.HandleFunc("/v1/lookup", s.handleLookupQueryOrPost)
	mux.HandleFunc("/v1/lookup/", s.handleLookupPath)
	mux.HandleFunc("/v1/bulk", s.handleBulk)

	handler := http.Handler(mux)
	if s.cors {
		handler = s.corsMiddleware(handler)
	}
	return s.loggingMiddleware(handler)
}

func (s *restServer) corsMiddleware(next http.Handler) http.Handler {
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

func (s *restServer) loggingMiddleware(next http.Handler) http.Handler {
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

func (s *restServer) start(ctx context.Context) error {
	s.server = &http.Server{
		Addr:         s.listenAddr,
		Handler:      s.routes(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 20 * time.Second,
	}

	shutdownCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	serverErr := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stdout, "asname REST API listening on http://%s\n", s.listenAddr)
		fmt.Fprintf(os.Stdout, "Databases: ASN (yes), Names (yes), Country (%v), City (%v), Netblock (%v), Category (%v)\n",
			s.eng.countryDB != nil, s.eng.cityDB != nil, s.eng.netblockDB != nil, s.eng.categoryDB != nil)
		fmt.Fprintf(os.Stdout, "Ready to handle requests. Press Ctrl+C to shut down.\n")
		if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case <-shutdownCtx.Done():
		fmt.Fprintf(os.Stdout, "\nShutting down REST server gracefully...\n")
		timeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(timeoutCtx)
	case err := <-serverErr:
		return err
	}
}

type healthResponse struct {
	Status    string            `json:"status"`
	Version   string            `json:"version"`
	Databases map[string]bool   `json:"databases"`
}

func (s *restServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := healthResponse{
		Status:  "healthy",
		Version: version,
		Databases: map[string]bool{
			"asn":      true,
			"names":    true,
			"country":  s.eng.countryDB != nil,
			"city":     s.eng.cityDB != nil,
			"netblock": s.eng.netblockDB != nil,
			"category": s.eng.categoryDB != nil,
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *restServer) handleLookupQueryOrPost(w http.ResponseWriter, r *http.Request) {
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

func (s *restServer) handleLookupPath(w http.ResponseWriter, r *http.Request) {
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
	Query   string             `json:"query"`
	Count   int                `json:"count"`
	Results []jsonLookupResult `json:"results"`
}

type bulkResponse struct {
	Count   int                `json:"count"`
	Results []jsonLookupResult `json:"results"`
	Errors  []jsonErrorDetail  `json:"errors,omitempty"`
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

func (s *restServer) lookupSingle(w http.ResponseWriter, ctx context.Context, rawTarget string, wantRDNS bool) {
	t := newTarget(rawTarget)
	if t.err != nil {
		writeJSONError(w, http.StatusBadRequest, t.err.Error())
		return
	}

	if t.host != "" && len(t.ips) == 0 {
		var err error
		t.ips, err = lookupHostIPsWithRetry(ctx, t.host)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("dns resolution failed: %v", err))
			return
		}
	}

	results, err := s.eng.lookupTarget(t)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if wantRDNS {
		resolveReverseDNS(ctx, results)
	}

	jsonResults := make([]jsonLookupResult, 0, len(results))
	for _, res := range results {
		jsonResults = append(jsonResults, toJSONResult(res))
	}

	resp := lookupResponse{
		Query:   rawTarget,
		Count:   len(jsonResults),
		Results: jsonResults,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *restServer) handleBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	contentType := r.Header.Get("Content-Type")
	var targetStrings []string
	wantRDNS := s.wantsReverseDNS(r)

	// Bounded body reader (10 MB max)
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
		// Plain text: one per line
		lines := strings.Split(string(bodyBytes), "\n")
		for _, l := range lines {
			entry, ok := entryFromLine(l)
			if ok && entry != "" {
				targetStrings = append(targetStrings, entry)
			}
		}
	}

	if len(targetStrings) == 0 {
		writeJSONError(w, http.StatusBadRequest, "no targets provided in request body")
		return
	}

	targets := make([]target, 0, len(targetStrings))
	for _, raw := range targetStrings {
		targets = append(targets, newTarget(raw))
	}

	resolveTargets(r.Context(), targets)

	var allResults []lookupResult
	var errorDetails []jsonErrorDetail

	for _, t := range targets {
		if t.err != nil {
			errorDetails = append(errorDetails, jsonErrorDetail{Target: t.raw, Error: t.err.Error()})
			continue
		}
		found, err := s.eng.lookupTarget(t)
		if err != nil {
			errorDetails = append(errorDetails, jsonErrorDetail{Target: t.raw, Error: err.Error()})
			continue
		}
		allResults = append(allResults, found...)
	}

	if wantRDNS && len(allResults) > 0 {
		resolveReverseDNS(r.Context(), allResults)
	}

	jsonResults := make([]jsonLookupResult, 0, len(allResults))
	for _, res := range allResults {
		jsonResults = append(jsonResults, toJSONResult(res))
	}

	resp := bulkResponse{
		Count:   len(jsonResults),
		Results: jsonResults,
		Errors:  errorDetails,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *restServer) wantsReverseDNS(r *http.Request) bool {
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
	// Try RawURLEncoding, URLEncoding, RawStdEncoding, StdEncoding
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
