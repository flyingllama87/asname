package rest

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/flyingllama87/asname/internal/engine"
)

func TestRESTHealth(t *testing.T) {
	eng := engine.NewTestEngine(t)
	server := NewServer(eng, "127.0.0.1:8086", false, false, "0.5.0")
	handler := server.Routes()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp healthResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, "healthy", resp.Status)
	require.True(t, resp.Databases["asn"])
	require.True(t, resp.Databases["names"])
}

func TestRESTLookupQueryParam(t *testing.T) {
	eng := engine.NewTestEngine(t)
	server := NewServer(eng, "127.0.0.1:8086", false, false, "0.5.0")
	handler := server.Routes()

	req := httptest.NewRequest(http.MethodGet, "/v1/lookup?q=8.8.8.8", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp lookupResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, "8.8.8.8", resp.Query)
	require.Equal(t, 1, resp.Count)
	require.Len(t, resp.Results, 1)
	require.Equal(t, "8.8.8.8", resp.Results[0].IP)
	require.Equal(t, "AS15169", resp.Results[0].ASN.ASNString)
}

func TestRESTLookupPath(t *testing.T) {
	eng := engine.NewTestEngine(t)
	server := NewServer(eng, "127.0.0.1:8086", false, false, "0.5.0")
	handler := server.Routes()

	req := httptest.NewRequest(http.MethodGet, "/v1/lookup/8.8.8.8", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp lookupResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, "8.8.8.8", resp.Query)
	require.Len(t, resp.Results, 1)
	require.Equal(t, "8.8.8.8", resp.Results[0].IP)
}

func TestRESTLookupBase64(t *testing.T) {
	eng := engine.NewTestEngine(t)
	server := NewServer(eng, "127.0.0.1:8086", false, false, "0.5.0")
	handler := server.Routes()

	b64Target := base64.RawURLEncoding.EncodeToString([]byte("8.8.8.8"))
	req := httptest.NewRequest(http.MethodGet, "/v1/lookup/b64/"+b64Target, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp lookupResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, "8.8.8.8", resp.Query)
	require.Len(t, resp.Results, 1)
	require.Equal(t, "8.8.8.8", resp.Results[0].IP)
}

func TestRESTBulkJSON(t *testing.T) {
	eng := engine.NewTestEngine(t)
	server := NewServer(eng, "127.0.0.1:8086", false, false, "0.5.0")
	handler := server.Routes()

	body := `{"targets": ["8.8.8.8", "8.8.8.8"]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/bulk", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp bulkResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, 2, resp.Count)
	require.Len(t, resp.Results, 2)
}

func TestRESTBulkPlainText(t *testing.T) {
	eng := engine.NewTestEngine(t)
	server := NewServer(eng, "127.0.0.1:8086", false, false, "0.5.0")
	handler := server.Routes()

	body := "8.8.8.8\n# comment\n8.8.8.8\n"
	req := httptest.NewRequest(http.MethodPost, "/v1/bulk", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp bulkResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, 2, resp.Count)
	require.Len(t, resp.Results, 2)
}

func TestRESTCORS(t *testing.T) {
	eng := engine.NewTestEngine(t)
	server := NewServer(eng, "127.0.0.1:8086", true, false, "0.5.0")
	handler := server.Routes()

	req := httptest.NewRequest(http.MethodOptions, "/v1/lookup?q=8.8.8.8", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusNoContent, w.Code)
	require.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestRESTBadRequest(t *testing.T) {
	eng := engine.NewTestEngine(t)
	server := NewServer(eng, "127.0.0.1:8086", false, false, "0.5.0")
	handler := server.Routes()

	req := httptest.NewRequest(http.MethodGet, "/v1/lookup", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRESTSearchASNsWithoutNetblockDB(t *testing.T) {
	eng := engine.NewTestEngine(t)
	handler := NewServer(eng, "127.0.0.1:8086", false, false, "0.5.0").Routes()

	req := httptest.NewRequest(http.MethodGet, "/v1/search?q=google", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp searchResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Equal(t, 1, resp.ASNCount)
	require.Equal(t, "AS15169", resp.ASNs[0].ASN)
	require.Equal(t, "asn", resp.ASNs[0].Type)
	require.Equal(t, 0, resp.Count)

	// Asking for netblocks alone still reports the missing database.
	req = httptest.NewRequest(http.MethodGet, "/v1/search?q=google&scope=netblocks", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusInternalServerError, w.Code)

	req = httptest.NewRequest(http.MethodGet, "/v1/search?q=google&scope=bogus", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRESTSearchCountry(t *testing.T) {
	eng := engine.NewTestEngine(t)
	handler := NewServer(eng, "127.0.0.1:8086", false, false, "0.5.0").Routes()
	get := func(url string) (int, searchResponse) {
		req := httptest.NewRequest(http.MethodGet, url, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		var resp searchResponse
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		return w.Code, resp
	}
	code, resp := get("/v1/search?q=google&scope=asns&country=US")
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, 1, resp.ASNCount)
	require.Equal(t, "US", resp.Country)

	_, resp = get("/v1/search?q=google&scope=asns&country=Australia")
	require.Equal(t, 0, resp.ASNCount)

	_, resp = get("/v1/search?q=google&scope=asns&country=worldwide")
	require.Equal(t, 1, resp.ASNCount)

	code, _ = get("/v1/search?q=google&country=Narnia")
	require.Equal(t, http.StatusBadRequest, code)
}

func TestRESTExploreValidates(t *testing.T) {
	eng := engine.NewTestEngine(t)
	handler := NewServer(eng, "127.0.0.1:8086", false, false, "0.5.0").Routes()
	for _, q := range []string{"len=abc", "len=24-8", "family=v5", "reputation=bad", "sort=up", "asn=xyz", "country=Narnia", "min_listed_pct=-1"} {
		req := httptest.NewRequest(http.MethodGet, "/v1/explore?"+q, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		require.Equal(t, http.StatusBadRequest, w.Code, q)
	}
	// No prefix database: the index cannot be built.
	req := httptest.NewRequest(http.MethodGet, "/v1/explore?len=8", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
}
