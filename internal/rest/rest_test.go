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
