package sources

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/flyingllama87/asname/internal/fixture"
)

// maxMindArchive packs an .mmdb as MaxMind ships it: a tar.gz holding a
// dated directory with the database and its licence.
func maxMindArchive(t *testing.T, dbType string) []byte {
	t.Helper()
	mmdb := filepath.Join(t.TempDir(), "x.mmdb")
	require.NoError(t, fixture.WriteCityDBType(mmdb, dbType, []fixture.CityNetwork{
		{CIDR: "81.0.0.0/24", City: map[string]string{"en": "Kerkrade"}, Region: "Limburg", Country: "NL"},
	}))
	data, err := os.ReadFile(mmdb)
	require.NoError(t, err)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range map[string][]byte{
		dbType + "_20261113/LICENSE.txt":         []byte("licence"),
		dbType + "_20261113/" + dbType + ".mmdb": data,
	} {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}))
		_, err := tw.Write(body)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

func TestUpdateMaxMindCity(t *testing.T) {
	const account, key = "319", "s3cr3t-key"
	archive := maxMindArchive(t, "GeoLite2-City")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if r.URL.Path != "/geoip/databases/GeoLite2-City/download" || !ok || user != account || pass != key {
			http.Error(w, "Invalid account ID or license key", http.StatusUnauthorized)
			return
		}
		w.Write(archive)
	}))
	defer srv.Close()
	oldNew, oldLegacy := maxMindDownload, maxMindLegacyDownload
	maxMindDownload = srv.URL + "/geoip/databases/%s/download?suffix=tar.gz"
	maxMindLegacyDownload = srv.URL + "/app/geoip_download?edition_id=%s&license_key=%s&suffix=tar.gz"
	defer func() { maxMindDownload, maxMindLegacyDownload = oldNew, oldLegacy }()

	dir := t.TempDir()
	cfg := Config{CachePath: filepath.Join(dir, "cache")}
	path := filepath.Join(dir, MaxMindCityFilename)
	require.NoError(t, updateMaxMindCity(context.Background(), cfg, path, account, key, "GeoLite2-City"))

	db, err := LoadCityDB(path)
	require.NoError(t, err)
	defer db.Close()
	require.Equal(t, "MaxMind GeoLite2", CityProvider(db))
	require.Equal(t, "Kerkrade, Limburg, Netherlands", LookupCity(db, net.ParseIP("81.0.0.9")))
	_, err = os.Stat(path + ".new")
	require.True(t, os.IsNotExist(err), "no temporary file is left")

	// A key without the account goes to the old URL, which refuses it:
	// the error says what to set, and never shows the key.
	cfg2 := Config{CachePath: filepath.Join(dir, "cache2")}
	err = updateMaxMindCity(context.Background(), cfg2, filepath.Join(dir, "other.mmdb"), "", "wrong-key-123", "GeoLite2-City")
	require.ErrorContains(t, err, MaxMindAccountEnvVar)
	require.NotContains(t, err.Error(), "wrong-key-123")

	// A wrong key with the account fails without showing the key either.
	cfg3 := Config{CachePath: filepath.Join(dir, "cache3")}
	err = updateMaxMindCity(context.Background(), cfg3, filepath.Join(dir, "third.mmdb"), account, "wrong-key-456", "GeoLite2-City")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "wrong-key-456")
}

func TestUpdateMaxMindCityRejectsOtherEditions(t *testing.T) {
	archive := maxMindArchive(t, "GeoLite2-ASN")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(archive) }))
	defer srv.Close()
	old := maxMindDownload
	maxMindDownload = srv.URL + "/%s"
	defer func() { maxMindDownload = old }()

	dir := t.TempDir()
	path := filepath.Join(dir, MaxMindCityFilename)
	err := updateMaxMindCity(context.Background(), Config{CachePath: filepath.Join(dir, "cache")}, path, "1", "k", "GeoLite2-ASN")
	require.ErrorContains(t, err, "not a city database")
	require.False(t, CityDBPresent(path))
}

func TestRedactURLHidesKeys(t *testing.T) {
	require.Equal(t, "https://x/dl?edition_id=GeoLite2-City&license_key=...&suffix=tar.gz",
		redactURL("https://x/dl?edition_id=GeoLite2-City&license_key=abc123&suffix=tar.gz"))
	require.Equal(t, "https://x/bulk?apikey=...", redactURL("https://x/bulk?apikey=APIKEY"))
}
