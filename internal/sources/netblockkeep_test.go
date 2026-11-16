package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNetblockUpdateKeepsCompleteDatabaseWhenARegistryFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/org":
			w.Write([]byte("organisation: ORG-X\norg-name: Example Ltd\n"))
		case "/net":
			w.Write([]byte("inetnum: 192.0.2.0 - 192.0.2.255\nnetname: EXAMPLE\norg: ORG-X\ncountry: AU\n"))
		default: // the ARIN delegated statistics: a whole registry missing
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	oldSources, oldARIN := netblockSources, arinDelegatedURL
	netblockSources = []netblockSource{{name: "TEST", orgURLs: []string{srv.URL + "/org"}, netURLs: []string{srv.URL + "/net"}, schema: rpslSchema}}
	arinDelegatedURL = srv.URL + "/arin"
	t.Cleanup(func() { netblockSources, arinDelegatedURL = oldSources, oldARIN })
	t.Setenv(ArinKeyEnvVar, "")

	dir := t.TempDir()
	cfg := Config{
		NetblockPath:     filepath.Join(dir, NetblockFilename),
		NamesPath:        filepath.Join(dir, "missing-names"),
		CachePath:        filepath.Join(dir, "cache"),
		UpdateRecordPath: filepath.Join(dir, UpdateRecordFilename),
	}
	ctx := context.Background()

	// No database yet: a partial one beats none.
	require.NoError(t, UpdateNetblockDB(ctx, cfg))
	require.True(t, LoadUpdateRecord(cfg.UpdateRecordPath)[KeyNetblock].Incomplete())

	// The existing database is itself incomplete: replacing it loses nothing.
	old := time.Now().Add(-time.Hour)
	require.NoError(t, os.Chtimes(cfg.NetblockPath, old, old))
	require.NoError(t, UpdateNetblockDB(ctx, cfg))
	info, err := os.Stat(cfg.NetblockPath)
	require.NoError(t, err)
	require.True(t, info.ModTime().After(old), "incomplete database was not replaced")

	// The existing database is complete: keep it, and record the failure.
	require.NoError(t, saveUpdateRecord(cfg.UpdateRecordPath, KeyNetblock, UpdateOutcome{Attempted: time.Now()}))
	require.NoError(t, os.Chtimes(cfg.NetblockPath, old, old))
	err = UpdateNetblockDB(ctx, cfg)
	require.ErrorContains(t, err, "ARIN (delegated statistics) could not be read, keeping the existing netblock database")
	info, err = os.Stat(cfg.NetblockPath)
	require.NoError(t, err)
	require.True(t, info.ModTime().Equal(old), "complete database was replaced")
	rec := LoadUpdateRecord(cfg.UpdateRecordPath)[KeyNetblock]
	require.NotEmpty(t, rec.Error)
	require.Equal(t, []string{"ARIN (delegated statistics)"}, rec.Failed)
}
