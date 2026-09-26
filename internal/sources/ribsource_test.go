package sources

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// listingServer serves an Apache-style index for the current and previous month.
func listingServer(t *testing.T, names ...string) (*httptest.Server, *int) {
	t.Helper()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		for _, n := range names {
			fmt.Fprintf(w, "<a href=\"%s\">%s</a>\n", n, n)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestLatestRIBURLPicksTheNewestDump(t *testing.T) {
	srv, _ := listingServer(t, "bview.20260909.0800.gz", "bview.20260911.0000.gz")
	src := ribSource{
		name:     "test",
		listing:  srv.URL + "/%s/",
		filename: regexp.MustCompile(`bview\.[0-9]{8}\.[0-9]{4}\.gz`),
	}
	url, err := latestRIBURL(context.Background(), t.TempDir(), src)
	require.NoError(t, err)
	month := time.Now().UTC().Format("2006.01")
	require.Equal(t, srv.URL+"/"+month+"/bview.20260911.0000.gz", url)
}

func TestLatestRIBURLReportsAnEmptyListing(t *testing.T) {
	srv, _ := listingServer(t)
	src := ribSource{
		name:     "test",
		listing:  srv.URL + "/%s/",
		filename: regexp.MustCompile(`bview\.[0-9]{8}\.[0-9]{4}\.gz`),
	}
	_, err := latestRIBURL(context.Background(), t.TempDir(), src)
	require.ErrorContains(t, err, "no dump listed")
}

func TestUpdateDatabaseFallsBackToTheNextSource(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer dead.Close()

	live, hits := listingServer(t, "bview.20260911.0000.gz")

	restore := ribSources
	defer func() { ribSources = restore }()
	ribSources = []ribSource{
		{name: "dead", listing: dead.URL + "/%s/", filename: regexp.MustCompile(`rib\.[0-9]{8}\.[0-9]{4}\.bz2`)},
		{name: "live", listing: live.URL + "/%s/", filename: regexp.MustCompile(`bview\.[0-9]{8}\.[0-9]{4}\.gz`)},
	}

	dir := t.TempDir()
	cfg := Config{DBPath: filepath.Join(dir, "asname.db"), CachePath: filepath.Join(dir, "cache")}
	err := UpdateDatabase(context.Background(), cfg, "")

	// The second source is reached and its dump fetched; the body is not a real
	// gzip stream, so the run still fails, but it fails at the live source.
	require.Error(t, err)
	require.ErrorContains(t, err, "live")
	require.Greater(t, *hits, 0, "the fallback source must be listed after the first one fails")
	_, statErr := os.Stat(cfg.DBPath)
	require.True(t, os.IsNotExist(statErr))
}
