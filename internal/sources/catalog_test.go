package sources

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSourceCatalogCoversEveryDatabase(t *testing.T) {
	for _, key := range UpdateKeys {
		cat := SourceCatalog(key)
		require.NotEmpty(t, cat, key)
		for _, c := range cat {
			require.NotEmpty(t, c.Name, key)
			require.NotEmpty(t, c.Provides, c.Name)
			require.NotContains(t, c.URL, "apikey", "no keys in URLs")
			require.NotContains(t, c.URL, "%s", "dated URLs are trimmed")
		}
	}
	names := map[string]bool{}
	for _, c := range SourceCatalog(KeyCategory) {
		names[c.Name] = true
	}
	for _, api := range vpnAPIs {
		require.True(t, names[api.source], "the catalog lists %s under the name the builder records", api.source)
	}
}

func TestSourceStatusesMergeTheRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rec.json")
	ctx, done := beginUpdate(context.Background(), Config{UpdateRecordPath: path}, KeyReputation)
	noteSource(ctx, "IPsum", 120, "")
	noteFailed(ctx, "FireHOL level 2")
	noteSource(ctx, "per-ASN counts", 0, "")
	done(nil)

	rec := LoadUpdateRecord(path)[KeyReputation]
	require.Equal(t, []string{"FireHOL level 2"}, rec.Failed)
	got := map[string]SourceStatus{}
	var order []string
	for _, s := range sourceStatuses(KeyReputation, rec) {
		got[s.Name] = s
		order = append(order, s.Name)
	}
	require.Equal(t, "Spamhaus ASN-DROP", order[0], "catalog order first")
	require.Equal(t, "per-ASN counts", order[len(order)-1], "then recorded sources the catalog lacks")
	require.True(t, got["IPsum"].Recorded)
	require.Equal(t, 120, got["IPsum"].Entries)
	require.True(t, got["FireHOL level 2"].Failed)
	require.False(t, got["Spamhaus DROP IPv4"].Recorded, "not reached in this update")
	require.NotEmpty(t, got["IPsum"].URL)

	// A record from before per-source outcomes still shows its failures.
	old := sourceStatuses(KeyCategory, UpdateOutcome{Failed: []string{"PeeringDB"}})
	for _, s := range old {
		require.Equal(t, s.Name == "PeeringDB", s.Failed, s.Name)
	}
}
