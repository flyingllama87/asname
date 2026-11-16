package sources

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func TestUpdateRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), UpdateRecordFilename)
	cfg := Config{UpdateRecordPath: path}

	// A database written without two of its sources.
	ctx, done := beginUpdate(context.Background(), cfg, KeyNetblock)
	noteFailed(ctx, "RIPE")
	noteFailed(ctx, "RIPE")
	noteFailed(ctx, "ARIN (delegated statistics)")
	done(nil)

	// A database that failed outright.
	_, done = beginUpdate(context.Background(), cfg, KeyCountry)
	done(errors.New("1 of 5 registries failed"))

	// A clean update.
	_, done = beginUpdate(context.Background(), cfg, KeyCity)
	done(nil)

	rec := LoadUpdateRecord(path)
	if got, want := rec.Incomplete(), []string{KeyCountry, KeyNetblock}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Incomplete() = %v, want %v", got, want)
	}
	if got, want := rec[KeyNetblock].Failed, []string{"RIPE", "ARIN (delegated statistics)"}; !reflect.DeepEqual(got, want) {
		t.Errorf("netblock failed = %v, want %v", got, want)
	}
	if rec[KeyCity].Attempted.IsZero() || rec[KeyCity].Incomplete() {
		t.Errorf("city = %+v, want a clean attempt", rec[KeyCity])
	}

	// A retry that reads every source clears the entry.
	_, done = beginUpdate(context.Background(), cfg, KeyNetblock)
	done(nil)
	if LoadUpdateRecord(path)[KeyNetblock].Incomplete() {
		t.Error("netblock still incomplete after a clean retry")
	}

	// A cancelled update records nothing.
	cctx, cancel := context.WithCancel(context.Background())
	ctx, done = beginUpdate(cctx, cfg, KeyCategory)
	noteFailed(ctx, "Tor")
	cancel()
	done(context.Canceled)
	if _, ok := LoadUpdateRecord(path)[KeyCategory]; ok {
		t.Error("cancelled update was recorded")
	}

	// Outside an update, noteFailed is a no-op; with no path nothing is written.
	noteFailed(context.Background(), "x")
	_, done = beginUpdate(context.Background(), Config{}, KeyASN)
	done(errors.New("boom"))
}
