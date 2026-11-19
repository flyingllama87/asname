package sources

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"sync"
	"time"
)

// UpdateRecordFilename records how the last update of each database went.
const UpdateRecordFilename = "update-record.json"

// Database keys used in the update record, also shown to the user.
const (
	KeyASN        = "asn"
	KeyNames      = "names"
	KeyCountry    = "country"
	KeyCity       = "city"
	KeyNetblock   = "netblock"
	KeyGeofeed    = "geofeed"
	KeyCategory   = "category"
	KeyReputation = "reputation"
)

// UpdateKeys lists the database keys in update order.
var UpdateKeys = []string{KeyASN, KeyNames, KeyCountry, KeyCity, KeyNetblock, KeyGeofeed, KeyCategory, KeyReputation}

// UpdateOutcome is the outcome of the last update of one database.
type UpdateOutcome struct {
	// Attempted is when the last update ran.
	Attempted time.Time `json:"attempted"`
	// Error is set when the update failed outright and the previous file was kept.
	Error string `json:"error,omitempty"`
	// Failed names the sources that could not be read. The database was
	// still written, without them (or, for VPN providers, from a fallback copy).
	Failed []string `json:"failed,omitempty"`
	// Stale names the sources that could not be downloaded and were built
	// from their last good copy instead.
	Stale []string `json:"stale,omitempty"`
	// Sources lists every source the update read or tried, in order.
	// Records written before asname 0.17 have none.
	Sources []SourceOutcome `json:"sources,omitempty"`
}

// SourceOutcome is how one source fared in the last update of a database.
type SourceOutcome struct {
	Name string `json:"name"`
	// Entries is how many ranges, names or list entries it gave; 0 when
	// the builder does not count them.
	Entries int `json:"entries,omitempty"`
	// Failed means it could not be read and the database was built
	// without it (or, for a VPN provider, from gluetun's copy).
	Failed bool `json:"failed,omitempty"`
	// Note says anything else worth knowing, e.g. that an archive was
	// skipped because an earlier one worked.
	Note string `json:"note,omitempty"`
	// StaleSince, when set, means the download failed and the source was
	// read from its last good copy, downloaded then.
	StaleSince time.Time `json:"stale_since,omitzero"`
}

// Incomplete reports whether the last update left anything out.
// A source built from its last good copy counts, so --incremental tries it
// again.
func (s UpdateOutcome) Incomplete() bool {
	return s.Error != "" || len(s.Failed) > 0 || len(s.Stale) > 0
}

// UpdateRecord maps a database key to its last update outcome.
type UpdateRecord map[string]UpdateOutcome

// LoadUpdateRecord reads the status file. A missing or unreadable file is empty.
func LoadUpdateRecord(path string) UpdateRecord {
	s := UpdateRecord{}
	if path == "" {
		return s
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	if json.Unmarshal(data, &s) != nil {
		return UpdateRecord{}
	}
	return s
}

// Incomplete returns the keys whose last update left something out, sorted.
func (s UpdateRecord) Incomplete() []string {
	var keys []string
	for k, v := range s {
		if v.Incomplete() {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

var statusMu sync.Mutex

func saveUpdateRecord(path, key string, st UpdateOutcome) error {
	statusMu.Lock()
	defer statusMu.Unlock()
	s := LoadUpdateRecord(path)
	s[key] = st
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, append(data, '\n'))
}

type failKey struct{}

type failures struct {
	mu      sync.Mutex
	names   []string
	stale   []string
	sources []SourceOutcome
}

// source returns the entry for name, adding it if need be. f.mu is held.
func (f *failures) source(name string) *SourceOutcome {
	for i := range f.sources {
		if f.sources[i].Name == name {
			return &f.sources[i]
		}
	}
	f.sources = append(f.sources, SourceOutcome{Name: name})
	return &f.sources[len(f.sources)-1]
}

// noteSource records that source was read during the update running under
// ctx, giving entries (0 if not counted) and an optional note. Outside an
// update it does nothing.
func noteSource(ctx context.Context, source string, entries int, note string) {
	f, ok := ctx.Value(failKey{}).(*failures)
	if !ok {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.source(source)
	s.Entries += entries
	if note != "" {
		s.Note = note
	}
}

// noteUnused records a source that was not needed or not read, without
// making the update incomplete: a RIB archive skipped because another
// worked, or one that failed before a later one succeeded.
func noteUnused(ctx context.Context, source, note string) {
	f, ok := ctx.Value(failKey{}).(*failures)
	if !ok {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.source(source).Note = note
}

// noteStale records that source could not be downloaded during the update
// running under ctx and was read from its last good copy, from when.
func noteStale(ctx context.Context, source string, when time.Time) {
	f, ok := ctx.Value(failKey{}).(*failures)
	if !ok || when.IsZero() {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.source(source).StaleSince = when.UTC()
	for _, n := range f.stale {
		if n == source {
			return
		}
	}
	f.stale = append(f.stale, source)
}

// noteFailed records that source could not be read during the update running
// under ctx. Outside an update it does nothing.
func noteFailed(ctx context.Context, source string) {
	f, ok := ctx.Value(failKey{}).(*failures)
	if !ok {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.source(source).Failed = true
	for _, n := range f.names {
		if n == source {
			return
		}
	}
	f.names = append(f.names, source)
}

// beginUpdate starts tracking the update of database key. The returned
// function records the outcome in cfg.UpdateRecordPath; with no UpdateRecordPath set,
// nothing is recorded. Cancellation is not recorded, since it says nothing
// about the sources.
func beginUpdate(ctx context.Context, cfg Config, key string) (context.Context, func(error)) {
	if cfg.UpdateRecordPath == "" {
		return ctx, func(error) {}
	}
	if _, nested := ctx.Value(failKey{}).(*failures); nested {
		return ctx, func(error) {}
	}
	f := &failures{}
	ctx = context.WithValue(ctx, failKey{}, f)
	return ctx, func(err error) {
		if ctx.Err() != nil {
			return
		}
		st := UpdateOutcome{Attempted: time.Now().UTC()}
		f.mu.Lock()
		st.Failed = append([]string(nil), f.names...)
		st.Stale = append([]string(nil), f.stale...)
		st.Sources = append([]SourceOutcome(nil), f.sources...)
		f.mu.Unlock()
		if err != nil {
			st.Error = err.Error()
		}
		if serr := saveUpdateRecord(cfg.UpdateRecordPath, key, st); serr != nil {
			logf(ctx, "asname: warning: recording update status: %v\n", serr)
		}
	}
}
