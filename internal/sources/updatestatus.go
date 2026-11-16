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
	KeyCategory   = "category"
	KeyReputation = "reputation"
)

// UpdateKeys lists the database keys in update order.
var UpdateKeys = []string{KeyASN, KeyNames, KeyCountry, KeyCity, KeyNetblock, KeyCategory, KeyReputation}

// UpdateOutcome is the outcome of the last update of one database.
type UpdateOutcome struct {
	// Attempted is when the last update ran.
	Attempted time.Time `json:"attempted"`
	// Error is set when the update failed outright and the previous file was kept.
	Error string `json:"error,omitempty"`
	// Failed names the sources that could not be read. The database was
	// still written, without them (or, for VPN providers, from a fallback copy).
	Failed []string `json:"failed,omitempty"`
}

// Incomplete reports whether the last update left anything out.
func (s UpdateOutcome) Incomplete() bool { return s.Error != "" || len(s.Failed) > 0 }

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
	mu    sync.Mutex
	names []string
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
		f.mu.Unlock()
		if err != nil {
			st.Error = err.Error()
		}
		if serr := saveUpdateRecord(cfg.UpdateRecordPath, key, st); serr != nil {
			logf(ctx, "asname: warning: recording update status: %v\n", serr)
		}
	}
}
