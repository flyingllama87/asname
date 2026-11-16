package sources

import (
	"os"
	"time"
)

// DBStatus describes one data file on disk.
type DBStatus struct {
	Name     string
	Path     string
	Optional bool // only downloaded or built on request
	Present  bool
	Size     int64
	// Updated is the file's modification time: when asname last wrote it,
	// and what auto-update measures --max-age against.
	Updated time.Time
	// Built is when the source data was built, for a file that records it;
	// only the city database does. Zero otherwise.
	Built time.Time
	// Missing names the sources the last update could not read, and
	// LastError is set when it failed outright and kept the previous file;
	// see LoadUpdateRecord. Both are empty after a complete update.
	Missing   []string
	LastError string
	// UpdateKey is the update step that rebuilds this database, one of
	// UpdateKeys; the ASN prefixes are rebuilt with the ASN database.
	UpdateKey string
	// Sources lists every public source this database can be built from,
	// with how each fared in the last update when that was recorded.
	Sources []SourceStatus
	// VPNLists, for the category database, says which list each
	// vpn:<provider> tag came from and when it was current.
	VPNLists []VPNListStatus
}

// DatabaseStatus reports on each data file cfg names, core databases first.
func DatabaseStatus(cfg Config) []DBStatus {
	out := []DBStatus{
		{Name: "ASN", Path: cfg.DBPath},
		{Name: "AS names", Path: cfg.NamesPath},
		{Name: "Country", Path: cfg.CountryPath},
		{Name: "ASN prefixes", Path: cfg.PrefixPath},
		{Name: "City", Path: cfg.CityPath, Optional: true},
		{Name: "Netblock", Path: cfg.NetblockPath, Optional: true},
		{Name: "Category", Path: cfg.CategoryPath, Optional: true},
		{Name: "Reputation", Path: cfg.ReputationPath, Optional: true},
	}
	// The update record is kept per update step; the prefix database is
	// written by the ASN step, which records a failure to write it.
	keys := []string{KeyASN, KeyNames, KeyCountry, "", KeyCity, KeyNetblock, KeyCategory, KeyReputation}
	rec := LoadUpdateRecord(cfg.UpdateRecordPath)
	for i, key := range keys {
		out[i].UpdateKey = key
		if i == 3 {
			out[i].UpdateKey = KeyASN
		}
		if o, ok := rec[key]; ok && key != "" {
			out[i].Missing, out[i].LastError = o.Failed, o.Error
		}
		if key != "" {
			out[i].Sources = sourceStatuses(key, rec[key])
		}
	}
	for i := range out {
		s := &out[i]
		info, err := os.Stat(s.Path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		s.Present, s.Size, s.Updated = true, info.Size(), info.ModTime()
	}
	if cat := &out[6]; cat.Present {
		cat.VPNLists = categoryVPNLists(cat.Path, cat.Updated)
	}
	if city := &out[4]; city.Present {
		if db, err := LoadCityDB(city.Path); err == nil {
			if db.Metadata.BuildEpoch > 0 {
				city.Built = db.Metadata.BuildTime()
			}
			db.Close()
		}
	}
	return out
}
