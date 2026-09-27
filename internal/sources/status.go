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
	}
	for i := range out {
		s := &out[i]
		info, err := os.Stat(s.Path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		s.Present, s.Size, s.Updated = true, info.Size(), info.ModTime()
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
