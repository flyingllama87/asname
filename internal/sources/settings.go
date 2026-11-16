package sources

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SettingsFilename holds settings saved for a data directory, such as the
// refresh age chosen in the web UI.
const SettingsFilename = "settings.json"

// Settings are kept in the data directory, so the asname command and a
// server sharing the directory follow them alike.
type Settings struct {
	// MaxAge, a Go duration such as "168h0m0s", replaces the default age at
	// which databases are refreshed. "0s" turns refreshing off. Empty keeps
	// the default. --max-age and ASNAME_MAX_AGE override it.
	MaxAge string `json:"max_age,omitempty"`
}

// LoadSettings reads the settings at path. A missing file is no settings.
func LoadSettings(path string) (Settings, error) {
	var s Settings
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("reading %s: %w", path, err)
	}
	return s, nil
}

// SaveSettings writes s to path, replacing the file atomically.
func SaveSettings(path string, s Settings) error {
	if path == "" {
		return fmt.Errorf("no settings file")
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".settings-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// SavedMaxAge reports the refresh age saved in s, if any.
func (s Settings) SavedMaxAge() (time.Duration, bool) {
	if s.MaxAge == "" {
		return 0, false
	}
	d, err := time.ParseDuration(s.MaxAge)
	if err != nil || d < 0 {
		return 0, false
	}
	return d, true
}

// SetIPv6Routes records whether later ASN updates import IPv6 routes, as
// `asname update --ipv6` and `--no-ipv6` do. It takes effect at the next
// update of the ASN database.
func SetIPv6Routes(cfg Config, on bool) error {
	cfg.IPv6 = on
	return setIPv6Marker(cfg)
}
