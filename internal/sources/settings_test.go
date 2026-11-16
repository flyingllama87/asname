package sources

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSettingsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), SettingsFilename)

	s, err := LoadSettings(path)
	require.NoError(t, err, "a missing file is no settings")
	_, ok := s.SavedMaxAge()
	assert.False(t, ok)

	require.NoError(t, SaveSettings(path, Settings{MaxAge: (7 * 24 * time.Hour).String()}))
	s, err = LoadSettings(path)
	require.NoError(t, err)
	age, ok := s.SavedMaxAge()
	assert.True(t, ok)
	assert.Equal(t, 7*24*time.Hour, age)

	require.NoError(t, SaveSettings(path, Settings{MaxAge: "0s"}))
	s, _ = LoadSettings(path)
	age, ok = s.SavedMaxAge()
	assert.True(t, ok, "zero is a saved choice: never refresh")
	assert.Zero(t, age)

	require.NoError(t, os.WriteFile(path, []byte(`{"max_age":"-5h"}`), 0o644))
	s, _ = LoadSettings(path)
	_, ok = s.SavedMaxAge()
	assert.False(t, ok, "a negative age is ignored")
}

func TestSetIPv6Routes(t *testing.T) {
	cfg := Config{IPv6Path: filepath.Join(t.TempDir(), IPv6MarkerFilename)}
	require.NoError(t, SetIPv6Routes(cfg, true))
	assert.True(t, IPv6RoutesEnabled(cfg))
	require.NoError(t, SetIPv6Routes(cfg, false))
	assert.False(t, IPv6RoutesEnabled(cfg))
}
