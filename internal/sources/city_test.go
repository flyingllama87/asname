package sources

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFormatCity(t *testing.T) {
	cases := []struct {
		city, region, want string
	}{
		{"Mountain View", "California", "Mountain View, California"},
		{"Sydney", "New South Wales", "Sydney, New South Wales"},
		{"Berlin", "", "Berlin"},
		{"", "Queensland", "Queensland"},
		{"", "", ""},
		// A city-state repeats itself across both fields; say it once.
		{"Singapore", "Singapore", "Singapore"},
	}

	for _, tc := range cases {
		require.Equal(t, tc.want, FormatCity(tc.city, tc.region), "%q/%q", tc.city, tc.region)
	}
}

func TestPreferredName(t *testing.T) {
	require.Equal(t, "Vienna", PreferredName(map[string]string{"en": "Vienna", "de": "Wien"}))

	fallback := map[string]string{"ru": "Вена", "de": "Wien", "fr": "Vienne"}
	require.Equal(t, "Wien", PreferredName(fallback))
	require.Equal(t, "Wien", PreferredName(fallback))

	require.Equal(t, "", PreferredName(nil))
	require.Equal(t, "Wien", PreferredName(map[string]string{"en": "", "de": "Wien"}))
}

func TestCityDBPresent(t *testing.T) {
	dir := t.TempDir()
	require.False(t, CityDBPresent(filepath.Join(dir, "city.mmdb")))
	require.False(t, CityDBPresent(dir), "a directory is not a usable database")

	path := filepath.Join(dir, "city.mmdb")
	require.NoError(t, WriteFileAtomic(path, []byte("not really an mmdb")))
	require.True(t, CityDBPresent(path))
}
