package main

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
		require.Equal(t, tc.want, formatCity(tc.city, tc.region), "%q/%q", tc.city, tc.region)
	}
}

func TestPreferredName(t *testing.T) {
	require.Equal(t, "Vienna", preferredName(map[string]string{"en": "Vienna", "de": "Wien"}))

	// Without an English label, fall back deterministically rather than
	// picking whatever the map iteration happens to yield first.
	fallback := map[string]string{"ru": "Вена", "de": "Wien", "fr": "Vienne"}
	require.Equal(t, "Wien", preferredName(fallback))
	require.Equal(t, "Wien", preferredName(fallback))

	require.Equal(t, "", preferredName(nil))
	require.Equal(t, "Wien", preferredName(map[string]string{"en": "", "de": "Wien"}))
}

func TestCityDBPresent(t *testing.T) {
	dir := t.TempDir()
	require.False(t, cityDBPresent(filepath.Join(dir, "city.mmdb")))
	require.False(t, cityDBPresent(dir), "a directory is not a usable database")

	path := filepath.Join(dir, "city.mmdb")
	require.NoError(t, writeFileAtomic(path, []byte("not really an mmdb")))
	require.True(t, cityDBPresent(path))
}

// The city field is omitted entirely unless the city database is in use, so
// existing output is unchanged for everyone who has not opted in.
func TestFormatLookupOutputCity(t *testing.T) {
	res := googleResult()
	require.NotContains(t, formatLookupOutput(res, false, false), "City:")

	res.city = "Mountain View, California"
	require.Contains(t, formatLookupOutput(res, false, false), "→ City: Mountain View, California\n")
}

func TestFormatLookupOutputCityUniform(t *testing.T) {
	res := googleResult()
	res.city = "Mountain View, California"
	res.rdns = "dns.google"

	got := formatLookupOutput(res, true, false)
	require.Contains(t, got, "→ City: Mountain View, California")
	require.Contains(t, got, "→ Reverse DNS: dns.google\n")
	// The city column is padded because it is not the final field.
	require.Contains(t, got, "Mountain View, California          → Reverse DNS")
}
