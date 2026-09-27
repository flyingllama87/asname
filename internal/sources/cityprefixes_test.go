package sources

import (
	"path/filepath"
	"testing"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/stretchr/testify/require"

	"github.com/flyingllama87/asname/internal/fixture"
)

func openTestCityDB(t *testing.T) *maxminddb.Reader {
	t.Helper()
	brisbane := map[string]string{"en": "Brisbane"}
	path := filepath.Join(t.TempDir(), CityFilename)
	require.NoError(t, fixture.WriteCityDB(path, []fixture.CityNetwork{
		// Two records for one place, on adjacent networks.
		{CIDR: "1.0.0.0/24", City: brisbane, Region: "Queensland", Country: "AU"},
		{CIDR: "1.0.1.0/24", City: map[string]string{"en": "Brisbane", "ja": "ブリスベン"}, Region: "Queensland", Country: "AU"},
		{CIDR: "1.0.3.0/24", City: brisbane, Region: "Queensland", Country: "AU"},
		{CIDR: "2400:1000::/32", City: brisbane, Region: "Queensland", Country: "AU"},
		{CIDR: "1.0.2.0/24", City: brisbane, Region: "California", Country: "US"},
		{CIDR: "1.0.4.0/24", City: map[string]string{"en": "Munich", "de": "München"}, Region: "Bavaria", Country: "DE"},
		{CIDR: "1.0.5.0/24", City: map[string]string{"en": "Sydney"}, Region: "New South Wales", Country: "AU"},
	}))
	db, err := LoadCityDB(path)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func TestCityPrefixes(t *testing.T) {
	db := openTestCityDB(t)

	places, err := CityPrefixes(db, "brisbane")
	require.NoError(t, err)
	require.Equal(t, []CityPlace{
		{City: "Brisbane", Region: "Queensland", Country: "AU", IPv4: []string{"1.0.0.0/23", "1.0.3.0/24"}, IPv6: []string{"2400:1000::/32"}},
		{City: "Brisbane", Region: "California", Country: "US", IPv4: []string{"1.0.2.0/24"}},
	}, places)

	for _, q := range []string{"Brisbane, AU", "brisbane,australia", "Brisbane, queensland"} {
		places, err = CityPrefixes(db, q)
		require.NoError(t, err)
		require.Len(t, places, 1, q)
		require.Equal(t, "AU", places[0].Country, q)
	}

	places, err = CityPrefixes(db, "Brisbane, California")
	require.NoError(t, err)
	require.Len(t, places, 1)
	require.Equal(t, "US", places[0].Country)

	// Any language the database holds matches; the English name is reported.
	places, err = CityPrefixes(db, "münchen")
	require.NoError(t, err)
	require.Len(t, places, 1)
	require.Equal(t, "Munich", places[0].City)
	require.Equal(t, []string{"1.0.4.0/24"}, places[0].IPv4)

	places, err = CityPrefixes(db, "Brisbane, NZ")
	require.NoError(t, err)
	require.Empty(t, places)

	places, err = CityPrefixes(db, "Brisb")
	require.NoError(t, err)
	require.Empty(t, places, "a city name must match in full")

	_, err = CityPrefixes(db, " , AU")
	require.Error(t, err)
}
