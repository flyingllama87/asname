package sources

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/flyingllama87/asname/pkg/database"
)

func TestCountryPrefixes(t *testing.T) {
	b := database.NewBuilder()
	for cidr, cc := range map[string]string{
		"1.0.0.0/24":    "AU",
		"1.0.1.0/24":    "AU", // adjacent, so merged with the one above
		"10.0.0.0/14":   "AU",
		"10.1.0.0/16":   "US", // carved out of the AU block
		"8.8.8.0/24":    "US",
		"2001:db8::/32": "AU",
		"2001:db9::/32": "US",
	} {
		_, n, err := net.ParseCIDR(cidr)
		require.NoError(t, err)
		require.NoError(t, b.InsertMapping(n, EncodeCC(cc)))
	}
	db, err := b.Build()
	require.NoError(t, err)

	v4, v6, err := CountryPrefixes(db, "au")
	require.NoError(t, err)
	require.Equal(t, []string{"1.0.0.0/23", "10.0.0.0/16", "10.2.0.0/15"}, v4)
	require.Equal(t, []string{"2001:db8::/32"}, v6)

	v4, v6, err = CountryPrefixes(db, "US")
	require.NoError(t, err)
	require.Equal(t, []string{"8.8.8.0/24", "10.1.0.0/16"}, v4)
	require.Equal(t, []string{"2001:db9::/32"}, v6)

	v4, v6, err = CountryPrefixes(db, "NZ")
	require.NoError(t, err)
	require.Empty(t, v4)
	require.Empty(t, v6)

	_, _, err = CountryPrefixes(db, "AUS")
	require.Error(t, err)
}

func TestParseCountry(t *testing.T) {
	cc, err := ParseCountry("au")
	require.NoError(t, err)
	require.Equal(t, "AU", cc)

	cc, err = ParseCountry("australia")
	require.NoError(t, err)
	require.Equal(t, "AU", cc)

	_, err = ParseCountry("Atlantis")
	require.Error(t, err)
}
