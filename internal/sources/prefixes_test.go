package sources

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrefixDBBuildAndLookup(t *testing.T) {
	builder := NewPrefixDBBuilder()

	// Add prefixes for AS15169 (Google)
	_, p1, _ := net.ParseCIDR("8.8.8.0/24")
	_, p2, _ := net.ParseCIDR("8.8.4.0/24")
	_, p3, _ := net.ParseCIDR("2001:4860::/32")
	builder.Add(15169, p1)
	builder.Add(15169, p2)
	builder.Add(15169, p3)

	// Add prefixes for AS13335 (Cloudflare)
	_, p4, _ := net.ParseCIDR("1.1.1.0/24")
	_, p5, _ := net.ParseCIDR("2606:4700::/32")
	builder.Add(13335, p4)
	builder.Add(13335, p5)

	path := filepath.Join(t.TempDir(), PrefixFilename)
	n, err := builder.Write(path)
	require.NoError(t, err)
	require.Greater(t, n, int64(0))

	db, err := OpenPrefixDB(path)
	require.NoError(t, err)
	defer db.Close()

	// Lookup Google
	res, err := db.Lookup(15169)
	require.NoError(t, err)
	require.Equal(t, uint32(15169), res.ASN)
	require.Equal(t, "offline", res.Source)
	require.Len(t, res.IPv4, 2)
	require.Contains(t, res.IPv4, "8.8.4.0/24")
	require.Contains(t, res.IPv4, "8.8.8.0/24")
	require.Len(t, res.IPv6, 1)
	require.Contains(t, res.IPv6, "2001:4860::/32")

	// Lookup Cloudflare
	resCF, err := db.Lookup(13335)
	require.NoError(t, err)
	require.Equal(t, uint32(13335), resCF.ASN)
	require.Len(t, resCF.IPv4, 1)
	require.Contains(t, resCF.IPv4, "1.1.1.0/24")
	require.Len(t, resCF.IPv6, 1)

	// Lookup non-existent
	resNone, err := db.Lookup(999999)
	require.NoError(t, err)
	require.Empty(t, resNone.IPv4)
	require.Empty(t, resNone.IPv6)
}
