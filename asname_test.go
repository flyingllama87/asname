package asname

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/flyingllama87/asname/internal/sources"
	"github.com/flyingllama87/asname/pkg/database"
)

func createTestEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// 1. Build test ASN database (8.8.8.0/24 -> 15169, 1.1.1.0/24 -> 13335)
	b := database.NewBuilder()
	_, netGoogle, err := net.ParseCIDR("8.8.8.0/24")
	require.NoError(t, err)
	require.NoError(t, b.InsertMapping(netGoogle, 15169))

	_, netCF, err := net.ParseCIDR("1.1.1.0/24")
	require.NoError(t, err)
	require.NoError(t, b.InsertMapping(netCF, 13335))

	db, err := b.Build()
	require.NoError(t, err)
	dbData, err := db.MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, sources.DBFilename), dbData, 0o644))

	// 2. Build test names database
	namesContent := "15169\tGOOGLE - Google LLC, US\n13335\tCLOUDFLARENET - Cloudflare, Inc., US\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, sources.NamesFilename), []byte(namesContent), 0o644))

	// 3. Build test country database
	cb := database.NewBuilder()
	require.NoError(t, cb.InsertMapping(netGoogle, sources.EncodeCC("US")))
	require.NoError(t, cb.InsertMapping(netCF, sources.EncodeCC("US")))
	cdb, err := cb.Build()
	require.NoError(t, err)
	cData, err := cdb.MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, sources.CountryFilename), cData, 0o644))

	return dir
}

func TestNew_MissingDB(t *testing.T) {
	emptyDir := t.TempDir()
	client, err := New(WithDataDir(emptyDir))
	assert.Error(t, err)
	assert.Nil(t, client)
}

func TestClient_Lookup(t *testing.T) {
	dir := createTestEnv(t)

	client, err := New(WithDataDir(dir))
	require.NoError(t, err)
	defer client.Close()

	// 1. Lookup IP string
	results, err := client.Lookup("8.8.8.8")
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, "8.8.8.8", r.IP.String())
	assert.Equal(t, "AS15169", r.ASN)
	assert.Equal(t, uint32(15169), r.ASNNumber())
	assert.Equal(t, "GOOGLE - Google LLC, US", r.Name)
	assert.Equal(t, "US, United States", r.Country)
	assert.Equal(t, "US", r.CountryCode())
	assert.Equal(t, "United States", r.CountryName())
	assert.Contains(t, r.String(), "AS15169")

	// 2. Direct LookupIP
	ipRes, err := client.LookupIP(net.ParseIP("1.1.1.1"))
	require.NoError(t, err)
	assert.Equal(t, "AS13335", ipRes.ASN)
	assert.Equal(t, uint32(13335), ipRes.ASNNumber())
	assert.Equal(t, "CLOUDFLARENET - Cloudflare, Inc., US", ipRes.Name)
	assert.Equal(t, "US", ipRes.CountryCode())

	// 3. Unknown IP
	unknownRes, err := client.LookupIP(net.ParseIP("10.0.0.1"))
	require.NoError(t, err)
	assert.Equal(t, "N/A", unknownRes.ASN)
	assert.Equal(t, uint32(0), unknownRes.ASNNumber())
	assert.Equal(t, "Unknown", unknownRes.Name)

	// 4. Lookup ASN
	asnRes, err := client.LookupASN(15169)
	require.NoError(t, err)
	assert.True(t, asnRes.IsASN)
	assert.Equal(t, "AS15169", asnRes.ASN)
	assert.Equal(t, "GOOGLE - Google LLC, US", asnRes.Name)
	assert.Equal(t, "US, United States", asnRes.Country)
	assert.Contains(t, asnRes.String(), "ASN: AS15169")
}

func TestClient_LookupContext(t *testing.T) {
	dir := createTestEnv(t)

	client, err := New(WithDataDir(dir))
	require.NoError(t, err)
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	results, err := client.LookupContext(ctx, "8.8.8.8")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "AS15169", results[0].ASN)
}

func TestClient_Close(t *testing.T) {
	dir := createTestEnv(t)

	client, err := New(WithDataDir(dir))
	require.NoError(t, err)

	err = client.Close()
	require.NoError(t, err)

	// Repeated Close should be safe
	assert.NoError(t, client.Close())

	// Operations after close should fail
	_, err = client.Lookup("8.8.8.8")
	assert.Equal(t, ErrClosed, err)

	_, err = client.LookupIP(net.ParseIP("8.8.8.8"))
	assert.Equal(t, ErrClosed, err)

	_, err = client.LookupASN(15169)
	assert.Equal(t, ErrClosed, err)
}

func TestClient_ConcurrentLookups(t *testing.T) {
	dir := createTestEnv(t)

	client, err := New(WithDataDir(dir))
	require.NoError(t, err)
	defer client.Close()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				res, err := client.LookupIP(net.ParseIP("8.8.8.8"))
				assert.NoError(t, err)
				assert.Equal(t, "AS15169", res.ASN)

				res2, err := client.LookupIP(net.ParseIP("1.1.1.1"))
				assert.NoError(t, err)
				assert.Equal(t, "AS13335", res2.ASN)
			}
		}()
	}
	wg.Wait()
}

func TestResult_Helpers(t *testing.T) {
	r := Result{
		Country: "US, United States",
		ASN:     "AS15169",
	}
	assert.Equal(t, "US", r.CountryCode())
	assert.Equal(t, "United States", r.CountryName())
	assert.Equal(t, uint32(15169), r.ASNNumber())

	r2 := Result{Country: "Unknown", ASN: "N/A"}
	assert.Equal(t, "", r2.CountryCode())
	assert.Equal(t, "", r2.CountryName())
	assert.Equal(t, uint32(0), r2.ASNNumber())

	r3 := Result{Country: "DE"}
	assert.Equal(t, "DE", r3.CountryCode())
	assert.Equal(t, "DE", r3.CountryName())
}
