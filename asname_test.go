package asname

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/flyingllama87/asname/internal/engine"
	"github.com/flyingllama87/asname/internal/fixture"
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
	assert.Equal(t, "", unknownRes.ASN)
	assert.Equal(t, uint32(0), unknownRes.ASNNumber())
	assert.Equal(t, "", unknownRes.Name)
	assert.Equal(t, "", unknownRes.Country)
	assert.Contains(t, unknownRes.String(), "ASN: N/A | Name: Unknown | Country: Unknown")

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

	r2 := Result{}
	assert.Equal(t, "", r2.CountryCode())
	assert.Equal(t, "", r2.CountryName())
	assert.Equal(t, uint32(0), r2.ASNNumber())

	r3 := Result{Country: "DE"}
	assert.Equal(t, "DE", r3.CountryCode())
	assert.Equal(t, "DE", r3.CountryName())
}

func TestResultFromEngine_PlaceholdersBecomeEmpty(t *testing.T) {
	// The engine fills these in for the CLI's formatters when a loaded
	// database has no answer; the public Result must not carry them.
	r := resultFromEngine(engine.LookupResult{
		ASN: "N/A", Name: "Unknown", Country: "Unknown", City: "Unknown",
		Netblock: "Unknown", Category: "Unknown", RDNS: "N/A",
	})
	assert.Equal(t, Result{}, r)

	nb := netblockResultFromEngine(engine.NetblockEnrichedResult{ASN: "N/A", ASName: "Unknown", Country: "Unknown"})
	assert.Equal(t, NetblockResult{}, nb)

	kept := resultFromEngine(engine.LookupResult{ASN: "AS15169", City: "Sydney, New South Wales"})
	assert.Equal(t, "AS15169", kept.ASN)
	assert.Equal(t, "Sydney, New South Wales", kept.City)
}

func TestResolveConfig_Precedence(t *testing.T) {
	envDir := t.TempDir()
	t.Setenv(sources.DirEnvVar, envDir)
	t.Setenv(sources.DBEnvVar, "/env/asname.db")
	t.Setenv(sources.CountryEnvVar, "")

	// No directory given: $ASNAME_DIR supplies it, and a per-file variable
	// overrides the file it names.
	cfg := resolveConfig("", CustomPaths{})
	assert.Equal(t, "/env/asname.db", cfg.DBPath)
	assert.Equal(t, filepath.Join(envDir, sources.NamesFilename), cfg.NamesPath)
	assert.Equal(t, filepath.Join(envDir, sources.CountryFilename), cfg.CountryPath)
	assert.Equal(t, filepath.Join(envDir, sources.ContactFilename), cfg.ContactPath)

	// An explicit directory beats $ASNAME_DIR; an explicit path beats everything.
	cfg = resolveConfig("/explicit", CustomPaths{NamesPath: "/mine/names.txt"})
	assert.Equal(t, "/env/asname.db", cfg.DBPath)
	assert.Equal(t, "/mine/names.txt", cfg.NamesPath)
	assert.Equal(t, filepath.Join("/explicit", sources.CityFilename), cfg.CityPath)

	cfg = resolveConfig("", CustomPaths{DBPath: "/mine/asname.db"})
	assert.Equal(t, "/mine/asname.db", cfg.DBPath)
}

func TestNew_HonoursASNAME_DIR(t *testing.T) {
	t.Setenv(sources.DirEnvVar, createTestEnv(t))
	for _, env := range []string{sources.DBEnvVar, sources.NamesEnvVar, sources.CountryEnvVar} {
		t.Setenv(env, "")
	}

	assert.Equal(t, os.Getenv(sources.DirEnvVar), DefaultOptions().DataDir)
	client, err := New()
	require.NoError(t, err)
	defer client.Close()

	res, err := client.LookupIP(net.ParseIP("1.1.1.1"))
	require.NoError(t, err)
	assert.Equal(t, uint32(13335), res.ASNNumber())
}

func TestNew_WarningsGoToLog(t *testing.T) {
	dir := createTestEnv(t)
	var log strings.Builder

	// City forced on with no city database: the engine warns and carries on.
	client, err := New(WithDataDir(dir), WithCity(true), WithLog(&log))
	require.NoError(t, err)
	defer client.Close()
	assert.Contains(t, log.String(), "city database unavailable")
	assert.False(t, client.HasCityDB())
}

func TestUpdateStale_FreshFilesAreLeftAlone(t *testing.T) {
	dir := createTestEnv(t)

	for _, maxAge := range []time.Duration{0, time.Hour} {
		refreshed, err := UpdateStale(context.Background(), UpdateOptions{DataDir: dir}, maxAge)
		require.NoError(t, err)
		assert.Empty(t, refreshed, "maxAge %v", maxAge)
	}
}

func TestUpdateStale_OnlyStaleFilesAreSelected(t *testing.T) {
	dir := createTestEnv(t)

	// A cancelled context fails the first download UpdateStale attempts and
	// nothing else, so it shows whether any file was selected without
	// touching the network.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	refreshed, err := UpdateStale(ctx, UpdateOptions{DataDir: dir}, 24*time.Hour)
	require.NoError(t, err, "every core file is fresh, so nothing should be attempted")
	assert.Empty(t, refreshed)

	old := time.Now().Add(-48 * time.Hour)
	require.NoError(t, os.Chtimes(filepath.Join(dir, sources.NamesFilename), old, old))
	refreshed, err = UpdateStale(ctx, UpdateOptions{DataDir: dir}, 24*time.Hour)
	assert.ErrorIs(t, err, context.Canceled, "the stale names file should have been attempted")
	assert.Empty(t, refreshed)

	// Opt-in databases are only considered when selected.
	require.NoError(t, os.Chtimes(filepath.Join(dir, sources.NamesFilename), time.Now(), time.Now()))
	_, err = UpdateStale(ctx, UpdateOptions{DataDir: dir, City: true}, 24*time.Hour)
	assert.ErrorIs(t, err, context.Canceled, "the missing city database should have been attempted")
}

func TestUpdate_HonoursCancelledContext(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := Update(ctx, UpdateOptions{DataDir: dir, All: true})
	assert.ErrorIs(t, err, context.Canceled)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "a cancelled update must not write anything")
}

func TestLibraryContact_NeverPrompts(t *testing.T) {
	t.Setenv(sources.ContactEnvVar, "")
	cfg := resolveConfig(t.TempDir(), CustomPaths{})
	var log strings.Builder

	a := libraryContact(cfg, contactEmail(""), &log)
	email, ok := a.Contact()
	assert.False(t, ok)
	assert.Empty(t, email)
	assert.Contains(t, log.String(), sources.ContactEnvVar)
}

func TestNew_OnlinePrefixesOffByDefault(t *testing.T) {
	dir := createTestEnv(t)

	client, err := New(WithDataDir(dir))
	require.NoError(t, err)
	defer client.Close()
	assert.False(t, client.eng.OnlinePrefixes)

	// With no prefix database and online queries off, an ASN lookup answers
	// from the local names alone.
	res, err := client.LookupASN(15169)
	require.NoError(t, err)
	assert.Equal(t, "GOOGLE - Google LLC, US", res.Name)
	assert.Empty(t, res.Prefixes)
	assert.Empty(t, res.PrefixSource)

	online, err := New(WithDataDir(dir), WithOnlinePrefixes(true))
	require.NoError(t, err)
	defer online.Close()
	assert.True(t, online.eng.OnlinePrefixes)
}

func TestClient_Search_ASNsWithoutNetblockDB(t *testing.T) {
	dir := createTestEnv(t)
	client, err := New(WithDataDir(dir))
	require.NoError(t, err)
	defer client.Close()

	got, err := client.Search("cloudflare", SearchOptions{})
	require.NoError(t, err)
	assert.Equal(t, []ASNResult{{ASN: "AS13335", Number: 13335, Name: "CLOUDFLARENET - Cloudflare, Inc., US", Country: "US, United States"}}, got.ASNs)
	assert.Empty(t, got.Netblocks)

	got, err = client.Search("google", SearchOptions{Scope: SearchASNsOnly})
	require.NoError(t, err)
	require.Len(t, got.ASNs, 1)
	assert.Equal(t, uint32(15169), got.ASNs[0].Number)

	_, err = client.Search("google", SearchOptions{Scope: SearchNetblocksOnly})
	assert.Error(t, err, "netblocks were asked for but the database is absent")
}

func TestClient_CountryPrefixes(t *testing.T) {
	dir := createTestEnv(t)
	client, err := New(WithDataDir(dir))
	require.NoError(t, err)
	defer client.Close()

	got, err := client.CountryPrefixes("united states")
	require.NoError(t, err)
	assert.Equal(t, CountryResult{Country: "US", Name: "United States", IPv4: []string{"1.1.1.0/24", "8.8.8.0/24"}}, got)

	_, err = client.CountryPrefixes("Atlantis")
	assert.Error(t, err)
}

func TestClient_CityPrefixes(t *testing.T) {
	dir := createTestEnv(t)
	client, err := New(WithDataDir(dir))
	require.NoError(t, err)
	_, err = client.CityPrefixes("Brisbane")
	assert.ErrorContains(t, err, "city database is not open")
	client.Close()

	require.NoError(t, fixture.WriteCityDB(filepath.Join(dir, sources.CityFilename), []fixture.CityNetwork{
		{CIDR: "1.0.0.0/24", City: map[string]string{"en": "Brisbane"}, Region: "Queensland", Country: "AU"},
		{CIDR: "1.0.1.0/24", City: map[string]string{"en": "Brisbane"}, Region: "California", Country: "US"},
	}))
	client, err = New(WithDataDir(dir))
	require.NoError(t, err)
	defer client.Close()

	got, err := client.CityPrefixes("brisbane, au")
	require.NoError(t, err)
	assert.Equal(t, []CityResult{{City: "Brisbane", Region: "Queensland", Country: "AU", IPv4: []string{"1.0.0.0/24"}}}, got)

	got, err = client.CityPrefixes("Brisbane")
	require.NoError(t, err)
	assert.Len(t, got, 2)
}
