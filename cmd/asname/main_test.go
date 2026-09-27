package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/flyingllama87/asname/internal/fixture"
	"github.com/flyingllama87/asname/internal/sources"
	"github.com/flyingllama87/asname/pkg/database"
)

// writeFixtures writes a small set of every database search, country and
// lookup read into a temporary data directory and returns it. AS64500 (Valve)
// holds 208.64.200.0/22, and AS15169 (Google) holds 8.8.8.0/24 and
// 2001:4860::/32; AS64501 (Cloudflare) is named but announces nothing.
func writeFixtures(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	cidr := func(s string) *net.IPNet {
		_, n, err := net.ParseCIDR(s)
		require.NoError(t, err)
		return n
	}
	writeDB := func(name string, mappings map[string]uint32) {
		b := database.NewBuilder()
		for c, v := range mappings {
			require.NoError(t, b.InsertMapping(cidr(c), v))
		}
		db, err := b.Build()
		require.NoError(t, err)
		data, err := db.MarshalBinary()
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0o644))
	}

	writeDB(sources.DBFilename, map[string]uint32{
		"8.8.8.0/24":      15169,
		"208.64.200.0/22": 64500,
	})
	writeDB(sources.CountryFilename, map[string]uint32{
		"8.8.8.0/24":      sources.EncodeCC("US"),
		"208.64.200.0/22": sources.EncodeCC("US"),
		"1.0.0.0/24":      sources.EncodeCC("AU"),
		"1.0.1.0/24":      sources.EncodeCC("AU"),
		"1.1.1.0/24":      sources.EncodeCC("AU"),
		"2001:db8::/32":   sources.EncodeCC("AU"),
	})

	names := "15169\tGOOGLE - Google LLC, US\n" +
		"64500\tVALVE-CORP - Valve Corporation, US\n" +
		"64501\tCLOUDFLARENET - Cloudflare, Inc., US\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, sources.NamesFilename), []byte(names), 0o644))

	pb := sources.NewPrefixDBBuilder()
	pb.Add(15169, cidr("8.8.8.0/24"))
	pb.Add(15169, cidr("2001:4860::/32"))
	pb.Add(64500, cidr("208.64.200.0/22"))
	_, err := pb.Write(filepath.Join(dir, sources.PrefixFilename))
	require.NoError(t, err)

	require.NoError(t, sources.WriteNetblockDB(filepath.Join(dir, sources.NetblockFilename), []sources.NetblockRecord{
		{Start: net.ParseIP("8.8.8.0"), End: net.ParseIP("8.8.8.255"), Netname: "GOOGLE-DNS", Org: "Google LLC"},
		{Start: net.ParseIP("8.8.4.0"), End: net.ParseIP("8.8.4.255"), Netname: "GOOGLE-DNS-2", Org: "Google LLC"},
		{Start: net.ParseIP("2001:4860::"), End: net.ParseIP("2001:4860:ffff:ffff:ffff:ffff:ffff:ffff"), Netname: "GOOGLE-V6", Org: "Google LLC"},
	}))
	brisbane := map[string]string{"en": "Brisbane"}
	require.NoError(t, fixture.WriteCityDB(filepath.Join(dir, sources.CityFilename), []fixture.CityNetwork{
		{CIDR: "1.0.0.0/24", City: brisbane, Region: "Queensland", Country: "AU"},
		{CIDR: "1.0.1.0/24", City: brisbane, Region: "Queensland", Country: "AU"},
		{CIDR: "2400:1000::/32", City: brisbane, Region: "Queensland", Country: "AU"},
		{CIDR: "1.0.2.0/24", City: brisbane, Region: "California", Country: "US"},
	}))
	return dir
}

// run runs the app with args and returns what it wrote to stdout and stderr.
func run(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	t.Setenv("NO_COLOR", "1")
	var out, errOut bytes.Buffer
	app := newApp()
	app.Writer, app.ErrWriter = &out, &errOut
	app.Reader = strings.NewReader("")
	err = app.Run(append([]string{"asname"}, args...))
	return out.String(), errOut.String(), err
}

func lines(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func TestSearchFindsASNsAndNetblocks(t *testing.T) {
	dir := writeFixtures(t)
	out, _, err := run(t, "search", "--dir", dir, "google")
	require.NoError(t, err)

	got := lines(out)
	require.Len(t, got, 4, out)
	assert.True(t, strings.HasPrefix(got[0], "ASN: AS15169 | "), got[0])
	assert.Contains(t, got[0], " | ")
	assert.Contains(t, got[0], "8.8.8.0/24")
	assert.Contains(t, got[0], "2001:4860::/32")
	assert.Contains(t, out, "GOOGLE-DNS")
	assert.Contains(t, out, "GOOGLE-V6")
}

func TestSearchIsCaseInsensitive(t *testing.T) {
	dir := writeFixtures(t)
	lower, _, err := run(t, "search", "--dir", dir, "google")
	require.NoError(t, err)
	upper, _, err := run(t, "search", "--dir", dir, "GoOgLe")
	require.NoError(t, err)
	assert.Equal(t, lower, upper)
}

func TestSearchFindsASNOnlyOrganization(t *testing.T) {
	dir := writeFixtures(t)
	out, stderr, err := run(t, "search", "--dir", dir, "valve")
	require.NoError(t, err)
	require.Len(t, lines(out), 1, out)
	assert.Contains(t, out, "AS64500")
	assert.Contains(t, out, "208.64.200.0/22")
	assert.Empty(t, stderr)
}

func TestSearchScope(t *testing.T) {
	dir := writeFixtures(t)

	out, _, err := run(t, "search", "--dir", dir, "--asns-only", "google")
	require.NoError(t, err)
	require.Len(t, lines(out), 1, out)
	assert.Contains(t, out, "AS15169")

	out, _, err = run(t, "search", "--dir", dir, "--netblocks-only", "google")
	require.NoError(t, err)
	require.Len(t, lines(out), 3, out)
	for _, l := range lines(out) {
		assert.True(t, strings.HasPrefix(l, "Netblock: "), l)
	}

	_, stderr, err := run(t, "search", "--dir", dir, "--netblocks-only", "valve")
	require.NoError(t, err)
	assert.Contains(t, stderr, `no netblocks found matching "valve"`)

	_, _, err = run(t, "search", "--dir", dir, "--asns-only", "--netblocks-only", "google")
	assert.ErrorContains(t, err, "mutually exclusive")
}

func TestSearchAddressFamily(t *testing.T) {
	dir := writeFixtures(t)

	out, _, err := run(t, "search", "--dir", dir, "--v4-only", "google")
	require.NoError(t, err)
	assert.Contains(t, out, "8.8.8.0/24")
	assert.NotContains(t, out, "2001:4860")

	out, _, err = run(t, "search", "--dir", dir, "--v6-only", "google")
	require.NoError(t, err)
	assert.Contains(t, out, "2001:4860::/32")
	assert.NotContains(t, out, "8.8.")

	_, _, err = run(t, "search", "--dir", dir, "--v4-only", "--v6-only", "google")
	assert.ErrorContains(t, err, "mutually exclusive")
}

func TestSearchLimit(t *testing.T) {
	dir := writeFixtures(t)

	out, _, err := run(t, "search", "--dir", dir, "--netblocks-only", "google")
	require.NoError(t, err)
	assert.Len(t, lines(out), 3, "no --limit is unlimited")

	out, _, err = run(t, "search", "--dir", dir, "--netblocks-only", "--limit", "1", "google")
	require.NoError(t, err)
	assert.Len(t, lines(out), 1, out)

	out, _, err = run(t, "search", "--dir", dir, "-l", "1", "google")
	require.NoError(t, err)
	assert.Len(t, lines(out), 2, "the limit applies to ASNs and netblocks separately: %s", out)
}

func TestSearchJSON(t *testing.T) {
	dir := writeFixtures(t)
	out, _, err := run(t, "search", "--dir", dir, "-j", "google")
	require.NoError(t, err)

	types := map[string]int{}
	for _, l := range lines(out) {
		var v map[string]any
		require.NoError(t, json.Unmarshal([]byte(l), &v), l)
		types[v["type"].(string)]++
	}
	assert.Equal(t, map[string]int{"asn": 1, "netblock": 3}, types)

	_, _, err = run(t, "search", "--dir", dir, "-j", "-p", "google")
	assert.ErrorContains(t, err, "mutually exclusive")
}

func TestSearchWithoutNetblockDB(t *testing.T) {
	dir := writeFixtures(t)
	require.NoError(t, os.Remove(filepath.Join(dir, sources.NetblockFilename)))

	out, stderr, err := run(t, "search", "--dir", dir, "google")
	require.NoError(t, err)
	assert.Len(t, lines(out), 1, out)
	assert.Contains(t, stderr, "netblock database is not present")

	_, _, err = run(t, "search", "--dir", dir, "--netblocks-only", "google")
	assert.ErrorContains(t, err, "netblock database is not present")
}

func TestOrgFlag(t *testing.T) {
	dir := writeFixtures(t)
	out, _, err := run(t, "--dir", dir, "--no-update", "--asns-only", "-O", "google")
	require.NoError(t, err)
	require.Len(t, lines(out), 1, out)
	assert.Contains(t, out, "AS15169")
}

func TestCountry(t *testing.T) {
	dir := writeFixtures(t)

	out, _, err := run(t, "country", "--dir", dir, "AU")
	require.NoError(t, err)
	// 1.0.0.0/24 and 1.0.1.0/24 are adjacent, so they are listed as one block.
	assert.Equal(t, []string{"1.0.0.0/23", "1.1.1.0/24", "2001:db8::/32"}, lines(out))

	byName, _, err := run(t, "country", "--dir", dir, "australia")
	require.NoError(t, err)
	assert.Equal(t, out, byName)

	out, _, err = run(t, "country", "--dir", dir, "--v4-only", "AU")
	require.NoError(t, err)
	assert.Equal(t, []string{"1.0.0.0/23", "1.1.1.0/24"}, lines(out))

	out, _, err = run(t, "country", "--dir", dir, "--v6-only", "AU")
	require.NoError(t, err)
	assert.Equal(t, []string{"2001:db8::/32"}, lines(out))

	_, _, err = run(t, "country", "--dir", dir, "--v4-only", "--v6-only", "AU")
	assert.ErrorContains(t, err, "mutually exclusive")

	_, stderr, err := run(t, "country", "--dir", dir, "NZ")
	require.NoError(t, err)
	assert.Contains(t, stderr, "no blocks registered to NZ")

	_, _, err = run(t, "country", "--dir", dir, "Atlantis")
	assert.Error(t, err)
}

func TestCountryJSON(t *testing.T) {
	dir := writeFixtures(t)
	out, _, err := run(t, "country", "--dir", dir, "-j", "AU", "US")
	require.NoError(t, err)

	got := map[string][]string{}
	for _, l := range lines(out) {
		var v struct {
			Country string `json:"country"`
			CIDR    string `json:"cidr"`
		}
		require.NoError(t, json.Unmarshal([]byte(l), &v), l)
		got[v.Country] = append(got[v.Country], v.CIDR)
	}
	assert.Equal(t, []string{"1.0.0.0/23", "1.1.1.0/24", "2001:db8::/32"}, got["AU"])
	assert.Equal(t, []string{"8.8.8.0/24", "208.64.200.0/22"}, got["US"])
}

func TestLookup(t *testing.T) {
	dir := writeFixtures(t)
	out, _, err := run(t, "--dir", dir, "--no-update", "--no-whois", "8.8.8.8")
	require.NoError(t, err)
	assert.Contains(t, out, "AS15169")
	assert.Contains(t, out, "GOOGLE - Google LLC")

	_, _, err = run(t, "--dir", dir, "--no-update", "-p", "-j", "8.8.8.8")
	assert.ErrorContains(t, err, "mutually exclusive")
}

func TestVersion(t *testing.T) {
	out, _, err := run(t, "version")
	require.NoError(t, err)
	assert.Equal(t, "asname vdev\n", out)
}

func TestCity(t *testing.T) {
	dir := writeFixtures(t)

	out, stderr, err := run(t, "city", "--dir", dir, "Brisbane, AU")
	require.NoError(t, err)
	assert.Equal(t, []string{"1.0.0.0/23", "2400:1000::/32"}, lines(out))
	assert.Empty(t, stderr)

	out, stderr, err = run(t, "city", "--dir", dir, "brisbane")
	require.NoError(t, err)
	assert.Equal(t, []string{"1.0.0.0/23", "2400:1000::/32", "1.0.2.0/24"}, lines(out))
	assert.Contains(t, stderr, `"brisbane" matches 2 places`)
	assert.Contains(t, stderr, "Brisbane, Queensland, AU (2 blocks)")
	assert.Contains(t, stderr, "Brisbane, California, US (1 blocks)")

	out, _, err = run(t, "city", "--dir", dir, "--v4-only", "Brisbane, Queensland")
	require.NoError(t, err)
	assert.Equal(t, []string{"1.0.0.0/23"}, lines(out))

	out, stderr, err = run(t, "city", "--dir", dir, "--v6-only", "Brisbane")
	require.NoError(t, err)
	assert.Equal(t, []string{"2400:1000::/32"}, lines(out))
	assert.Empty(t, stderr, "a place with no blocks left after the filter is not listed")

	out, _, err = run(t, "city", "--dir", dir, "-p", "Brisbane, US")
	require.NoError(t, err)
	assert.Contains(t, out, "Brisbane, California, United States (US)")
	assert.Contains(t, out, "1.0.2.0/24")

	out, _, err = run(t, "city", "--dir", dir, "-j", "Brisbane, US")
	require.NoError(t, err)
	assert.JSONEq(t, `{"city":"Brisbane","region":"California","country":"US","cidr":"1.0.2.0/24","is_v6":false}`, out)

	_, stderr, err = run(t, "city", "--dir", dir, "Atlantis")
	require.NoError(t, err)
	assert.Contains(t, stderr, `no blocks located in "Atlantis"`)

	require.NoError(t, os.Remove(filepath.Join(dir, sources.CityFilename)))
	_, _, err = run(t, "city", "--dir", dir, "Brisbane")
	assert.ErrorContains(t, err, "asname update --city-only")
}
