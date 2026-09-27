package sources

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/flyingllama87/asname/pkg/database"
)

// gzippedRIB is a gzipped MRT dump with one TABLE_DUMP_V2 RIB record per
// prefix, each originated by origin.
func gzippedRIB(t *testing.T, origin uint32, prefixes ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	for _, p := range prefixes {
		_, ipNet, err := net.ParseCIDR(p)
		require.NoError(t, err)
		ones, _ := ipNet.Mask.Size()
		subtype := uint16(2) // RIB_IPV4_UNICAST
		ip := []byte(ipNet.IP.To4())
		if ip == nil {
			subtype = 4 // RIB_IPV6_UNICAST
			ip = ipNet.IP.To16()
		}
		asPath := binary.BigEndian.AppendUint32([]byte{2, 1}, origin)
		attr := append([]byte{0x40, 2, byte(len(asPath))}, asPath...)
		body := append([]byte{0, 0, 0, 1, byte(ones)}, ip[:(ones+7)/8]...)
		body = append(body, 0, 1, 0, 0, 0, 0, 0, 0)
		body = binary.BigEndian.AppendUint16(body, uint16(len(attr)))
		body = append(body, attr...)

		hdr := make([]byte, 12)
		binary.BigEndian.PutUint16(hdr[4:], 13)
		binary.BigEndian.PutUint16(hdr[6:], subtype)
		binary.BigEndian.PutUint32(hdr[8:], uint32(len(body)))
		gz.Write(hdr)
		gz.Write(body)
	}
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// ribArchive serves a listing naming dump, and dump itself, counting the
// requests for the dump.
func ribArchive(t *testing.T, dump string, body []byte) (*httptest.Server, *int) {
	t.Helper()
	fetched := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, dump) {
			fetched++
			w.Write(body)
			return
		}
		fmt.Fprintf(w, "<a href=\"%s\">%s</a>\n", dump, dump)
	}))
	t.Cleanup(srv.Close)
	return srv, &fetched
}

// dualArchive stands in for route-views2 (IPv4, plus a stray IPv6 route as the
// RIS dumps carry) and its route-views6 companion.
func dualArchive(t *testing.T) (v6Fetched *int) {
	t.Helper()
	v4, _ := ribArchive(t, "bview.20260911.0000.gz", gzippedRIB(t, 64500, "192.0.2.0/24", "2001:db8:ffff::/48"))
	v6, v6Fetched := ribArchive(t, "bview.20260911.0000.gz", gzippedRIB(t, 64501, "2001:db8::/32"))

	restore := ribSources
	t.Cleanup(func() { ribSources = restore })
	dump := regexp.MustCompile(`bview\.[0-9]{8}\.[0-9]{4}\.gz`)
	ribSources = []ribSource{{
		name: "v4", listing: v4.URL + "/%s/", filename: dump,
		ipv6: &ribSource{name: "v6", listing: v6.URL + "/%s/", filename: dump},
	}}
	return v6Fetched
}

func ipv6Config(t *testing.T) Config {
	dir := t.TempDir()
	return Config{
		DBPath:     filepath.Join(dir, DBFilename),
		PrefixPath: filepath.Join(dir, PrefixFilename),
		CachePath:  filepath.Join(dir, CacheDirName),
		IPv6Path:   filepath.Join(dir, IPv6MarkerFilename),
	}
}

func lookupASN(t *testing.T, cfg Config, ip string) (uint32, bool) {
	t.Helper()
	f, err := os.Open(cfg.DBPath)
	require.NoError(t, err)
	defer f.Close()
	db, err := database.NewFromDump(f)
	require.NoError(t, err)
	as, err := db.Lookup(net.ParseIP(ip))
	if err == database.ErrNotFound {
		return 0, false
	}
	require.NoError(t, err)
	return as.Number, true
}

func TestUpdateDatabaseLeavesIPv6OutByDefault(t *testing.T) {
	v6Fetched := dualArchive(t)
	cfg := ipv6Config(t)
	require.NoError(t, os.WriteFile(cfg.IPv6Path, nil, 0o644), "an update without IPv6 must clear an earlier opt-in")

	require.NoError(t, UpdateDatabase(context.Background(), cfg, ""))

	require.Zero(t, *v6Fetched, "the IPv6 companion must not be downloaded")
	asn, ok := lookupASN(t, cfg, "192.0.2.1")
	require.True(t, ok)
	require.Equal(t, uint32(64500), asn)
	_, ok = lookupASN(t, cfg, "2001:db8:ffff::1")
	require.False(t, ok, "IPv6 routes in a mixed dump must be dropped")

	pdb, err := OpenPrefixDB(cfg.PrefixPath)
	require.NoError(t, err)
	defer pdb.Close()
	pr, err := pdb.Lookup(64500)
	require.NoError(t, err)
	require.Empty(t, pr.IPv6)

	require.False(t, IPv6RoutesEnabled(cfg))
}

func TestUpdateDatabaseImportsIPv6WhenEnabled(t *testing.T) {
	v6Fetched := dualArchive(t)
	cfg := ipv6Config(t)
	cfg.IPv6 = true

	require.NoError(t, UpdateDatabase(context.Background(), cfg, ""))

	require.Equal(t, 1, *v6Fetched)
	for ip, want := range map[string]uint32{"192.0.2.1": 64500, "2001:db8::1": 64501, "2001:db8:ffff::1": 64500} {
		asn, ok := lookupASN(t, cfg, ip)
		require.True(t, ok, ip)
		require.Equal(t, want, asn, ip)
	}

	pdb, err := OpenPrefixDB(cfg.PrefixPath)
	require.NoError(t, err)
	defer pdb.Close()
	pr, err := pdb.Lookup(64501)
	require.NoError(t, err)
	require.Equal(t, []string{"2001:db8::/32"}, pr.IPv6)

	require.True(t, IPv6RoutesEnabled(cfg), "later updates must keep importing IPv6")
}
