package sources

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/flyingllama87/asname/pkg/database"
)

// reputationFixtures serves a small copy of each blocklist, in its real format.
func reputationFixtures(t *testing.T) *httptest.Server {
	t.Helper()
	files := map[string]string{
		"/asndrop.json": `{"asn":211486,"rir":"ripencc","domain":"example.net","cc":"SC","asname":"BAD-AS"}
{"type":"metadata","timestamp":1791778442,"size":100,"records":1}
`,
		"/drop_v4.json": `{"cidr":"198.51.100.0/24","sblid":"SBL000001","rir":"arin"}
{"type":"metadata","timestamp":1791778442,"size":100,"records":1}
`,
		"/ipsum.txt":     "# IPsum Threat Intelligence Feed\n#\n77.91.71.90\t7\n77.91.71.91\t7\n77.91.71.43\t3\n198.51.100.7\t2\n",
		"/level2.netset": "# FireHOL\n77.91.71.90/31\n77.91.122.15\n",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testASNDB(t *testing.T, routes map[string]uint32) database.Database {
	t.Helper()
	b := database.NewBuilder()
	for cidr, asn := range routes {
		_, ipNet, err := net.ParseCIDR(cidr)
		require.NoError(t, err)
		require.NoError(t, b.InsertMapping(ipNet, asn))
	}
	db, err := b.Build()
	require.NoError(t, err)
	return db
}

func buildTestReputationDB(t *testing.T) *ReputationDB {
	t.Helper()
	srv := reputationFixtures(t)
	b := newReputationBuilder(context.Background())
	for _, step := range []func() (int, error){
		func() (int, error) { return b.ImportASNDropFrom(srv.URL + "/asndrop.json") },
		func() (int, error) { return b.ImportDropFrom(srv.URL + "/drop_v4.json") },
		func() (int, error) { return b.ImportIPsumFrom(srv.URL + "/ipsum.txt") },
		func() (int, error) { return b.ImportNetsetFrom(srv.URL+"/level2.netset", "firehol-level2") },
	} {
		n, err := step()
		require.NoError(t, err)
		require.Positive(t, n)
	}
	b.Attribute(testASNDB(t, map[string]uint32{
		"77.91.71.0/24":   211486,
		"77.91.122.0/24":  211486,
		"198.51.100.0/24": 64500,
	}))

	data, err := b.Marshal(time.Unix(1791778442, 0))
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), ReputationFilename)
	require.NoError(t, os.WriteFile(path, data, 0o644))
	db, err := OpenReputationDB(path)
	require.NoError(t, err)
	return db
}

func TestReputationLookupAddress(t *testing.T) {
	db := buildTestReputationDB(t)

	assert.Equal(t, []string{"firehol-level2", "ipsum:7"}, db.Lookup(net.ParseIP("77.91.71.90")))
	assert.Equal(t, []string{"ipsum:3"}, db.Lookup(net.ParseIP("77.91.71.43")))
	assert.Nil(t, db.Lookup(net.ParseIP("77.91.71.44")))
	assert.Nil(t, db.Lookup(net.ParseIP("192.0.2.1")))
	assert.Equal(t, time.Unix(1791778442, 0), db.Built)
}

func TestReputationCoveringPrefixTagsInherited(t *testing.T) {
	db := buildTestReputationDB(t)

	// 198.51.100.7 is in IPsum and inside a DROP /24; the more specific
	// entry must still report the DROP listing.
	assert.Equal(t, []string{"ipsum:2", "spamhaus-drop:SBL000001"}, db.Lookup(net.ParseIP("198.51.100.7")))
	assert.Equal(t, []string{"spamhaus-drop:SBL000001"}, db.Lookup(net.ParseIP("198.51.100.200")))
}

func TestReputationASN(t *testing.T) {
	db := buildTestReputationDB(t)

	// .90 and .91 are on both lists but are counted once each.
	bad := db.LookupASN(211486)
	assert.Equal(t, ASNReputation{ASNDrop: true, ListedIPs: 4, MaxLists: 7}, bad)
	assert.True(t, bad.Listed())

	drop := db.LookupASN(64500)
	assert.Equal(t, uint32(1), drop.DropPrefixes)
	assert.Equal(t, uint32(1), drop.ListedIPs)

	assert.False(t, db.LookupASN(15169).Listed())
}

func TestASNReputationString(t *testing.T) {
	r := ASNReputation{ASNDrop: true, ListedIPs: 11, MaxLists: 7, AnnouncedIPv4: 2048}
	assert.Equal(t, "Spamhaus ASN-DROP; 11 listed IPs (0.54% of 2048 announced IPv4), max 7 lists", r.String())
	assert.Equal(t, "not listed", ASNReputation{}.String())
	assert.Equal(t, "1 Spamhaus DROP prefix", ASNReputation{DropPrefixes: 1}.String())
}

func TestCountIPv4(t *testing.T) {
	assert.Equal(t, uint64(512), CountIPv4([]string{"77.91.71.0/24", "77.91.71.128/25", "77.91.122.0/24", "2001:db8::/32"}))
	assert.Equal(t, uint64(0), CountIPv4(nil))
}

func TestOpenReputationDBRejectsOtherFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.db")
	require.NoError(t, os.WriteFile(path, []byte("ASNCAT\x00\x01 not a reputation database at all"), 0o644))
	_, err := OpenReputationDB(path)
	require.Error(t, err)
}
