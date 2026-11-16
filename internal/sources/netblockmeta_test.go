package sources

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRPSLMeta(t *testing.T) {
	// The two blocks from the 16 Nov 2026 analysis, as the RIPE dump has them.
	path := writeDumpFixture(t, `inetnum:        92.113.115.0 - 92.113.115.255
netname:        NET-92-113-115-0-24
country:        PL
geofeed:        https://geofeed.ipxo.com/geofeed.txt
org:            ORG-CU61-RIPE
mnt-by:         netutils-mnt
created:        2025-01-20T15:57:39Z

inetnum:        46.16.34.128 - 46.16.34.255
org:            ORG-AS895-RIPE
netname:        AlexHost
country:        US
mnt-by:         VPLAB-MNT
created:        2026-04-15T10:18:42Z

inetnum:        10.0.0.0 - 10.0.0.255
netname:        LEASED-BY-GEOFEED
country:        eu
geofeed:        https://www.prefixbroker.com/geofeed.csv
`)
	orgs := map[string]string{"ORG-CU61-RIPE": "Company 64d3452aYKe9ygar", "ORG-AS895-RIPE": "ALEXHOST SRL"}
	orgMnt := map[string]string{"ORG-CU61-RIPE": "netutils-mnt", "ORG-AS895-RIPE": "ALEXHOST-MNT"}

	var got []NetblockMeta
	require.NoError(t, scanDump(path, func(attrs []attr) error {
		ref := attrValue(attrs, "org")
		got = append(got, rpslMeta(attrs, orgs[ref], orgMnt[ref]))
		return nil
	}, "inetnum", "org", "country", "created", "mnt-by", "geofeed"))

	require.Equal(t, []NetblockMeta{
		{Country: "PL", Created: "2025-01-20", Tags: []string{"leased:ipxo", "anonymised-holder"}},
		{Country: "US", Created: "2026-04-15"},
		{Tags: []string{"leased:prefixbroker"}},
	}, got)
}

func TestNetblockMetaRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "netblock.db")
	require.NoError(t, WriteNetblockDB(path, []NetblockRecord{
		{Start: net.ParseIP("46.16.0.0"), End: net.ParseIP("46.16.255.255"), Netname: "CLOUDATA", Meta: NetblockMeta{Country: "RU"}},
		{Start: net.ParseIP("46.16.34.128"), End: net.ParseIP("46.16.34.255"), Netname: "AlexHost", Org: "ALEXHOST SRL",
			Meta: NetblockMeta{Country: "US", Created: "2026-04-15", Tags: []string{"leased:ipxo", "anonymised-holder"}}},
		// Same names, different metadata: must stay separate segments.
		{Start: net.ParseIP("46.16.35.0"), End: net.ParseIP("46.16.35.255"), Netname: "AlexHost", Org: "ALEXHOST SRL",
			Meta: NetblockMeta{Country: "MD"}},
	}))
	db, err := OpenNetblockDB(path)
	require.NoError(t, err)
	defer db.Close()

	info, err := db.Lookup(net.ParseIP("46.16.34.229"))
	require.NoError(t, err)
	require.Equal(t, "AlexHost (ALEXHOST SRL)", info.String())
	require.Equal(t, NetblockMeta{Country: "US", Created: "2026-04-15", Tags: []string{"leased:ipxo", "anonymised-holder"}}, info.NetblockMeta)

	info, err = db.Lookup(net.ParseIP("46.16.35.1"))
	require.NoError(t, err)
	require.Equal(t, "MD", info.Country)

	info, err = db.Lookup(net.ParseIP("46.16.36.1"))
	require.NoError(t, err)
	require.Equal(t, NetblockInfo{Netname: "CLOUDATA", NetblockMeta: NetblockMeta{Country: "RU"}}, info)

	res, err := db.SearchOrg("alexhost", NetblockSearchOptions{})
	require.NoError(t, err)
	require.Len(t, res, 2)
	require.Equal(t, []string{"46.16.34.128/25"}, res[0].CIDRs)
}

func TestNetblockReadsVersion1(t *testing.T) {
	// A version 1 file: header, one 12-byte IPv4 record, the string table.
	blob := append([]byte{0}, "OLD-NET\x00"...)
	var hdr [netblockHeaderSize]byte
	copy(hdr[:8], netblockMagicV1)
	binary.LittleEndian.PutUint32(hdr[16:20], 1)
	binary.LittleEndian.PutUint64(hdr[24:32], netblockHeaderSize+netblockSeg4SizeV1)
	binary.LittleEndian.PutUint64(hdr[32:40], uint64(len(blob)))
	var rec [netblockSeg4SizeV1]byte
	binary.LittleEndian.PutUint32(rec[0:4], binary.BigEndian.Uint32(net.ParseIP("10.0.0.0").To4()))
	binary.LittleEndian.PutUint32(rec[4:8], 1)
	data := append(append(hdr[:], rec[:]...), blob...)

	path := filepath.Join(t.TempDir(), "netblock.db")
	require.NoError(t, os.WriteFile(path, data, 0o644))
	db, err := OpenNetblockDB(path)
	require.NoError(t, err)
	defer db.Close()

	info, err := db.Lookup(net.ParseIP("10.1.2.3"))
	require.NoError(t, err)
	require.Equal(t, NetblockInfo{Netname: "OLD-NET"}, info)
}
