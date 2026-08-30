package sources

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
)

func buildTestNetblockDB(t *testing.T, add func(*netblockBuilder)) string {
	t.Helper()

	b := newNetblockBuilder()
	add(b)
	path := filepath.Join(t.TempDir(), NetblockFilename)
	_, err := b.write(path)
	require.NoError(t, err)
	return path
}

func lookupNetblock(t *testing.T, db *NetblockDB, ip string) string {
	t.Helper()

	info, err := db.Lookup(net.ParseIP(ip))
	require.NoError(t, err)
	return info.String()
}

func TestNetblockLookupPrefersTheMostSpecificRange(t *testing.T) {
	path := buildTestNetblockDB(t, func(b *netblockBuilder) {
		b.add(net.ParseIP("183.177.52.0"), net.ParseIP("183.177.55.255"), "EQUINIX-AU", "Equinix Australia Pty Ltd")
		b.add(net.ParseIP("183.177.54.128"), net.ParseIP("183.177.54.135"), "SISS-SY4", "Secure Internet Storage Solutions")
	})

	db, err := OpenNetblockDB(path)
	require.NoError(t, err)
	defer db.Close()

	require.Equal(t, "SISS-SY4 (Secure Internet Storage Solutions)", lookupNetblock(t, db, "183.177.54.135"))
	require.Equal(t, "SISS-SY4 (Secure Internet Storage Solutions)", lookupNetblock(t, db, "183.177.54.128"))
	require.Equal(t, "EQUINIX-AU (Equinix Australia Pty Ltd)", lookupNetblock(t, db, "183.177.54.127"))
	require.Equal(t, "EQUINIX-AU (Equinix Australia Pty Ltd)", lookupNetblock(t, db, "183.177.54.136"))
	require.Equal(t, "", lookupNetblock(t, db, "183.177.56.0"))
	require.Equal(t, "", lookupNetblock(t, db, "8.8.8.8"))
}

func TestNetblockLookupIPv6(t *testing.T) {
	path := buildTestNetblockDB(t, func(b *netblockBuilder) {
		start, end, ok := ParseNetRange("2001:db8::/32")
		require.True(t, ok)
		b.add(start, end, "EXAMPLE-V6", "Example Ltd")
	})

	db, err := OpenNetblockDB(path)
	require.NoError(t, err)
	defer db.Close()

	require.Equal(t, "EXAMPLE-V6 (Example Ltd)", lookupNetblock(t, db, "2001:db8::1"))
	require.Equal(t, "EXAMPLE-V6 (Example Ltd)", lookupNetblock(t, db, "2001:db8:ffff::ffff"))
	require.Equal(t, "", lookupNetblock(t, db, "2001:db9::1"))
}

func TestNetblockLookupSeparatesAddressFamilies(t *testing.T) {
	path := buildTestNetblockDB(t, func(b *netblockBuilder) {
		b.add(net.ParseIP("8.8.8.0"), net.ParseIP("8.8.8.255"), "GOOGLE-V4", "Google LLC")
		start, end, _ := ParseNetRange("2001:4860::/32")
		b.add(start, end, "GOOGLE-V6", "Google LLC")
	})

	db, err := OpenNetblockDB(path)
	require.NoError(t, err)
	defer db.Close()

	require.Equal(t, "GOOGLE-V4 (Google LLC)", lookupNetblock(t, db, "8.8.8.8"))
	require.Equal(t, "GOOGLE-V6 (Google LLC)", lookupNetblock(t, db, "2001:4860::8888"))

	four, err := db.Lookup(net.IP{8, 8, 8, 8})
	require.NoError(t, err)
	sixteen, err := db.Lookup(net.ParseIP("8.8.8.8").To16())
	require.NoError(t, err)
	require.Equal(t, four, sixteen)
}

func TestNetblockLookupAtEndOfAddressSpace(t *testing.T) {
	path := buildTestNetblockDB(t, func(b *netblockBuilder) {
		b.add(net.ParseIP("255.255.255.0"), net.ParseIP("255.255.255.255"), "LAST-V4", "")
		start, end, _ := ParseNetRange("ffff:ffff::/32")
		b.add(start, end, "LAST-V6", "")
	})

	db, err := OpenNetblockDB(path)
	require.NoError(t, err)
	defer db.Close()

	require.Equal(t, "LAST-V4", lookupNetblock(t, db, "255.255.255.255"))
	require.Equal(t, "LAST-V6", lookupNetblock(t, db, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
}

func TestOpenNetblockDBRejectsForeignFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), NetblockFilename)
	require.NoError(t, os.WriteFile(path, make([]byte, 128), 0o644))

	_, err := OpenNetblockDB(path)
	require.ErrorContains(t, err, "not an asname netblock database")
}

func TestOpenNetblockDBRejectsTruncatedFile(t *testing.T) {
	path := buildTestNetblockDB(t, func(b *netblockBuilder) {
		b.add(net.ParseIP("8.8.8.0"), net.ParseIP("8.8.8.255"), "GOOGLE", "Google LLC")
	})
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data[:len(data)-4], 0o644))

	_, err = OpenNetblockDB(path)
	require.ErrorContains(t, err, "truncated database")
}

func TestFlattenClipsPartiallyOverlappingRanges(t *testing.T) {
	segs := Flatten([]interval[uint32]{
		{start: 100, end: 200, netname: 1},
		{start: 150, end: 300, netname: 2},
	}, CompareUint32, IncUint32)

	require.Equal(t, []Segment[uint32]{
		{Start: 100, Netname: 1},
		{Start: 150, Netname: 2},
		{Start: 201},
	}, segs)
}

func TestFlattenMergesIdenticalNeighbours(t *testing.T) {
	segs := Flatten([]interval[uint32]{
		{start: 10, end: 19, netname: 1, org: 2},
		{start: 20, end: 29, netname: 1, org: 2},
	}, CompareUint32, IncUint32)

	require.Equal(t, []Segment[uint32]{
		{Start: 10, Netname: 1, Org: 2},
		{Start: 30},
	}, segs)
}

func TestNetblockInfoString(t *testing.T) {
	require.Equal(t, "SISS-SY4 (Secure Internet Storage Solutions)",
		NetblockInfo{Netname: "SISS-SY4", Org: "Secure Internet Storage Solutions"}.String())
	require.Equal(t, "SISS-SY4", NetblockInfo{Netname: "SISS-SY4"}.String())
	require.Equal(t, "Secure Internet Storage Solutions",
		NetblockInfo{Org: "Secure Internet Storage Solutions"}.String())
	require.Equal(t, "Example Ltd", NetblockInfo{Netname: "Example Ltd", Org: "EXAMPLE LTD"}.String())
	require.True(t, NetblockInfo{}.Empty())
}

func TestParseNetRange(t *testing.T) {
	for _, tc := range []struct{ in, start, end string }{
		{"183.177.54.128 - 183.177.54.135", "183.177.54.128", "183.177.54.135"},
		{"183.177.54.128-183.177.54.135", "183.177.54.128", "183.177.54.135"},
		{"8.8.8.0/24", "8.8.8.0", "8.8.8.255"},
		{"2001:db8::/32", "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"},
	} {
		start, end, ok := ParseNetRange(tc.in)
		require.True(t, ok, tc.in)
		require.Equal(t, tc.start, start.String(), tc.in)
		require.Equal(t, tc.end, end.String(), tc.in)
	}

	for _, in := range []string{"", "not a range", "2.152.0/22", "8.8.8.0 - "} {
		_, _, ok := ParseNetRange(in)
		require.False(t, ok, in)
	}
}

func TestCleanValue(t *testing.T) {
	require.Equal(t, "Example Ltd", CleanValue("   Example Ltd  "))
	require.Equal(t, "EU", CleanValue("EU # Country is really world wide"))
	require.Equal(t, "São Paulo", CleanValue("S\xe3o Paulo"))
	require.Equal(t, "São Paulo", CleanValue("São Paulo"))
}

func writeDumpFixture(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "dump.txt")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	return path
}

func TestScanDumpParsesRPSLObjects(t *testing.T) {
	path := writeDumpFixture(t, `%  This is the APNIC whois database

inetnum:        183.177.54.128 - 183.177.54.135
netname:        SISS-SY4
descr:          Secure Internet Storage Solutions
descr:          Suite 2305, 5 Lawson Street,
country:        AU
mnt-by:         MAINT-EQUINIX-AU

inetnum:        202.6.91.0 - 202.6.91.255
netname:        NLA-AU
org:            ORG-NLOA1-AP
remarks:        wrapped attribute follows
descr:          National Library
                of Australia
`)

	var got [][]attr
	require.NoError(t, scanDump(path, func(attrs []attr) error {
		got = append(got, append([]attr(nil), attrs...))
		return nil
	}, "inetnum", "netname", "descr", "org"))

	require.Len(t, got, 2)
	require.Equal(t, "183.177.54.128 - 183.177.54.135", attrValue(got[0], "inetnum"))
	require.Equal(t, "SISS-SY4", attrValue(got[0], "netname"))
	require.Equal(t, "Secure Internet Storage Solutions", attrValue(got[0], "descr"))
	require.Equal(t, "", attrValue(got[0], "org"))

	require.Equal(t, "ORG-NLOA1-AP", attrValue(got[1], "org"))
	require.Equal(t, "National Library of Australia", attrValue(got[1], "descr"))
}

func TestScanDumpParsesARINObjects(t *testing.T) {
	path := writeDumpFixture(t, `OrgID:          GOGL
OrgName:        Google LLC

NetHandle:      NET-8-8-8-0-1
OrgID:          GOGL
NetRange:       8.8.8.0 - 8.8.8.255
NetName:        GOGL-8-8-8
`)

	orgs := map[string]string{}
	require.NoError(t, scanDump(path, func(attrs []attr) error {
		if handle, name := attrValue(attrs, "orgid"), attrValue(attrs, "orgname"); handle != "" && name != "" {
			orgs[handle] = name
		}
		return nil
	}, arinSchema.orgKey, arinSchema.orgNameKey))
	require.Equal(t, map[string]string{"GOGL": "Google LLC"}, orgs)

	var ranges []string
	require.NoError(t, scanDump(path, func(attrs []attr) error {
		if r := attrValue(attrs, "netrange"); r != "" {
			ranges = append(ranges, r+" "+attrValue(attrs, "netname")+" "+orgs[attrValue(attrs, "orgid")])
		}
		return nil
	}, "netrange", "netname", "orgid"))
	require.Equal(t, []string{"8.8.8.0 - 8.8.8.255 GOGL-8-8-8 Google LLC"}, ranges)
}

func TestUpdateHonoursTheLookupOptInFlags(t *testing.T) {
	for _, tc := range []struct{ name, flag, only string }{
		{"netblock", "netblock", "netblock-only"},
		{"city", "city", "city-only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, args := range [][]string{
				{"asname", "-" + tc.flag[:1], "update"},
				{"asname", "--" + tc.flag, "update"},
				{"asname", "update", "--" + tc.only},
			} {
				asked := false
				app := &cli.App{
					Flags: []cli.Flag{
						&cli.BoolFlag{Name: tc.flag, Aliases: []string{tc.flag[:1]}},
					},
					Commands: []*cli.Command{{
						Name:  "update",
						Flags: []cli.Flag{&cli.BoolFlag{Name: tc.only}},
						Action: func(ctx *cli.Context) error {
							asked = ctx.Bool(tc.only) || ctx.Bool(tc.flag)
							return nil
						},
					}},
				}
				require.NoError(t, app.Run(args))
				require.True(t, asked, "%v should ask for the %s database", args, tc.name)
			}
		})
	}
}

func TestIsPlaceholderRange(t *testing.T) {
	require.True(t, IsPlaceholderRange("IANA-NETBLOCK-8", "This network range is not allocated to APNIC."))
	require.True(t, IsPlaceholderRange("NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK", "IPv4 address block not managed by the RIPE NCC"))
	require.True(t, IsPlaceholderRange("ARIN-CIDR-BLOCK", "Chunk of address space not allocated to APNIC"))
	require.True(t, IsPlaceholderRange("ROOT", "Root inet6num object"))

	require.False(t, IsPlaceholderRange("SISS-SY4", "Secure Internet Storage Solutions"))
	require.False(t, IsPlaceholderRange("ROOTSCOMM-SG", "Roots Communications Pte Ltd"))
	require.False(t, IsPlaceholderRange("NTT-NON-AU", "NTT Australia"))
	require.False(t, IsPlaceholderRange("DIALUP-POOL", "Dynamic addresses, not assigned to a specific client"))
}

func TestNetblockBuilderSkipsWholeAddressSpace(t *testing.T) {
	path := buildTestNetblockDB(t, func(b *netblockBuilder) {
		b.add(net.ParseIP("0.0.0.0"), net.ParseIP("255.255.255.255"), "IANA-BLK", "The whole IPv4 address space")
		b.add(net.ParseIP("8.8.8.0"), net.ParseIP("8.8.8.255"), "GOOGLE", "Google LLC")
	})

	db, err := OpenNetblockDB(path)
	require.NoError(t, err)
	defer db.Close()

	require.Equal(t, "GOOGLE (Google LLC)", lookupNetblock(t, db, "8.8.8.8"))
	require.Equal(t, "", lookupNetblock(t, db, "1.1.1.1"))
}
