package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// buildTestNetblockDB writes a database holding ranges and returns its path.
func buildTestNetblockDB(t *testing.T, add func(*netblockBuilder)) string {
	t.Helper()

	b := newNetblockBuilder()
	add(b)
	path := filepath.Join(t.TempDir(), netblockFilename)
	_, err := b.write(path)
	require.NoError(t, err)
	return path
}

func lookupNetblock(t *testing.T, db *netblockDB, ip string) string {
	t.Helper()

	info, err := db.Lookup(net.ParseIP(ip))
	require.NoError(t, err)
	return info.String()
}

// A small assignment inside a large allocation is what makes this database
// worth having: the ASN says Equinix, the /29 says who actually holds it.
func TestNetblockLookupPrefersTheMostSpecificRange(t *testing.T) {
	path := buildTestNetblockDB(t, func(b *netblockBuilder) {
		b.add(net.ParseIP("183.177.52.0"), net.ParseIP("183.177.55.255"), "EQUINIX-AU", "Equinix Australia Pty Ltd")
		b.add(net.ParseIP("183.177.54.128"), net.ParseIP("183.177.54.135"), "SISS-SY4", "Secure Internet Storage Solutions")
	})

	db, err := openNetblockDB(path)
	require.NoError(t, err)
	defer db.Close()

	// Inside the assignment.
	require.Equal(t, "SISS-SY4 (Secure Internet Storage Solutions)", lookupNetblock(t, db, "183.177.54.135"))
	require.Equal(t, "SISS-SY4 (Secure Internet Storage Solutions)", lookupNetblock(t, db, "183.177.54.128"))
	// Either side of it the enclosing allocation takes over again.
	require.Equal(t, "EQUINIX-AU (Equinix Australia Pty Ltd)", lookupNetblock(t, db, "183.177.54.127"))
	require.Equal(t, "EQUINIX-AU (Equinix Australia Pty Ltd)", lookupNetblock(t, db, "183.177.54.136"))
	// Outside every range.
	require.Equal(t, "", lookupNetblock(t, db, "183.177.56.0"))
	require.Equal(t, "", lookupNetblock(t, db, "8.8.8.8"))
}

func TestNetblockLookupIPv6(t *testing.T) {
	path := buildTestNetblockDB(t, func(b *netblockBuilder) {
		start, end, ok := parseNetRange("2001:db8::/32")
		require.True(t, ok)
		b.add(start, end, "EXAMPLE-V6", "Example Ltd")
	})

	db, err := openNetblockDB(path)
	require.NoError(t, err)
	defer db.Close()

	require.Equal(t, "EXAMPLE-V6 (Example Ltd)", lookupNetblock(t, db, "2001:db8::1"))
	require.Equal(t, "EXAMPLE-V6 (Example Ltd)", lookupNetblock(t, db, "2001:db8:ffff::ffff"))
	require.Equal(t, "", lookupNetblock(t, db, "2001:db9::1"))
}

// An IPv4 address must not be answered from the IPv6 table or vice versa, and
// the 4-byte form the resolver returns must behave like the 16-byte one.
func TestNetblockLookupSeparatesAddressFamilies(t *testing.T) {
	path := buildTestNetblockDB(t, func(b *netblockBuilder) {
		b.add(net.ParseIP("8.8.8.0"), net.ParseIP("8.8.8.255"), "GOOGLE-V4", "Google LLC")
		start, end, _ := parseNetRange("2001:4860::/32")
		b.add(start, end, "GOOGLE-V6", "Google LLC")
	})

	db, err := openNetblockDB(path)
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

// A range covering the very last address must not wrap when the sweep closes
// it, and must still be found.
func TestNetblockLookupAtEndOfAddressSpace(t *testing.T) {
	path := buildTestNetblockDB(t, func(b *netblockBuilder) {
		b.add(net.ParseIP("255.255.255.0"), net.ParseIP("255.255.255.255"), "LAST-V4", "")
		start, end, _ := parseNetRange("ffff:ffff::/32")
		b.add(start, end, "LAST-V6", "")
	})

	db, err := openNetblockDB(path)
	require.NoError(t, err)
	defer db.Close()

	require.Equal(t, "LAST-V4", lookupNetblock(t, db, "255.255.255.255"))
	require.Equal(t, "LAST-V6", lookupNetblock(t, db, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
}

func TestOpenNetblockDBRejectsForeignFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), netblockFilename)
	require.NoError(t, os.WriteFile(path, make([]byte, 128), 0o644))

	_, err := openNetblockDB(path)
	require.ErrorContains(t, err, "not an asname netblock database")
}

func TestOpenNetblockDBRejectsTruncatedFile(t *testing.T) {
	path := buildTestNetblockDB(t, func(b *netblockBuilder) {
		b.add(net.ParseIP("8.8.8.0"), net.ParseIP("8.8.8.255"), "GOOGLE", "Google LLC")
	})
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data[:len(data)-4], 0o644))

	_, err = openNetblockDB(path)
	require.ErrorContains(t, err, "truncated database")
}

func TestFlattenClipsPartiallyOverlappingRanges(t *testing.T) {
	// The second range starts inside the first but runs past its end, which
	// registry data should never contain. It must be clipped rather than
	// leaving the sweep to unwind the two out of order.
	segs := flatten([]interval[uint32]{
		{start: 100, end: 200, netname: 1},
		{start: 150, end: 300, netname: 2},
	}, compareUint32, incUint32)

	require.Equal(t, []segment[uint32]{
		{start: 100, netname: 1},
		{start: 150, netname: 2},
		{start: 201},
	}, segs)
}

func TestFlattenMergesIdenticalNeighbours(t *testing.T) {
	segs := flatten([]interval[uint32]{
		{start: 10, end: 19, netname: 1, org: 2},
		{start: 20, end: 29, netname: 1, org: 2},
	}, compareUint32, incUint32)

	// Two adjacent ranges naming the same thing are one segment, and the gap
	// after them is recorded so the second range does not run on forever.
	require.Equal(t, []segment[uint32]{
		{start: 10, netname: 1, org: 2},
		{start: 30},
	}, segs)
}

func TestNetblockInfoString(t *testing.T) {
	require.Equal(t, "SISS-SY4 (Secure Internet Storage Solutions)",
		netblockInfo{netname: "SISS-SY4", org: "Secure Internet Storage Solutions"}.String())
	require.Equal(t, "SISS-SY4", netblockInfo{netname: "SISS-SY4"}.String())
	require.Equal(t, "Secure Internet Storage Solutions",
		netblockInfo{org: "Secure Internet Storage Solutions"}.String())
	// A registry that repeats itself should not be printed twice.
	require.Equal(t, "Example Ltd", netblockInfo{netname: "Example Ltd", org: "EXAMPLE LTD"}.String())
	require.True(t, netblockInfo{}.empty())
}

func TestParseNetRange(t *testing.T) {
	for _, tc := range []struct{ in, start, end string }{
		{"183.177.54.128 - 183.177.54.135", "183.177.54.128", "183.177.54.135"},
		{"183.177.54.128-183.177.54.135", "183.177.54.128", "183.177.54.135"},
		{"8.8.8.0/24", "8.8.8.0", "8.8.8.255"},
		{"2001:db8::/32", "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"},
	} {
		start, end, ok := parseNetRange(tc.in)
		require.True(t, ok, tc.in)
		require.Equal(t, tc.start, start.String(), tc.in)
		require.Equal(t, tc.end, end.String(), tc.in)
	}

	for _, in := range []string{"", "not a range", "2.152.0/22", "8.8.8.0 - "} {
		_, _, ok := parseNetRange(in)
		require.False(t, ok, in)
	}
}

func TestCleanValue(t *testing.T) {
	require.Equal(t, "Example Ltd", cleanValue("   Example Ltd  "))
	// RPSL treats the rest of the line after '#' as a comment.
	require.Equal(t, "EU", cleanValue("EU # Country is really world wide"))
	// Some registries still publish Latin-1, which must not reach the terminal
	// as invalid UTF-8.
	require.Equal(t, "São Paulo", cleanValue("S\xe3o Paulo"))
	require.Equal(t, "São Paulo", cleanValue("São Paulo"))
}

// writeDumpFixture writes a whois dump for scanDump to read.
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
	// Only the first descr is kept: the ones after it are the postal address.
	require.Equal(t, "Secure Internet Storage Solutions", attrValue(got[0], "descr"))
	require.Equal(t, "", attrValue(got[0], "org"))

	require.Equal(t, "ORG-NLOA1-AP", attrValue(got[1], "org"))
	// A continuation line belongs to the attribute above it.
	require.Equal(t, "National Library of Australia", attrValue(got[1], "descr"))
}

// ARIN's bulk dump is the same shape with its own attribute names, so the same
// parser reads it. It cannot be fetched without a signed agreement, so this
// fixture stands in for the format.
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

func TestIsPlaceholderRange(t *testing.T) {
	// Each registry answers for ranges it does not hold, and says so.
	require.True(t, isPlaceholderRange("IANA-NETBLOCK-8", "This network range is not allocated to APNIC."))
	require.True(t, isPlaceholderRange("NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK", "IPv4 address block not managed by the RIPE NCC"))
	require.True(t, isPlaceholderRange("ARIN-CIDR-BLOCK", "Chunk of address space not allocated to APNIC"))
	require.True(t, isPlaceholderRange("ROOT", "Root inet6num object"))

	// Real assignments that merely look like one of the patterns must survive.
	require.False(t, isPlaceholderRange("SISS-SY4", "Secure Internet Storage Solutions"))
	require.False(t, isPlaceholderRange("ROOTSCOMM-SG", "Roots Communications Pte Ltd"))
	require.False(t, isPlaceholderRange("NTT-NON-AU", "NTT Australia"))
	require.False(t, isPlaceholderRange("DIALUP-POOL", "Dynamic addresses, not assigned to a specific client"))
}

// The registries all keep a placeholder covering the whole address space, which
// would otherwise name every unassigned address after IANA.
func TestNetblockBuilderSkipsWholeAddressSpace(t *testing.T) {
	path := buildTestNetblockDB(t, func(b *netblockBuilder) {
		b.add(net.ParseIP("0.0.0.0"), net.ParseIP("255.255.255.255"), "IANA-BLK", "The whole IPv4 address space")
		b.add(net.ParseIP("8.8.8.0"), net.ParseIP("8.8.8.255"), "GOOGLE", "Google LLC")
	})

	db, err := openNetblockDB(path)
	require.NoError(t, err)
	defer db.Close()

	require.Equal(t, "GOOGLE (Google LLC)", lookupNetblock(t, db, "8.8.8.8"))
	require.Equal(t, "", lookupNetblock(t, db, "1.1.1.1"))
}
