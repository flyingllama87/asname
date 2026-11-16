package engine

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCDNMatching(t *testing.T) {
	require.Equal(t, "Akamai", cdnFromCNAME("nsa.gov.edgekey.net."))
	require.Equal(t, "Akamai", cdnFromCNAME("e1234.dscx.akamaiedge.net"))
	require.Equal(t, "Amazon CloudFront", cdnFromCNAME("d111111abcdef8.cloudfront.net."))
	require.Equal(t, "Fastly", cdnFromCNAME("dualstack.n.sni.global.fastly.net"))
	require.Equal(t, "", cdnFromCNAME("www.example.com."))
	// A suffix matches whole labels only.
	require.Equal(t, "", cdnFromCNAME("notakamai.net"))
	require.Equal(t, "", cdnFromCNAME("fake-cloudfront.net"))

	require.Equal(t, "Akamai", cdnFromNS("a5-66.akam.net."))
	require.Equal(t, "", cdnFromNS("ns1.example.net."))
}

func TestNAT64(t *testing.T) {
	// Vodafone AU's DNS64 answers for ipv4only.arpa.
	ans := []netip.Addr{netip.MustParseAddr("2405:6e00:64::c000:aa"), netip.MustParseAddr("2405:6e00:64::c000:ab")}
	local := nat64PrefixesFrom(ans)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("2405:6e00:64::/96")}, local)
	// A /64 prefix skips the reserved octet.
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("2001:db8:1:2::/64")},
		nat64PrefixesFrom([]netip.Addr{netip.MustParseAddr("2001:db8:1:2:c0:0:aa00:0")}))
	require.Empty(t, nat64PrefixesFrom([]netip.Addr{netip.MustParseAddr("2001:db8::1")}))

	// nsa.gov over DNS64: A and synthesized AAAA collapse to one IPv4 address.
	tg := Target{Raw: "nsa.gov", Host: "nsa.gov", IPs: []net.IP{net.ParseIP("23.46.47.108"), net.ParseIP("2405:6e00:64::172e:2f6c")}}
	got, found := tg.UnmapNAT64(local)
	require.Equal(t, []net.IP{net.ParseIP("23.46.47.108").To4()}, []net.IP{got.IPs[0].To4()})
	require.Len(t, got.IPs, 1)
	require.Equal(t, &NAT64{Address: "2405:6e00:64::172e:2f6c", Prefix: "2405:6e00:64::/96", DNS64: true}, found["23.46.47.108"])

	// A pasted well-known-prefix address, with no local prefix known.
	got, found = Target{Raw: "64:ff9b::808:808", IPs: []net.IP{net.ParseIP("64:ff9b::808:808")}}.UnmapNAT64(nil)
	require.Equal(t, "8.8.8.8", got.IPs[0].String())
	require.False(t, found["8.8.8.8"].DNS64)

	// Real IPv6 is left alone.
	got, found = Target{Raw: "x", IPs: []net.IP{net.ParseIP("2001:4860:4860::8888")}}.UnmapNAT64(local)
	require.Equal(t, "2001:4860:4860::8888", got.IPs[0].String())
	require.Nil(t, found)
}

func TestDropIPv6IfDualStack(t *testing.T) {
	dual := Target{Host: "x", IPs: []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::2")}}
	got, n := dual.dropIPv6IfDualStack()
	require.Equal(t, 2, n)
	require.Len(t, got.IPs, 1)
	only6 := Target{Host: "x", IPs: []net.IP{net.ParseIP("2001:db8::1")}}
	got, n = only6.dropIPv6IfDualStack()
	require.Zero(t, n)
	require.Len(t, got.IPs, 1)
}
