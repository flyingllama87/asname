package sources

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSpecialPurpose(t *testing.T) {
	for _, c := range []struct{ ip, prefix, name, rfc, global string }{
		{"100.64.0.1", "100.64.0.0/10", "Shared Address Space (carrier-grade NAT)", "RFC 6598", "false"},
		{"10.1.2.3", "10.0.0.0/8", "Private use (RFC 1918)", "RFC 1918", "false"},
		{"192.0.0.170", "192.0.0.170/32", "NAT64/DNS64 Discovery", "RFC 8880", "false"},
		{"192.0.0.5", "192.0.0.0/29", "IPv4 Service Continuity Prefix", "RFC 7335", "false"},
		{"203.0.113.9", "203.0.113.0/24", "Documentation (TEST-NET-3)", "RFC 5737", "false"},
		{"64:ff9b::808:808", "64:ff9b::/96", "IPv4/IPv6 translation (NAT64)", "RFC 6052", "true"},
		{"2001:db8::1", "2001:db8::/32", "Documentation", "RFC 3849", "false"},
		{"2001::1", "2001::/32", "TEREDO", "RFC 4380", ""},
		{"239.1.1.1", "224.0.0.0/4", "Multicast", "RFC 5771", "false"},
		{"127.0.0.1", "127.0.0.0/8", "Loopback", "RFC 1122", "false"},
	} {
		s, ok := SpecialPurpose(net.ParseIP(c.ip))
		require.True(t, ok, c.ip)
		require.Equal(t, Special{Prefix: c.prefix, Name: c.name, RFC: c.rfc, Global: c.global}, s, c.ip)
	}
	for _, ip := range []string{"8.8.8.8", "192.88.99.1", "2606:4700::1"} {
		_, ok := SpecialPurpose(net.ParseIP(ip))
		require.False(t, ok, ip)
	}
}
