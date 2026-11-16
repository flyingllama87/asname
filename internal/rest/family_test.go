package rest

import (
	"net"
	"testing"

	"github.com/flyingllama87/asname/internal/engine"
	"github.com/stretchr/testify/require"
)

func TestHostFamilyFiltersHostnamesOnly(t *testing.T) {
	host := engine.Target{Raw: "example.com", Host: "example.com", IPs: []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}}
	got := hostFamily(host, true, false)
	require.NoError(t, got.Err)
	require.Len(t, got.IPs, 1)
	require.Equal(t, "192.0.2.1", got.IPs[0].String())

	only6 := engine.Target{Raw: "v6.example", Host: "v6.example", IPs: []net.IP{net.ParseIP("2001:db8::1")}}
	require.Error(t, hostFamily(only6, true, false).Err)

	// An address given as such is looked up whatever the family.
	literal := engine.Target{Raw: "2001:db8::1", IPs: []net.IP{net.ParseIP("2001:db8::1")}}
	got = hostFamily(literal, true, false)
	require.NoError(t, got.Err)
	require.Len(t, got.IPs, 1)
}
