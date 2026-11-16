package engine

import (
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
