package sources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNameMatcher(t *testing.T) {
	rank := func(query, name string, fuzzy bool) int {
		return NewNameMatcher(query, fuzzy).Rank([]byte(name))
	}
	for _, c := range []struct {
		query, name string
		want        int
	}{
		{"cloudflare", "CLOUDFLARENET - Cloudflare, Inc.", MatchExact},
		{"colo crossing", "AS-COLOCROSSING - HostPapa", MatchCompact},
		{"amazon 02", "AMAZON-02 - Amazon.com, Inc.", MatchCompact},
		{"digital ocean", "DigitalOcean, LLC", MatchCompact},
		{"univ of mississippi", "MSSTATE - Mississippi State University", MatchWords},
		{"Telstra Corporation Ltd", "ASN-TELSTRA - Telstra Limited", MatchWords},
		{"telstra", "TelstraEuropeLtd-Backbone", MatchExact},
		{"europe telstra", "TelstraEuropeLtd-Backbone", MatchWords},
		{"núcleo", "Núcleo de Inf. e Coord.", MatchExact},
		{"nucleo info", "Núcleo de Informação", MatchNone},
		// Words match only where a word starts, and numbers only whole.
		{"deutsche telekom", "mitteldeutsche IT GmbH, Telekom", MatchNone},
		{"level 3", "PSL-AU - Level 23, Exchange Plaza", MatchNone},
		{"level 3", "LEVEL365 HOLDINGS LLC", MatchNone},
		{"inc", "Cloudflare, Inc.", MatchExact},
		{"inc llc", "Cloudflare, Inc.", MatchNone},
	} {
		assert.Equal(t, c.want, rank(c.query, c.name, true), "%q in %q", c.query, c.name)
	}
	// A plain search finds exact matches alone, as it always has.
	assert.Equal(t, MatchNone, rank("colo crossing", "AS-COLOCROSSING", false))
	assert.Equal(t, MatchExact, rank("colocrossing", "AS-COLOCROSSING", false))
}
