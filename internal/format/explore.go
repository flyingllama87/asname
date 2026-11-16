package format

import (
	"fmt"
	"time"

	"github.com/flyingllama87/asname/internal/engine"
)

// JSONExplorePrefix is one prefix of an explore result.
type JSONExplorePrefix struct {
	Prefix     string                `json:"prefix"`
	ASN        string                `json:"asn"`
	ASName     string                `json:"as_name"`
	Country    string                `json:"country"`
	ASCountry  string                `json:"as_country"`
	Tags       []string              `json:"tags"`
	Addresses  uint64                `json:"addresses,omitempty"`
	Reputation JSONExploreReputation `json:"reputation"`
}

// JSONExploreReputation is what the blocklists say about a prefix.
type JSONExploreReputation struct {
	ListedIPs      uint64   `json:"listed_ips"`
	ListedSharePct float64  `json:"listed_share_pct"`
	MaxIPsum       int      `json:"max_ipsum"`
	SpamhausDrop   bool     `json:"spamhaus_drop"`
	DropInside     bool     `json:"spamhaus_drop_inside"`
	SBL            []string `json:"sbl,omitempty"`
	ASNDrop        bool     `json:"spamhaus_asn_drop"`
	FireHOLLevel2  bool     `json:"firehol_level2"`
	FireHOLLevel3  bool     `json:"firehol_level3"`
}

// JSONExploreFacet counts the matching prefixes with one value.
type JSONExploreFacet struct {
	Value string `json:"value"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

// JSONExplore is an explore result, as /v1/explore and `asname explore
// --json` give it.
type JSONExplore struct {
	Count     int                 `json:"count"`
	Offset    int                 `json:"offset"`
	Addresses uint64              `json:"ipv4_addresses"`
	Results   []JSONExplorePrefix `json:"results"`
	Countries []JSONExploreFacet  `json:"countries"`
	Tags      []JSONExploreFacet  `json:"tags"`
	ASNs      []JSONExploreFacet  `json:"asns"`
	AllTags   []string            `json:"all_tags"`
	Built     time.Time           `json:"index_built"`
	TookMS    int64               `json:"took_ms"`
}

// NewJSONExplore converts an explore result.
func NewJSONExplore(res engine.ExploreResult, offset int) JSONExplore {
	out := JSONExplore{
		Count:     res.Total,
		Offset:    offset,
		Addresses: res.Addresses,
		Results:   make([]JSONExplorePrefix, 0, len(res.Prefixes)),
		AllTags:   res.AllTags,
		Built:     res.Built,
		TookMS:    res.Took.Milliseconds(),
	}
	for _, p := range res.Prefixes {
		tags := p.Tags
		if tags == nil {
			tags = []string{}
		}
		out.Results = append(out.Results, JSONExplorePrefix{
			Prefix:    p.Prefix,
			ASN:       fmt.Sprintf("AS%d", p.ASN),
			ASName:    p.ASName,
			Country:   p.Country,
			ASCountry: p.ASCountry,
			Tags:      tags,
			Addresses: p.Addresses,
			Reputation: JSONExploreReputation{
				ListedIPs:      p.ListedIPs,
				ListedSharePct: p.ListedSharePct,
				MaxIPsum:       p.MaxIPsum,
				SpamhausDrop:   p.Drop,
				DropInside:     p.DropInside,
				SBL:            p.SBL,
				ASNDrop:        p.ASNDrop,
				FireHOLLevel2:  p.FireHOL2,
				FireHOLLevel3:  p.FireHOL3,
			},
		})
	}
	facets := func(f []engine.ExploreFacet) []JSONExploreFacet {
		o := make([]JSONExploreFacet, 0, len(f))
		for _, x := range f {
			o = append(o, JSONExploreFacet{x.Value, x.Label, x.Count})
		}
		return o
	}
	out.Countries, out.Tags, out.ASNs = facets(res.Countries), facets(res.Tags), facets(res.ASNs)
	return out
}
