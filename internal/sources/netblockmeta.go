package sources

import (
	"net/url"
	"regexp"
	"strings"
)

// NetblockMeta is what a registry range says about itself beyond its name:
// the country its holder registered it in, when it was created, and flags
// derived from who maintains it.
type NetblockMeta struct {
	// Country is the range's own ISO country code. It can differ from the
	// RIR delegation country, which is that of the larger parent allocation.
	Country string
	// Created is the date the range was registered, YYYY-MM-DD.
	Created string
	// Tags flag the range: "leased:<broker>" for space an IP leasing broker
	// maintains, "anonymised-holder" for a holder whose name is withheld.
	Tags []string
}

// encode packs m as "CC|YYYY-MM-DD|tag,tag", or "" when m is empty.
func (m NetblockMeta) encode() string {
	if m.Country == "" && m.Created == "" && len(m.Tags) == 0 {
		return ""
	}
	return m.Country + "|" + m.Created + "|" + strings.Join(m.Tags, ",")
}

func decodeNetblockMeta(s string) NetblockMeta {
	if s == "" {
		return NetblockMeta{}
	}
	parts := strings.SplitN(s, "|", 3)
	for len(parts) < 3 {
		parts = append(parts, "")
	}
	m := NetblockMeta{Country: parts[0], Created: parts[1]}
	if parts[2] != "" {
		m.Tags = strings.Split(parts[2], ",")
	}
	return m
}

// leasingMaintainers maps the RIPE maintainers of IP leasing brokers to a
// short broker name. Matched case-insensitively against mnt-by on the range
// and on its organisation. NetUtils is IPXO's registry arm.
var leasingMaintainers = map[string]string{
	"netutils-mnt":          "ipxo",
	"ipxo-mnt":              "ipxo",
	"interlir-mnt":          "interlir",
	"lir-de-interlir-1-mnt": "interlir",
	"prefixbroker-mnt":      "prefixbroker",
	"mnt-ipbroker":          "ipbroker",
	"lirservices-mnt":       "lir-services",
	"mnt-bz-ipv4mall-1":     "ipv4mall",
}

// leasingGeofeeds maps the geofeed hosts of IP leasing brokers to the same names.
var leasingGeofeeds = map[string]string{
	"geofeed.ipxo.com":     "ipxo",
	"geofeed.netutils.io":  "ipxo",
	"interlir.com":         "interlir",
	"www.interlir.com":     "interlir",
	"prefixbroker.com":     "prefixbroker",
	"www.prefixbroker.com": "prefixbroker",
	"ipbroker.info":        "ipbroker",
	"www.ipbroker.info":    "ipbroker",
}

// anonymisedOrgName matches the placeholder names a leasing broker registers
// end users under instead of their own, such as "Company 64d3452aYKe9ygar".
var anonymisedOrgName = regexp.MustCompile(`^Company [0-9a-f]{8}[A-Za-z0-9]{8}$`)

// leasingBroker names the broker behind a range from its maintainers or geofeed.
func leasingBroker(mntBy, orgMntBy, geofeed string) string {
	for _, m := range []string{mntBy, orgMntBy} {
		if b := leasingMaintainers[strings.ToLower(strings.TrimSpace(m))]; b != "" {
			return b
		}
	}
	if geofeed != "" {
		if u, err := url.Parse(strings.TrimSpace(geofeed)); err == nil {
			if b := leasingGeofeeds[strings.ToLower(u.Hostname())]; b != "" {
				return b
			}
		}
	}
	return ""
}

// rpslMeta reads a RIPE-style range's metadata. orgName and orgMntBy come
// from the organisation object the range references.
func rpslMeta(attrs []attr, orgName, orgMntBy string) NetblockMeta {
	m := NetblockMeta{Country: strings.ToUpper(attrValue(attrs, "country"))}
	if len(m.Country) != 2 || m.Country == "EU" || m.Country == "ZZ" {
		m.Country = ""
	}
	if c := attrValue(attrs, "created"); len(c) >= 10 && c[4] == '-' && c[7] == '-' {
		m.Created = c[:10]
	}
	if b := leasingBroker(attrValue(attrs, "mnt-by"), orgMntBy, attrValue(attrs, "geofeed")); b != "" {
		m.Tags = append(m.Tags, "leased:"+b)
	}
	if anonymisedOrgName.MatchString(orgName) {
		m.Tags = append(m.Tags, "anonymised-holder")
	}
	return m
}
