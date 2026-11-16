package sources

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// CatalogSource is one public source a database can be built from.
type CatalogSource struct {
	// Name matches the name the builder records in the update record.
	Name string `json:"name"`
	// URL is where it is downloaded from, or its documentation when the
	// download URL carries a date or a key.
	URL string `json:"url,omitempty"`
	// Provides says what it contributes, in plain words.
	Provides string `json:"provides"`
	// Group puts a source under another in the list: the VPN providers'
	// own lists sit under "VPN providers".
	Group string `json:"group,omitempty"`
	// Condition says when it is used, if not always.
	Condition string `json:"condition,omitempty"`
}

// SourceCatalog lists every source the database with update key may be
// built from, in the order the builder tries them.
func SourceCatalog(key string) []CatalogSource {
	switch key {
	case KeyASN:
		out := make([]CatalogSource, 0, len(ribSources)+1)
		for i, src := range ribSources {
			cond := ""
			if i > 0 {
				cond = "only if the archives before it fail"
			}
			out = append(out, CatalogSource{Name: src.name, URL: listingRoot(src.listing), Condition: cond,
				Provides: "A full BGP routing table: which AS announces each prefix. Also builds the ASN prefixes database."})
			if src.ipv6 != nil {
				out = append(out, CatalogSource{Name: src.ipv6.name, URL: listingRoot(src.ipv6.listing),
					Condition: "with IPv6 routes on, alongside " + src.name,
					Provides:  "The IPv6 routing table, which " + src.name + " lacks."})
			}
		}
		return out
	case KeyNames:
		return []CatalogSource{{Name: "RIPE NCC AS names", URL: ripeASNames,
			Provides: "The name and country of every registered AS number."}}
	case KeyCountry:
		out := make([]CatalogSource, 0, len(rirDelegatedURLs))
		for _, u := range rirDelegatedURLs {
			out = append(out, CatalogSource{Name: delegatedSourceName(u), URL: u,
				Provides: "Which country each block of the registry's addresses is allocated to."})
		}
		return out
	case KeyCity:
		return []CatalogSource{
			{Name: "DB-IP City Lite", URL: "https://db-ip.com/db/download/ip-to-city-lite",
				Provides: "Approximate city for each address (CC BY 4.0, monthly)."},
			{Name: MaxMindSourceName, URL: "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data",
				Condition: "with a MaxMind account (" + MaxMindAccountEnvVar + " and " + MaxMindKeyEnvVar + "); GeoLite2-City unless " + MaxMindEditionEnvVar + " names another edition",
				Provides:  "A second, independent city estimate, shown beside DB-IP's: GeoLite2 City (free with an account) or a paid GeoIP2 City edition."},
		}
	case KeyNetblock:
		return []CatalogSource{
			{Name: "APNIC", URL: apnicWhoisBase, Provides: "Asia-Pacific registrations: who each block is assigned to, its country and date."},
			{Name: "RIPE", URL: ripeWhoisBase, Provides: "Europe, Middle East and Central Asia registrations."},
			{Name: "AFRINIC", URL: afrinicWhoisDump, Provides: "African registrations."},
			{Name: "ARIN", URL: "https://www.arin.net/reference/research/bulkwhois/", Condition: "with an ARIN bulk whois key (" + ArinKeyEnvVar + ")",
				Provides: "North American registrations, including customer reassignments."},
			{Name: "ARIN (delegated statistics)", URL: arinDelegatedURL, Condition: "without an ARIN key",
				Provides: "ARIN's allocations, named after the AS that routes them: coarser than bulk whois."},
		}
	case KeyGeofeed:
		return []CatalogSource{{Name: GeofeedSourceName, URL: "https://www.rfc-editor.org/rfc/rfc8805",
			Condition: "with the netblock database, which finds the feeds",
			Provides: "Where each network says its own addresses are (RFC 8805 geofeeds), fetched from the URL its registry ranges name (RFC 9092). " +
				"A feed only counts for the addresses inside the ranges that name it. It is the holder's claim: leased and VPN space can say anything."}}
	case KeyCategory:
		out := []CatalogSource{
			{Name: "AWS", URL: awsRanges, Provides: "Amazon Web Services address ranges (cloud:aws)."},
			{Name: "Google Cloud", URL: gcpRanges, Provides: "Google Cloud address ranges (cloud:gcp)."},
			{Name: "Oracle Cloud", URL: oracleRanges, Provides: "Oracle Cloud address ranges (cloud:oracle)."},
			{Name: "Fastly", URL: fastlyRanges, Provides: "Fastly CDN ranges (cdn:fastly)."},
			{Name: "Cloudflare", URL: cloudflareV4Ranges, Provides: "Cloudflare ranges, IPv4 and IPv6 (cdn:cloudflare)."},
			{Name: "DigitalOcean", URL: digitalOceanRanges, Provides: "DigitalOcean's published geofeed (cloud:digitalocean)."},
			{Name: "Linode", URL: linodeRanges, Provides: "Linode/Akamai's geofeed (cloud:linode)."},
			{Name: "Vultr", URL: vultrRanges, Provides: "Vultr's geofeed (cloud:vultr)."},
			{Name: "Azure", URL: azureServiceTagsPage, Provides: "Microsoft Azure's public-cloud ranges from its weekly Service Tags file (cloud:azure; Front Door's edge also cdn)."},
			{Name: "Tor", URL: torExitList, Provides: "Current Tor exit relays (tor-exit)."},
			{Name: "iCloud Private Relay", URL: icloudRelayEgress, Provides: "Apple's Private Relay egress ranges, each with the region its users are in (relay:icloud)."},
			{Name: "Team Cymru bogons", URL: "https://www.team-cymru.com/bogon-reference", Provides: "Space no registry has handed out, IPv4 and IPv6 (bogon)."},
			{Name: "MISP warninglists", URL: "https://github.com/MISP/misp-warninglists", Provides: "Known scanners, crawlers, services, public resolvers and sinkholes, and clouds without a list of their own (scanner:, crawler:, service:, public-dns, sinkhole, cloud:...). IP lists only."},
			{Name: "VPN providers", Provides: "Commercial VPN servers (vpn:<provider>): each provider's own list where it publishes one, otherwise gluetun's copy."},
		}
		for _, api := range vpnAPIs {
			out = append(out, CatalogSource{Name: api.source, URL: api.url, Group: "VPN providers",
				Provides: strings.Fields(api.source)[0] + "'s own server list; gluetun's copy is used if this fails."})
		}
		out = append(out,
			CatalogSource{Name: "gluetun server lists", URL: "https://github.com/qdm12/gluetun-servers", Group: "VPN providers",
				Provides: "Server lists for some 30 VPN providers, kept by the gluetun project, used for providers without their own list."},
			CatalogSource{Name: "PeeringDB", URL: peeringDBNets, Provides: "The network type operators give themselves: ISP, content, enterprise, education..."},
			CatalogSource{Name: "bgp.tools", URL: "https://bgp.tools/tags/", Condition: "with a contact email (ASNAME_CONTACT_EMAIL)",
				Provides: "bgp.tools' AS tags: hosting, home broadband, mobile, VPN, government, university..."},
			CatalogSource{Name: InferSourceName, URL: "https://github.com/flyingllama87/asname/blob/main/internal/sources/inferrules.yaml",
				Condition: "with the AS names list",
				Provides:  "asname's own rules: education, government, finance, healthcare, ISP, mobile and hosting from words in the AS's registered name, and a short list of well-known networks. Shown as inferred, alongside the other sources' tags."},
			CatalogSource{Name: InferNetnameSourceName, URL: "https://github.com/flyingllama87/asname/blob/main/internal/sources/inferrules.yaml",
				Condition: "with the netblock database",
				Provides:  "asname's own rules on registry netnames: broadband pools (DSL, PPPoE, fibre, dynamic), mobile data pools (LTE, 3G, GGSN), carrier-grade NAT and hosting ranges, tagged range:... per address range. Shown as inferred."},
		)
		return out
	case KeyReputation:
		return []CatalogSource{
			{Name: "Spamhaus ASN-DROP", URL: spamhausASNDrop, Provides: "Networks (whole AS numbers) Spamhaus says are run by or for criminals."},
			{Name: "Spamhaus DROP IPv4", URL: spamhausDropV4, Provides: "Hijacked or criminal IPv4 blocks: don't route or peer."},
			{Name: "Spamhaus DROP IPv6", URL: spamhausDropV6, Provides: "The same for IPv6."},
			{Name: "IPsum", URL: ipsumList, Provides: "Addresses seen attacking, counted by how many of ~30 blocklists name them."},
			{Name: "FireHOL level 2", URL: fireholLevel2, Provides: "Addresses attacking in the last 48 hours, from several feeds."},
			{Name: "FireHOL level 3", URL: fireholLevel3, Provides: "Addresses attacking in the last 30 days: broader, more false positives."},
			{Name: "abuse.ch Feodo Tracker", URL: feodoTracker, Provides: "Botnet command-and-control servers, with the malware family each serves (feodo:<family>)."},
		}
	}
	return nil
}

// listingRoot trims a dated listing URL ("…/bgpdata/%s/RIBS/") to the part
// before the date.
func listingRoot(listing string) string {
	if i := strings.Index(listing, "%s"); i > 0 {
		return listing[:i]
	}
	return listing
}

// SourceStatus is a catalog source with how it fared in the last update.
type SourceStatus struct {
	CatalogSource
	// Recorded is false when the last update predates per-source records,
	// or the source was not reached (it is listed from the catalog only).
	Recorded bool   `json:"recorded"`
	Entries  int    `json:"entries,omitempty"`
	Failed   bool   `json:"failed,omitempty"`
	Note     string `json:"note,omitempty"`
}

// sourceStatuses merges the catalog for key with the recorded outcomes:
// every catalog source in order, then any recorded source the catalog does
// not list (a bgp.tools tag that failed, say).
func sourceStatuses(key string, o UpdateOutcome) []SourceStatus {
	recorded := o.Sources
	// A record from before per-source outcomes still names its failures.
	if len(recorded) == 0 {
		for _, name := range o.Failed {
			recorded = append(recorded, SourceOutcome{Name: name, Failed: true})
		}
	}
	byName := make(map[string]SourceOutcome, len(recorded))
	for _, r := range recorded {
		byName[r.Name] = r
	}
	var out []SourceStatus
	seen := map[string]bool{}
	for _, c := range SourceCatalog(key) {
		st := SourceStatus{CatalogSource: c}
		if r, ok := byName[c.Name]; ok {
			st.Recorded, st.Entries, st.Failed, st.Note = true, r.Entries, r.Failed, r.Note
		}
		seen[c.Name] = true
		out = append(out, st)
	}
	for _, r := range recorded {
		if seen[r.Name] {
			continue
		}
		out = append(out, SourceStatus{CatalogSource: CatalogSource{Name: r.Name}, Recorded: true,
			Entries: r.Entries, Failed: r.Failed, Note: r.Note})
	}
	return out
}

// VPNListStatus says which list a vpn:<provider> tag in the category
// database came from, and when that list was current.
type VPNListStatus struct {
	Tag    string    `json:"tag"`
	Source string    `json:"source"`
	Date   time.Time `json:"date,omitzero"`
}

var vpnListCache struct {
	sync.Mutex
	path  string
	mtime time.Time
	lists []VPNListStatus
}

// categoryVPNLists reads the VPN lists recorded in the category database
// at path, sorted by tag. The answer is kept until the file changes, so the
// status endpoint does not reparse the database on every call.
func categoryVPNLists(path string, mtime time.Time) []VPNListStatus {
	vpnListCache.Lock()
	defer vpnListCache.Unlock()
	if vpnListCache.path == path && vpnListCache.mtime.Equal(mtime) {
		return vpnListCache.lists
	}
	var lists []VPNListStatus
	if db, err := OpenCategoryDB(path); err == nil {
		for tag, l := range db.vpnLists {
			if !strings.HasPrefix(tag, "vpn:") {
				continue // MISP lists' names, shown with lookups only
			}
			lists = append(lists, VPNListStatus{Tag: tag, Source: l.Source, Date: l.Date})
		}
		sort.Slice(lists, func(i, j int) bool { return lists[i].Tag < lists[j].Tag })
	}
	vpnListCache.path, vpnListCache.mtime, vpnListCache.lists = path, mtime, lists
	return lists
}
