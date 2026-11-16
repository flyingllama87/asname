package sources

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path"
	"regexp"
	"strings"

	"github.com/flyingllama87/asname/pkg/database"
)

const (
	// azureServiceTagsPage links the week's Azure Service Tags file, whose
	// name carries its date, so the link is read from the page.
	azureServiceTagsPage = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
	icloudRelayEgress    = "https://mask-api.icloud.com/egress-ip-ranges.csv"
	cymruFullbogonsV4    = "https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt"
	cymruFullbogonsV6    = "https://www.team-cymru.org/Services/Bogons/fullbogons-ipv6.txt"
	mispWarninglists     = "https://codeload.github.com/MISP/misp-warninglists/tar.gz/refs/heads/main"
)

// Tags that describe an address without saying what kind of network it is
// on. They add to the network's own tags rather than hide them: an open
// resolver on a home connection is still on an ISP.
var supplementaryPrefixes = []string{"scanner:", "crawler:", "service:"}

var supplementaryTags = map[string]bool{"public-dns": true, "sinkhole": true, "bogon": true, "parking": true}

// SupplementaryTag reports whether tag adds to a network's tags rather than
// replacing them.
func SupplementaryTag(tag string) bool {
	for _, p := range supplementaryPrefixes {
		if strings.HasPrefix(tag, p) {
			return true
		}
	}
	return supplementaryTags[tag]
}

var azureJSONLink = regexp.MustCompile(`https://download\.microsoft\.com/[^"']*ServiceTags_Public_\d+\.json`)

// importAzure reads Microsoft's public Azure Service Tags: every Azure
// public-cloud range (AzureCloud), with Front Door's edge also marked cdn.
func (b *categoryBuilder) importAzure() (int, error) {
	resp, err := httpGetUA(b.ctx, azureServiceTagsPage, "")
	if err != nil {
		return 0, err
	}
	page, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	resp.Body.Close()
	if err != nil {
		return 0, err
	}
	link := azureJSONLink.Find(page)
	if link == nil {
		return 0, fmt.Errorf("no Service Tags file linked from %s", azureServiceTagsPage)
	}
	return b.ImportAzureFrom(string(link))
}

func (b *categoryBuilder) ImportAzureFrom(url string) (int, error) {
	var doc struct {
		Values []struct {
			Name       string `json:"name"`
			Properties struct {
				AddressPrefixes []string `json:"addressPrefixes"`
			} `json:"properties"`
		} `json:"values"`
	}
	if err := fetchJSON(b.ctx, url, "", &doc); err != nil {
		return 0, err
	}
	count := 0
	for _, v := range doc.Values {
		var tags []string
		switch v.Name {
		case "AzureCloud":
			tags = []string{"cloud:azure"}
		case "AzureFrontDoor.Frontend":
			tags = []string{"cloud:azure", "cdn"}
		default:
			continue
		}
		for _, p := range v.Properties.AddressPrefixes {
			b.addPrefix(p, tags...)
			count++
		}
	}
	if count == 0 {
		return 0, fmt.Errorf("no AzureCloud ranges in %s", url)
	}
	return count, nil
}

// RelayLocation is where Apple says an iCloud Private Relay egress range's
// users are: Private Relay keeps a user's rough location, so the egress
// stands for a region, not the place its servers are.
type RelayLocation struct {
	Country, Region, City string
}

func (l RelayLocation) String() string {
	return GeofeedLocation{Country: l.Country, Region: l.Region, City: l.City}.String()
}

// importICloudRelay reads Apple's iCloud Private Relay egress ranges, a
// geofeed-format CSV: prefix, country, region, city.
func (b *categoryBuilder) ImportICloudRelayFrom(url string) (int, error) {
	resp, err := httpGetUA(b.ctx, url, "")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	r := csv.NewReader(bufio.NewReaderSize(resp.Body, 1<<16))
	r.FieldsPerRecord = -1
	r.ReuseRecord = true
	count := 0
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, err
		}
		if len(rec) < 2 {
			continue
		}
		p, ok := parsePrefix(rec[0])
		if !ok {
			continue
		}
		b.addPrefix(p.String(), "relay:icloud")
		loc := RelayLocation{Country: strings.TrimSpace(rec[1])}
		if len(rec) > 2 {
			loc.Region = strings.TrimSpace(rec[2])
		}
		if len(rec) > 3 {
			loc.City = strings.TrimSpace(rec[3])
		}
		b.relay[p] = loc
		count++
	}
	if count == 0 {
		return 0, fmt.Errorf("no ranges in %s", url)
	}
	return count, nil
}

// importBogons reads Team Cymru's full bogon lists: space no registry has
// handed out (and the reserved blocks), which nothing should announce.
func (b *categoryBuilder) importBogons() (int, error) {
	total := 0
	for _, url := range []string{cymruFullbogonsV4, cymruFullbogonsV6} {
		n, err := b.ImportCIDRList(url, "", "bogon")
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// mispSkip are MISP warninglists asname reads first-hand from the provider,
// or that the IANA table covers, or that are too broad to say anything.
var mispSkip = map[string]bool{
	"amazon-aws": true, "google-gcp": true, "oracle-oci": true, "digitalocean": true, "linode": true,
	"vultr": true, "cloudflare": true, "fastly": true, "microsoft-azure": true, "tor-exit-nodes": true,
	"icloud-private-relay": true, "rfc1918": true, "rfc3849": true, "rfc5735": true, "rfc6598": true,
	"multicast": true, "ipv6-linklocal": true, "apple-ipv4": true, "apple-ipv6": true,
	// Broad "datacenter or VPN" ranges compiled from AS names: the AS
	// tags already say this, from better sources.
	"datacenter-ipv4": true, "datacenter-ipv6": true, "vpn-ipv4": true, "vpn-ipv6": true,
}

// mispTags maps the MISP warninglists asname reads to its tags. Lists named
// *-scanning or *-scanner that are not here become scanner:<name>.
var mispTags = map[string][]string{
	"alibaba-cloud":                    {"cloud:alibaba"},
	"ibm-cloud":                        {"cloud:ibm"},
	"huawei-cloud":                     {"cloud:huawei"},
	"tencent-cloud":                    {"cloud:tencent"},
	"coreweave":                        {"cloud:coreweave"},
	"scaleway":                         {"cloud:scaleway"},
	"hetzner":                          {"cloud:hetzner"},
	"leaseweb":                         {"cloud:leaseweb"},
	"rackspace":                        {"cloud:rackspace"},
	"ovh-cluster":                      {"cloud:ovh"},
	"godaddy":                          {"cloud:godaddy"},
	"microsoft-azure-china":            {"cloud:azure"},
	"microsoft-azure-germany":          {"cloud:azure"},
	"microsoft-azure-us-gov":           {"cloud:azure"},
	"akamai":                           {"cdn", "cloud:akamai"},
	"bunny-net":                        {"cdn", "cloud:bunny"},
	"cachefly":                         {"cdn", "cloud:cachefly"},
	"cdn77":                            {"cdn", "cloud:cdn77"},
	"gcore":                            {"cdn", "cloud:gcore"},
	"imperva":                          {"cdn", "cloud:imperva"},
	"sucuri":                           {"cdn", "cloud:sucuri"},
	"stackpath":                        {"cdn", "cloud:stackpath"},
	"googlebot":                        {"crawler:googlebot"},
	"openai-gptbot":                    {"crawler:gptbot"},
	"public-dns-v4":                    {"public-dns"},
	"public-dns-v6":                    {"public-dns"},
	"sinkholes":                        {"sinkhole"},
	"parking-domain":                   {"parking"},
	"zscaler":                          {"service:zscaler"},
	"salesforce":                       {"service:salesforce"},
	"github":                           {"service:github"},
	"telegram-ips":                     {"service:telegram"},
	"wikimedia":                        {"service:wikimedia"},
	"apple":                            {"service:apple"},
	"microsoft-office365-ip":           {"service:microsoft-365"},
	"microsoft-office365-cn":           {"service:microsoft-365"},
	"palo-alto-networks-cortex-cloud":  {"service:palo-alto-cortex"},
	"tenable-cloud-ipv4":               {"service:tenable-cloud"},
	"tenable-cloud-ipv6":               {"service:tenable-cloud"},
	"check-host-net":                   {"service:check-host"},
	"crl-ip":                           {"service:crl-ocsp"},
	"umbrella-blockpage-v4":            {"service:umbrella-blockpage"},
	"umbrella-blockpage-v6":            {"service:umbrella-blockpage"},
	"smtp-sending-ips":                 {"service:mail-sending"},
	"google-gmail-sending-ips":         {"service:mail-sending"},
	"smtp-receiving-ips":               {"service:mail-receiving"},
	"palo-alto-networks-cortex-xpanse": {"scanner:palo-alto-xpanse"},
	"shadowserver":                     {"scanner:shadowserver"},
	"driftnet":                         {"scanner:driftnet"},
	"umich-cse-connection-attempts":    {"scanner:umich"},
}

// MISPListTags returns the tags asname gives a MISP warninglist by its
// directory name, or none to skip it.
func MISPListTags(dir string) []string {
	if mispSkip[dir] {
		return nil
	}
	if tags, ok := mispTags[dir]; ok {
		return tags
	}
	for _, suffix := range []string{"-nt-scanning", "-scanning", "-scanner"} {
		if name, ok := strings.CutSuffix(dir, suffix); ok && name != "" {
			return []string{"scanner:" + name}
		}
	}
	return nil
}

// importMISP reads the cidr lists out of the MISP warninglists repository's
// tarball: known scanners, crawlers, services, resolvers and sinkholes, and
// clouds asname has no first-hand list for.
func (b *categoryBuilder) ImportMISPFrom(url string) (int, error) {
	resp, err := httpGetUA(b.ctx, url, "")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return 0, err
	}
	tr := tar.NewReader(gz)
	count, lists := 0, 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, err
		}
		// <repo>-<branch>/lists/<name>/list.json
		parts := strings.Split(path.Clean(h.Name), "/")
		if len(parts) != 4 || parts[1] != "lists" || parts[3] != "list.json" {
			continue
		}
		tags := MISPListTags(parts[2])
		if len(tags) == 0 {
			continue
		}
		var doc struct {
			Name string   `json:"name"`
			Type string   `json:"type"`
			List []string `json:"list"`
		}
		if err := json.NewDecoder(io.LimitReader(tr, 64<<20)).Decode(&doc); err != nil || doc.Type != "cidr" {
			continue
		}
		for _, entry := range doc.List {
			b.addPrefix(entry, tags...)
			count++
		}
		lists++
		for _, t := range tags {
			if strings.Contains(t, ":") && !strings.HasPrefix(t, "cloud:") {
				if _, have := b.vpnLists[t]; !have {
					b.vpnLists[t] = VPNList{Source: "MISP warninglist: " + doc.Name}
				}
			}
		}
	}
	if lists == 0 {
		return 0, fmt.Errorf("no warninglists read")
	}
	return count, nil
}

// marshalRelay encodes the Private Relay locations: a trie from egress
// range to an index into a table of "country|region|city" strings.
func (b *categoryBuilder) marshalRelay() ([]byte, error) {
	locs := []string{""}
	index := map[string]uint32{"": 0}
	var trie trieBuilder = database.NewBuilder()
	for p, l := range b.relay {
		key := l.Country + "|" + l.Region + "|" + l.City
		i, ok := index[key]
		if !ok {
			i = uint32(len(locs))
			locs = append(locs, key)
			index[key] = i
		}
		ipNet := &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
		if err := trie.InsertMapping(ipNet, i); err != nil {
			return nil, fmt.Errorf("inserting %s: %v", p, err)
		}
	}
	var trieBytes []byte
	if len(b.relay) > 0 {
		trie.SetFillFactor(OptimizationFillFactor)
		built, err := trie.Build()
		if err != nil {
			return nil, fmt.Errorf("building relay table: %v", err)
		}
		if trieBytes, err = built.MarshalBinary(); err != nil {
			return nil, err
		}
	}
	out := binary.LittleEndian.AppendUint64(nil, uint64(len(trieBytes)))
	out = append(out, trieBytes...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(locs)-1))
	for _, l := range locs[1:] {
		out = append(out, l...)
		out = append(out, 0)
	}
	return out, nil
}

var (
	mappedFirst = netip.MustParseAddr("::ffff:0.0.0.0")
	mappedLast  = netip.MustParseAddr("::ffff:255.255.255.255")
)

// splitMapped keeps a prefix out of the IPv4-mapped space the tries store
// IPv4 in. An IPv4-mapped prefix (::ffff:192.0.2.1/128) becomes the IPv4
// one; an IPv6 prefix covering the mapped space (::/10 in Team Cymru's bogon
// list) loses it, or it would cover every IPv4 address.
func splitMapped(p netip.Prefix) []netip.Prefix {
	p = p.Masked()
	a := p.Addr()
	if a.Is4In6() {
		bits := p.Bits() - 96
		if bits < 0 {
			bits = 0
		}
		return []netip.Prefix{netip.PrefixFrom(a.Unmap(), bits).Masked()}
	}
	if !a.Is6() || !p.Contains(mappedFirst) {
		return []netip.Prefix{p}
	}
	first, last := a, lastAddr6(p)
	var out []netip.Prefix
	if first.Less(mappedFirst) {
		out = append(out, rangeCIDRs(first, mappedFirst.Prev())...)
	}
	if mappedLast.Less(last) {
		out = append(out, rangeCIDRs(mappedLast.Next(), last)...)
	}
	return out
}

// lastAddr6 is the last address in an IPv6 prefix.
func lastAddr6(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As16()
	for i := p.Bits(); i < 128; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	return netip.AddrFrom16(b)
}
