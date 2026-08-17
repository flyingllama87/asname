package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/flyingllama87/asname/pkg/database"
)

// The categories come from three kinds of source, in descending order of how
// much they can be trusted.
//
// The providers' own published ranges are authoritative: when AWS says a prefix
// is CloudFront, it is CloudFront. These cover the addresses most lookups
// actually land on, and they are exact.
//
// bgp.tools' operator tags are curated, and cover the long tail of hosting
// companies, ISPs and VPN operators that publish nothing themselves.
//
// PeeringDB's network type is self-reported by the operator, and only exists
// for networks that peer publicly — around 35,000 of the ~121,000 ASNs in the
// routing table — but where it exists it comes straight from the people
// running the network.
//
// What is deliberately absent is VPN and proxy detection beyond operators who
// run their own AS. Most consumer VPN exits are rented from ordinary cloud
// providers and are indistinguishable, from routing data alone, from any other
// virtual machine. Telling them apart needs active measurement, which is a
// different tool than this one.
const (
	awsRanges          = "https://ip-ranges.amazonaws.com/ip-ranges.json"
	gcpRanges          = "https://www.gstatic.com/ipranges/cloud.json"
	oracleRanges       = "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"
	fastlyRanges       = "https://api.fastly.com/public-ip-list"
	cloudflareV4Ranges = "https://www.cloudflare.com/ips-v4"
	cloudflareV6Ranges = "https://www.cloudflare.com/ips-v6"
	digitalOceanRanges = "https://www.digitalocean.com/geo/google.csv"
	linodeRanges       = "https://geoip.linode.com/"
	vultrRanges        = "https://geofeed.constant.com/"
	torExitList        = "https://check.torproject.org/torbulkexitlist"
	bgpToolsTagURL     = "https://bgp.tools/tags/%s.csv"
	peeringDBNets      = "https://www.peeringdb.com/api/net?fields=asn,info_type"
)

// bgpToolsTagNames maps the tags bgp.tools publishes to the vocabulary asname
// reports.
//
// These describe the operator, not the address: the tag means the AS is
// associated with that thing, not that every address in it is. Three of their
// tags are left out because that reading makes them useless here rather than
// merely imprecise. "tor" sits on a quarter of the eyeball ISPs in their data,
// because subscribers run relays; "anycast" sits on Telstra, Google and
// Amazon, because everyone large anycasts something; and "biznet" means the
// network sells business connectivity, which is a description of an ISP rather
// than of the business at the other end. What is left says what a network is
// for.
var bgpToolsTagNames = map[string][]string{
	"vpsh":   {"hosting"},
	"dsl":    {"isp"},
	"mobile": {"mobile"},
	"vpn":    {"vpn"},
	"cdn":    {"cdn"},
	"gov":    {"government"},
	"uni":    {"education"},
	"corp":   {"enterprise"},
	"satnet": {"satellite"},
	"perso":  {"personal"},
}

// peeringDBTypes maps PeeringDB's self-reported network type to the same
// vocabulary.
var peeringDBTypes = map[string][]string{
	"Cable/DSL/ISP":        {"isp"},
	"NSP":                  {"transit"},
	"Content":              {"content"},
	"Enterprise":           {"enterprise"},
	"Educational/Research": {"education"},
	"Non-Profit":           {"non-profit"},
	"Network Services":     {"network-services"},
	"Government":           {"government"},
	"Route Server":         {"route-server"},
	"Route Collector":      {"route-server"},
}

// updateCategoryDB builds the category database and atomically replaces
// cfg.categoryPath. A source that fails is reported and skipped: a missing
// provider costs some prefixes, not the whole database.
func updateCategoryDB(cfg config, contact *contactAsker) error {
	fmt.Fprintln(os.Stderr, "asname: building IP->category database")
	b := newCategoryBuilder()

	type source struct {
		name    string
		import_ func() (int, error)
	}
	sources := []source{
		{"AWS", b.importAWS},
		{"Google Cloud", b.importGCP},
		{"Oracle Cloud", b.importOracle},
		{"Fastly", b.importFastly},
		{"Cloudflare", b.importCloudflare},
		{"DigitalOcean", func() (int, error) { return b.importCIDRList(digitalOceanRanges, "", "cloud:digitalocean") }},
		{"Linode", func() (int, error) { return b.importCIDRList(linodeRanges, "", "cloud:linode") }},
		{"Vultr", func() (int, error) { return b.importCIDRList(vultrRanges, "", "cloud:vultr") }},
		{"Tor", func() (int, error) { return b.importCIDRList(torExitList, "", "tor-exit") }},
		{"PeeringDB", b.importPeeringDB},
	}
	// bgp.tools is only contacted once there is an address to identify with.
	if email, ok := contact.contact(); ok {
		sources = append(sources, source{"bgp.tools", func() (int, error) { return b.importBGPTools(email) }})
	}

	imported := 0
	for _, src := range sources {
		n, err := src.import_()
		if err != nil {
			fmt.Fprintf(os.Stderr, "asname: warning: %s: %v\n", src.name, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "asname: %s: %d entries\n", src.name, n)
		imported += n
	}
	if imported == 0 {
		return fmt.Errorf("no categories imported")
	}

	data, err := b.marshal()
	if err != nil {
		return err
	}
	if err := writeFileAtomic(cfg.categoryPath, data); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "asname: wrote %s (%d prefixes, %d ASNs, %d bytes)\n",
		cfg.categoryPath, len(b.prefixes), len(b.asns), len(data))
	return nil
}

// categoryBuilder accumulates tags per prefix and per ASN. Both are maps
// because sources overlap: AWS lists the same prefix under several services,
// and an ASN can carry tags from bgp.tools and PeeringDB at once.
type categoryBuilder struct {
	prefixes map[string]map[string]bool
	asns     map[uint32]map[string]bool
}

func newCategoryBuilder() *categoryBuilder {
	return &categoryBuilder{
		prefixes: make(map[string]map[string]bool),
		asns:     make(map[uint32]map[string]bool),
	}
}

func (b *categoryBuilder) addPrefix(cidr string, tags ...string) {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" || len(tags) == 0 {
		return
	}
	// A bare address is a host route; the Tor exit list is written that way.
	if !strings.Contains(cidr, "/") {
		ip := net.ParseIP(cidr)
		if ip == nil {
			return
		}
		if ip.To4() != nil {
			cidr += "/32"
		} else {
			cidr += "/128"
		}
	}
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return
	}
	set := b.prefixes[cidr]
	if set == nil {
		set = make(map[string]bool, len(tags))
		b.prefixes[cidr] = set
	}
	for _, tag := range tags {
		set[tag] = true
	}
}

func (b *categoryBuilder) addASN(asn uint32, tags ...string) {
	if asn == 0 || len(tags) == 0 {
		return
	}
	set := b.asns[asn]
	if set == nil {
		set = make(map[string]bool, len(tags))
		b.asns[asn] = set
	}
	for _, tag := range tags {
		set[tag] = true
	}
}

// importAWS reads the ranges AWS publish for each of their services. The
// service name is what makes CloudFront distinguishable from EC2, which is the
// difference between "CDN" and "someone's virtual machine".
func (b *categoryBuilder) importAWS() (int, error) { return b.importAWSFrom(awsRanges) }

func (b *categoryBuilder) importAWSFrom(url string) (int, error) {
	var doc struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Service  string `json:"service"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPPrefix string `json:"ipv6_prefix"`
			Service  string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := fetchJSON(url, "", &doc); err != nil {
		return 0, err
	}

	count := 0
	add := func(prefix, service string) {
		tags := []string{"cloud:aws"}
		switch service {
		case "CLOUDFRONT", "CLOUDFRONT_ORIGIN_FACING":
			tags = append(tags, "cdn")
		case "GLOBALACCELERATOR":
			tags = append(tags, "anycast")
		}
		b.addPrefix(prefix, tags...)
		count++
	}
	for _, p := range doc.Prefixes {
		add(p.IPPrefix, p.Service)
	}
	for _, p := range doc.IPv6Prefixes {
		add(p.IPPrefix, p.Service)
	}
	return count, nil
}

func (b *categoryBuilder) importGCP() (int, error) {
	var doc struct {
		Prefixes []struct {
			IPv4 string `json:"ipv4Prefix"`
			IPv6 string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := fetchJSON(gcpRanges, "", &doc); err != nil {
		return 0, err
	}
	count := 0
	for _, p := range doc.Prefixes {
		for _, prefix := range []string{p.IPv4, p.IPv6} {
			if prefix != "" {
				b.addPrefix(prefix, "cloud:gcp")
				count++
			}
		}
	}
	return count, nil
}

func (b *categoryBuilder) importOracle() (int, error) {
	var doc struct {
		Regions []struct {
			CIDRs []struct {
				CIDR string `json:"cidr"`
			} `json:"cidrs"`
		} `json:"regions"`
	}
	if err := fetchJSON(oracleRanges, "", &doc); err != nil {
		return 0, err
	}
	count := 0
	for _, region := range doc.Regions {
		for _, c := range region.CIDRs {
			b.addPrefix(c.CIDR, "cloud:oracle")
			count++
		}
	}
	return count, nil
}

func (b *categoryBuilder) importFastly() (int, error) {
	var doc struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	if err := fetchJSON(fastlyRanges, "", &doc); err != nil {
		return 0, err
	}
	count := 0
	for _, prefix := range append(doc.Addresses, doc.IPv6Addresses...) {
		b.addPrefix(prefix, "cdn", "cloud:fastly")
		count++
	}
	return count, nil
}

func (b *categoryBuilder) importCloudflare() (int, error) {
	total := 0
	for _, url := range []string{cloudflareV4Ranges, cloudflareV6Ranges} {
		n, err := b.importCIDRList(url, "", "cdn", "cloud:cloudflare")
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// importCIDRList reads a list with one prefix per line, which covers the plain
// lists and the RFC 8805 geofeeds several providers publish, where the prefix
// is the first comma-separated field.
func (b *categoryBuilder) importCIDRList(url, userAgent string, tags ...string) (int, error) {
	resp, err := httpGetUA(url, userAgent)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	count := 0
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		prefix, _, _ := strings.Cut(line, ",")
		before := len(b.prefixes)
		b.addPrefix(prefix, tags...)
		if len(b.prefixes) > before {
			count++
		}
	}
	return count, sc.Err()
}

// importBGPTools reads the operator tags, identifying with the contact address
// the user supplied.
func (b *categoryBuilder) importBGPTools(email string) (int, error) {
	agent := bgpToolsUserAgent(email)

	names := make([]string, 0, len(bgpToolsTagNames))
	for name := range bgpToolsTagNames {
		names = append(names, name)
	}
	sort.Strings(names)

	total := 0
	for _, name := range names {
		n, err := b.importBGPToolsTag(name, bgpToolsTagNames[name], agent)
		if err != nil {
			// One tag failing is not worth losing the other twelve over.
			fmt.Fprintf(os.Stderr, "asname: warning: bgp.tools %s: %v\n", name, err)
			continue
		}
		total += n
	}
	if total == 0 {
		return 0, fmt.Errorf("no tags read")
	}
	return total, nil
}

func (b *categoryBuilder) importBGPToolsTag(name string, tags []string, agent string) (int, error) {
	return b.importBGPToolsTagFrom(fmt.Sprintf(bgpToolsTagURL, name), tags, agent)
}

func (b *categoryBuilder) importBGPToolsTagFrom(url string, tags []string, agent string) (int, error) {
	resp, err := httpGetUA(url, agent)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	count := 0
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		// Lines are "AS1234,Operator Name".
		field, _, _ := strings.Cut(sc.Text(), ",")
		asn, ok := parseASN(field)
		if !ok {
			continue
		}
		b.addASN(asn, tags...)
		count++
	}
	return count, sc.Err()
}

// importPeeringDB reads the network type operators report for themselves.
func (b *categoryBuilder) importPeeringDB() (int, error) { return b.importPeeringDBFrom(peeringDBNets) }

func (b *categoryBuilder) importPeeringDBFrom(url string) (int, error) {
	var doc struct {
		Data []struct {
			ASN      uint32 `json:"asn"`
			InfoType string `json:"info_type"`
		} `json:"data"`
	}
	if err := fetchJSON(url, "", &doc); err != nil {
		return 0, err
	}
	count := 0
	for _, net := range doc.Data {
		tags, ok := peeringDBTypes[net.InfoType]
		if !ok {
			continue
		}
		b.addASN(net.ASN, tags...)
		count++
	}
	return count, nil
}

// marshal builds the prefix trie, interns the tag sets and serialises the
// database.
func (b *categoryBuilder) marshal() ([]byte, error) {
	// Tag sets repeat heavily — every Cloudflare prefix carries the same pair —
	// so they are stored once and referred to by index. Index 0 is reserved for
	// "nothing known", which is what the trie returns on a miss.
	sets := []string{""}
	index := map[string]uint32{"": 0}
	intern := func(tags map[string]bool) uint32 {
		key := joinTags(tags)
		if i, ok := index[key]; ok {
			return i
		}
		i := uint32(len(sets))
		sets = append(sets, key)
		index[key] = i
		return i
	}

	var trie trieBuilder = database.NewBuilder()
	for cidr, tags := range b.prefixes {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if err := trie.InsertMapping(ipNet, intern(tags)); err != nil {
			return nil, fmt.Errorf("inserting %s: %v", cidr, err)
		}
	}
	trie.SetFillFactor(optimizationFillFactor)
	built, err := trie.Build()
	if err != nil {
		return nil, fmt.Errorf("building prefix table: %v", err)
	}
	trieBytes, err := built.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// ASNs are written in order so the file is reproducible from one build to
	// the next when the sources have not changed.
	asns := make([]uint32, 0, len(b.asns))
	for asn := range b.asns {
		asns = append(asns, asn)
	}
	slices.Sort(asns)

	asnEntries := make([]byte, 0, len(asns)*8)
	for _, asn := range asns {
		var entry [8]byte
		binary.LittleEndian.PutUint32(entry[0:4], asn)
		binary.LittleEndian.PutUint32(entry[4:8], intern(b.asns[asn]))
		asnEntries = append(asnEntries, entry[:]...)
	}

	out := make([]byte, categoryHeaderSize, categoryHeaderSize+len(trieBytes)+len(asnEntries)+4096)
	copy(out[:8], categoryMagic)
	binary.LittleEndian.PutUint64(out[8:16], uint64(len(trieBytes)))
	binary.LittleEndian.PutUint32(out[16:20], uint32(len(sets)-1))
	binary.LittleEndian.PutUint32(out[20:24], uint32(len(asns)))

	out = append(out, trieBytes...)
	for _, set := range sets[1:] {
		out = append(out, set...)
		out = append(out, 0)
	}
	out = append(out, asnEntries...)
	return out, nil
}

// joinTags renders a tag set in the canonical order the database stores.
func joinTags(tags map[string]bool) string {
	out := make([]string, 0, len(tags))
	for tag := range tags {
		if tag != "" {
			out = append(out, tag)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// parseASN reads "AS1234" or "1234".
func parseASN(s string) (uint32, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "AS"), "as")
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

// fetchJSON gets a URL and decodes it, streaming rather than buffering since
// the AWS and PeeringDB documents are several megabytes.
func fetchJSON(url, userAgent string, into any) error {
	resp, err := httpGetUA(url, userAgent)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(bufio.NewReaderSize(resp.Body, 1<<20)).Decode(into); err != nil {
		return fmt.Errorf("decoding %s: %v", url, err)
	}
	return nil
}

// httpGetUA is httpGet with a caller-chosen User-Agent, for the one source that
// asks to know who is calling.
func httpGetUA(url, userAgent string) (*http.Response, error) {
	if userAgent == "" {
		return httpGet(url)
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return resp, nil
}
