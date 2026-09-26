package sources

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/flyingllama87/asname/pkg/database"
)

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

// UpdateCategoryDB builds the category database and atomically replaces cfg.CategoryPath.
func UpdateCategoryDB(ctx context.Context, cfg Config, contact *ContactAsker) error {
	logf(ctx, "asname: building IP->category database\n")
	b := newCategoryBuilder(ctx)

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
		{"DigitalOcean", func() (int, error) { return b.ImportCIDRList(digitalOceanRanges, "", "cloud:digitalocean") }},
		{"Linode", func() (int, error) { return b.ImportCIDRList(linodeRanges, "", "cloud:linode") }},
		{"Vultr", func() (int, error) { return b.ImportCIDRList(vultrRanges, "", "cloud:vultr") }},
		{"Tor", func() (int, error) { return b.ImportCIDRList(torExitList, "", "tor-exit") }},
		{"PeeringDB", b.importPeeringDB},
	}
	if email, ok := contact.Contact(); ok {
		sources = append(sources, source{"bgp.tools", func() (int, error) { return b.importBGPTools(email) }})
	}

	imported := 0
	for _, src := range sources {
		n, err := src.import_()
		if err != nil {
			logf(ctx, "asname: warning: %s: %v\n", src.name, err)
			continue
		}
		logf(ctx, "asname: %s: %d entries\n", src.name, n)
		imported += n
	}
	if imported == 0 {
		return fmt.Errorf("no categories imported")
	}

	data, err := b.Marshal()
	if err != nil {
		return err
	}
	if err := WriteFileAtomic(cfg.CategoryPath, data); err != nil {
		return err
	}
	logf(ctx, "asname: wrote %s (%d prefixes, %d ASNs, %d bytes)\n",
		cfg.CategoryPath, len(b.prefixes), len(b.asns), len(data))
	return nil
}

type categoryBuilder struct {
	// ctx bounds the builder's downloads and carries its log writer; the
	// builder lives for one UpdateCategoryDB call.
	ctx      context.Context
	prefixes map[string]map[string]bool
	asns     map[uint32]map[string]bool
}

func newCategoryBuilder(ctx context.Context) *categoryBuilder {
	return &categoryBuilder{
		ctx:      ctx,
		prefixes: make(map[string]map[string]bool),
		asns:     make(map[uint32]map[string]bool),
	}
}

func (b *categoryBuilder) addPrefix(cidr string, tags ...string) {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" || len(tags) == 0 {
		return
	}
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

func (b *categoryBuilder) importAWS() (int, error) { return b.ImportAWSFrom(awsRanges) }

func (b *categoryBuilder) ImportAWSFrom(url string) (int, error) {
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
	if err := fetchJSON(b.ctx, url, "", &doc); err != nil {
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
	if err := fetchJSON(b.ctx, gcpRanges, "", &doc); err != nil {
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
	if err := fetchJSON(b.ctx, oracleRanges, "", &doc); err != nil {
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
	if err := fetchJSON(b.ctx, fastlyRanges, "", &doc); err != nil {
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
		n, err := b.ImportCIDRList(url, "", "cdn", "cloud:cloudflare")
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func (b *categoryBuilder) ImportCIDRList(url, userAgent string, tags ...string) (int, error) {
	resp, err := httpGetUA(b.ctx, url, userAgent)
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

func (b *categoryBuilder) importBGPTools(email string) (int, error) {
	agent := BGPToolsUserAgent(email)

	names := make([]string, 0, len(bgpToolsTagNames))
	for name := range bgpToolsTagNames {
		names = append(names, name)
	}
	sort.Strings(names)

	total := 0
	for _, name := range names {
		n, err := b.importBGPToolsTag(name, bgpToolsTagNames[name], agent)
		if err != nil {
			logf(b.ctx, "asname: warning: bgp.tools %s: %v\n", name, err)
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
	return b.ImportBGPToolsTagFrom(fmt.Sprintf(bgpToolsTagURL, name), tags, agent)
}

func (b *categoryBuilder) ImportBGPToolsTagFrom(url string, tags []string, agent string) (int, error) {
	resp, err := httpGetUA(b.ctx, url, agent)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	count := 0
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		field, _, _ := strings.Cut(sc.Text(), ",")
		asn, ok := ParseASN(field)
		if !ok {
			continue
		}
		b.addASN(asn, tags...)
		count++
	}
	return count, sc.Err()
}

func (b *categoryBuilder) importPeeringDB() (int, error) { return b.ImportPeeringDBFrom(peeringDBNets) }

func (b *categoryBuilder) ImportPeeringDBFrom(url string) (int, error) {
	var doc struct {
		Data []struct {
			ASN      uint32 `json:"asn"`
			InfoType string `json:"info_type"`
		} `json:"data"`
	}
	if err := fetchJSON(b.ctx, url, "", &doc); err != nil {
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

func (b *categoryBuilder) Marshal() ([]byte, error) {
	sets := []string{""}
	index := map[string]uint32{"": 0}
	intern := func(tags map[string]bool) uint32 {
		key := JoinTags(tags)
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
	trie.SetFillFactor(OptimizationFillFactor)
	built, err := trie.Build()
	if err != nil {
		return nil, fmt.Errorf("building prefix table: %v", err)
	}
	trieBytes, err := built.MarshalBinary()
	if err != nil {
		return nil, err
	}

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

func JoinTags(tags map[string]bool) string {
	out := make([]string, 0, len(tags))
	for tag := range tags {
		if tag != "" {
			out = append(out, tag)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func ParseASN(s string) (uint32, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "AS"), "as")
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

func fetchJSON(ctx context.Context, url, userAgent string, into any) error {
	resp, err := httpGetUA(ctx, url, userAgent)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(bufio.NewReaderSize(resp.Body, 1<<20)).Decode(into); err != nil {
		return fmt.Errorf("decoding %s: %v", url, err)
	}
	return nil
}

// httpGetUA issues a GET bound to ctx, sending userAgent when it is set, and
// treats any status but 200 as an error.
func httpGetUA(ctx context.Context, url, userAgent string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
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
