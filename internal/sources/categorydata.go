package sources

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
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
func UpdateCategoryDB(ctx context.Context, cfg Config, contact *ContactAsker) (err error) {
	ctx, done := beginUpdate(ctx, cfg, KeyCategory)
	defer func() { done(err) }()

	logf(ctx, "asname: building IP->category database\n")
	ctx, cache := withSourceCache(ctx, cfg.CacheDir())
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
		{"VPN providers", func() (int, error) { return b.ImportVPNServers(vpnAPIs, gluetunServerLists) }},
		{"PeeringDB", b.importPeeringDB},
	}
	if email, ok := contact.Contact(); ok {
		sources = append(sources, source{"bgp.tools", func() (int, error) { return b.importBGPTools(email) }})
	}

	imported := 0
	for _, src := range sources {
		cache.begin()
		n, err := src.import_()
		if err != nil {
			cache.discard()
			logf(ctx, "asname: warning: %s: %v\n", src.name, err)
			noteFailed(ctx, src.name)
			continue
		}
		logf(ctx, "asname: %s: %d entries\n", src.name, n)
		noteSource(ctx, src.name, n, "")
		imported += n
	}
	if imported == 0 {
		return fmt.Errorf("no categories imported")
	}

	if n, err := b.importInferred(cfg.NamesPath); err != nil {
		logf(ctx, "asname: warning: %s: %v\n", InferSourceName, err)
		noteFailed(ctx, InferSourceName)
	} else {
		logf(ctx, "asname: %s: %d ASNs\n", InferSourceName, n)
		noteSource(ctx, InferSourceName, n, "")
	}
	// Netname rules need the netblock database, which is optional.
	if NetblockDBPresent(cfg.NetblockPath) {
		if st, err := b.importNetnames(cfg.NetblockPath, cfg.DBPath); err != nil {
			logf(ctx, "asname: warning: %s: %v\n", InferNetnameSourceName, err)
			noteFailed(ctx, InferNetnameSourceName)
		} else {
			n := 0
			for _, c := range st.ranges {
				n += c
			}
			logf(ctx, "asname: %s: %d ranges\n", InferNetnameSourceName, n)
			noteSource(ctx, InferNetnameSourceName, n, "")
		}
	} else {
		noteUnused(ctx, InferNetnameSourceName, "not used: needs the netblock database")
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
	// vpnLists records where each vpn:<provider> tag's addresses came from.
	vpnLists map[string]VPNList
	// inferred holds the tags asname's own rules give each AS
	// (inferrules.yaml), kept apart from the sources' tags.
	inferred map[uint32]InferredTags
	// rangeTags holds the range: tags the netname rules give registry
	// ranges, by prefix; kept apart like inferred.
	rangeTags map[netip.Prefix]map[string]bool
	// lookupHost resolves the hostnames some VPN providers list instead of
	// addresses.
	lookupHost func(ctx context.Context, host string) ([]string, error)
}

func newCategoryBuilder(ctx context.Context) *categoryBuilder {
	return &categoryBuilder{
		ctx:        ctx,
		prefixes:   make(map[string]map[string]bool),
		asns:       make(map[uint32]map[string]bool),
		vpnLists:   make(map[string]VPNList),
		inferred:   make(map[uint32]InferredTags),
		rangeTags:  make(map[netip.Prefix]map[string]bool),
		lookupHost: net.DefaultResolver.LookupHost,
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
			noteFailed(b.ctx, "bgp.tools "+name)
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

	// A VPN or Tor address inside a cloud range keeps the cloud's tags too.
	prefixes := make(map[netip.Prefix]map[string]bool, len(b.prefixes))
	for cidr, tags := range b.prefixes {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		p = p.Masked()
		set := prefixes[p]
		if set == nil {
			set = make(map[string]bool, len(tags))
			prefixes[p] = set
		}
		for tag := range tags {
			set[tag] = true
		}
	}
	inheritCovering(prefixes)

	var trie trieBuilder = database.NewBuilder()
	for p, tags := range prefixes {
		ipNet := &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
		if err := trie.InsertMapping(ipNet, intern(tags)); err != nil {
			return nil, fmt.Errorf("inserting %s: %v", p, err)
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

	// The VPN lists trail the ASN table, so a reader that predates them
	// stops before reaching them.
	listed := make([]string, 0, len(b.vpnLists))
	for tag := range b.vpnLists {
		listed = append(listed, tag)
	}
	sort.Strings(listed)
	vpnLists := binary.LittleEndian.AppendUint32(nil, uint32(len(listed)))
	for _, tag := range listed {
		list := b.vpnLists[tag]
		var unix int64
		if !list.Date.IsZero() {
			unix = list.Date.Unix()
		}
		vpnLists = append(vpnLists, tag...)
		vpnLists = append(vpnLists, 0)
		vpnLists = append(vpnLists, list.Source...)
		vpnLists = append(vpnLists, 0)
		vpnLists = binary.LittleEndian.AppendUint64(vpnLists, uint64(unix))
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
	out = append(out, vpnLists...)
	out = append(out, b.marshalInferred()...)
	ranges, err := b.marshalRangeTags()
	if err != nil {
		return nil, err
	}
	out = append(out, ranges...)
	return out, nil
}

// InferNetnameSourceName names asname's netname rules among the sources.
const InferNetnameSourceName = "asname netname rules"

// netnameStats counts what importNetnames tagged, for logs and evaluation.
type netnameStats struct {
	ranges, skipped map[string]int
	addrs4          map[string]uint64
	samples         map[string][]string
}

// importNetnames gives range: tags to the netblock database's ranges whose
// netnames the rules recognise (inferrules.yaml), skipping ranges inside
// networks that only host servers. b.asns and b.inferred must already hold
// this build's AS tags; asnDBPath says which AS announces each range.
func (b *categoryBuilder) importNetnames(netblockPath, asnDBPath string) (netnameStats, error) {
	st := netnameStats{ranges: map[string]int{}, skipped: map[string]int{}, addrs4: map[string]uint64{}, samples: map[string][]string{}}
	rules, err := DefaultInferRules()
	if err != nil {
		return st, err
	}
	nb, err := OpenNetblockDB(netblockPath)
	if err != nil {
		return st, err
	}
	defer nb.Close()
	f, err := os.Open(asnDBPath)
	if err != nil {
		return st, fmt.Errorf("needs the ASN database: %v", err)
	}
	asnDB, err := database.NewFromDump(f)
	f.Close()
	if err != nil {
		return st, fmt.Errorf("reading the ASN database: %v", err)
	}

	// Netnames repeat across ranges, so each is classified once.
	byOffset := map[uint32][]string{}
	hostingOnly := map[uint32]bool{}
	asnKnown := map[uint32]bool{}
	seen := 0
	err = nb.EachRange(func(r NetblockRange) error {
		if r.NetnameOff == 0 {
			return nil
		}
		tags, ok := byOffset[r.NetnameOff]
		if !ok {
			name, err := nb.str(r.NetnameOff)
			if err != nil {
				return err
			}
			tags = rules.InferNetname(name)
			byOffset[r.NetnameOff] = tags
		}
		if len(tags) == 0 {
			return nil
		}
		var asn uint32
		if as, err := asnDB.Lookup(net.IP(r.Start.AsSlice()).To16()); err == nil {
			asn = as.Number
		}
		if !asnKnown[asn] {
			asnKnown[asn] = true
			all := slices.Collect(maps.Keys(b.asns[asn]))
			all = append(all, b.inferred[asn].Tags...)
			hostingOnly[asn] = HostingOnly(all)
		}
		keep := tags[:0:0]
		for _, tag := range tags {
			if hostingOnly[asn] {
				st.skipped[tag]++
				continue
			}
			keep = append(keep, tag)
		}
		if len(keep) == 0 {
			return nil
		}
		for _, cidr := range rangeCIDRs(r.Start, r.End) {
			set := b.rangeTags[cidr]
			if set == nil {
				set = map[string]bool{}
				b.rangeTags[cidr] = set
			}
			for _, tag := range keep {
				set[tag] = true
			}
		}
		seen++
		for _, tag := range keep {
			st.ranges[tag]++
			if r.Start.Is4() {
				st.addrs4[tag] += uint64(addrUint32(r.End)-addrUint32(r.Start)) + 1
			}
			// An even spread of samples for review.
			if st.ranges[tag]%97 == 1 && len(st.samples[tag]) < 60 {
				name, _ := nb.str(r.NetnameOff)
				st.samples[tag] = append(st.samples[tag], fmt.Sprintf("%s-%s %s AS%d", r.Start, r.End, name, asn))
			}
		}
		return nil
	})
	return st, err
}

func addrUint32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

// rangeCIDRs covers start..end with the fewest prefixes.
func rangeCIDRs(start, end netip.Addr) []netip.Prefix {
	var strs []string
	if start.Is4() {
		strs = IPv4RangeToCIDRs(addrUint32(start), addrUint32(end))
	} else {
		strs = IPv6RangeToCIDRs(start.As16(), end.As16())
	}
	out := make([]netip.Prefix, 0, len(strs))
	for _, s := range strs {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// marshalRangeTags encodes the netname range tags after the inferred AS
// tags: the length of a prefix table, the table (each prefix maps to an
// index into the sets that follow), the number of sets, and the sets, each
// tags joined by ", " and NUL-terminated.
func (b *categoryBuilder) marshalRangeTags() ([]byte, error) {
	sets := []string{""}
	index := map[string]uint32{"": 0}
	var trie trieBuilder = database.NewBuilder()
	for p, tags := range b.rangeTags {
		key := JoinTags(tags)
		i, ok := index[key]
		if !ok {
			i = uint32(len(sets))
			sets = append(sets, key)
			index[key] = i
		}
		ipNet := &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
		if err := trie.InsertMapping(ipNet, i); err != nil {
			return nil, fmt.Errorf("inserting %s: %v", p, err)
		}
	}
	var trieBytes []byte
	if len(b.rangeTags) > 0 {
		trie.SetFillFactor(OptimizationFillFactor)
		built, err := trie.Build()
		if err != nil {
			return nil, fmt.Errorf("building range table: %v", err)
		}
		if trieBytes, err = built.MarshalBinary(); err != nil {
			return nil, err
		}
	}
	out := binary.LittleEndian.AppendUint64(nil, uint64(len(trieBytes)))
	out = append(out, trieBytes...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(sets)-1))
	for _, set := range sets[1:] {
		out = append(out, set...)
		out = append(out, 0)
	}
	return out, nil
}

// InferSourceName names asname's own rules among the category sources.
const InferSourceName = "asname name rules"

// importInferred applies asname's rules to every AS in the names list at
// namesPath and returns how many ASNs got a tag.
func (b *categoryBuilder) importInferred(namesPath string) (int, error) {
	rules, err := DefaultInferRules()
	if err != nil {
		return 0, err
	}
	names, err := LoadNames(namesPath)
	if err != nil {
		return 0, fmt.Errorf("needs the AS names list: %v", err)
	}
	for asn, name := range names {
		if inf := rules.Infer(asn, name); len(inf.Tags) > 0 {
			b.inferred[asn] = inf
		}
	}
	return len(b.inferred), nil
}

// marshalInferred encodes the inferred tags, which trail the VPN lists so a
// reader that predates them stops before reaching them: a count, then per
// ASN its number, 'n' (from the name) or 'l' (from asname's list), and its
// tags joined by ", " and NUL-terminated.
func (b *categoryBuilder) marshalInferred() []byte {
	asns := make([]uint32, 0, len(b.inferred))
	for asn := range b.inferred {
		asns = append(asns, asn)
	}
	slices.Sort(asns)
	out := binary.LittleEndian.AppendUint32(nil, uint32(len(asns)))
	for _, asn := range asns {
		inf := b.inferred[asn]
		from := byte('n')
		if inf.From == InferredFromList {
			from = 'l'
		}
		out = binary.LittleEndian.AppendUint32(out, asn)
		out = append(out, from)
		out = append(out, strings.Join(inf.Tags, ", ")...)
		out = append(out, 0)
	}
	return out
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
		// A cached payload that will not decode must not be served again.
		if sc, ok := ctx.Value(sourceCacheKey{}).(*sourceCache); ok {
			dropCached(sc.dir, url)
		}
		return fmt.Errorf("decoding %s: %v", url, err)
	}
	return nil
}

// httpGetUA issues a GET bound to ctx, sending userAgent when it is set, and
// treats any status but 200 as an error.
func httpGetUA(ctx context.Context, url, userAgent string) (*http.Response, error) {
	if sc, ok := ctx.Value(sourceCacheKey{}).(*sourceCache); ok {
		return sc.get(ctx, url, userAgent)
	}
	resp, err := doWithRetry(ctx, url, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", orDefaultAgent(userAgent))
		return req, nil
	})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return resp, nil
}
