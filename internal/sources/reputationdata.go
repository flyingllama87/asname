package sources

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/flyingllama87/asname/pkg/database"
)

const (
	spamhausASNDrop = "https://www.spamhaus.org/drop/asndrop.json"
	spamhausDropV4  = "https://www.spamhaus.org/drop/drop_v4.json"
	spamhausDropV6  = "https://www.spamhaus.org/drop/drop_v6.json"
	ipsumList       = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
	fireholLevel2   = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset"
	fireholLevel3   = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset"

	// maxExpandBits caps how large an IPv4 block is counted address by
	// address towards an ASN's listed IPs; a larger block counts once.
	maxExpandBits = 16
)

// UpdateReputationDB downloads the blocklists, builds the reputation
// database and atomically replaces cfg.ReputationPath. Per-ASN counts are
// attributed with the ASN database at cfg.DBPath; without it they are
// skipped and only the ASN-DROP list is recorded per ASN.
func UpdateReputationDB(ctx context.Context, cfg Config) error {
	logf(ctx, "asname: building IP->reputation database\n")
	b := newReputationBuilder(ctx)

	type source struct {
		name    string
		import_ func() (int, error)
	}
	srcs := []source{
		{"Spamhaus ASN-DROP", func() (int, error) { return b.ImportASNDropFrom(spamhausASNDrop) }},
		{"Spamhaus DROP IPv4", func() (int, error) { return b.ImportDropFrom(spamhausDropV4) }},
		{"Spamhaus DROP IPv6", func() (int, error) { return b.ImportDropFrom(spamhausDropV6) }},
		{"IPsum", func() (int, error) { return b.ImportIPsumFrom(ipsumList) }},
		{"FireHOL level 2", func() (int, error) { return b.ImportNetsetFrom(fireholLevel2, "firehol-level2") }},
		{"FireHOL level 3", func() (int, error) { return b.ImportNetsetFrom(fireholLevel3, "firehol-level3") }},
	}

	imported := 0
	for _, src := range srcs {
		n, err := src.import_()
		if err != nil {
			logf(ctx, "asname: warning: %s: %v\n", src.name, err)
			continue
		}
		logf(ctx, "asname: %s: %d entries\n", src.name, n)
		imported += n
	}
	if imported == 0 {
		return fmt.Errorf("no blocklist entries imported")
	}

	if f, err := os.Open(cfg.DBPath); err != nil {
		logf(ctx, "asname: warning: ASN database unavailable, skipping per-ASN counts: %v\n", err)
	} else {
		asnDB, err := database.NewFromDump(f)
		f.Close()
		if err != nil {
			logf(ctx, "asname: warning: ASN database unreadable, skipping per-ASN counts: %v\n", err)
		} else {
			b.Attribute(asnDB)
		}
	}

	data, err := b.Marshal(time.Now())
	if err != nil {
		return err
	}
	if err := WriteFileAtomic(cfg.ReputationPath, data); err != nil {
		return err
	}
	logf(ctx, "asname: wrote %s (%d prefixes, %d ASNs, %d bytes)\n",
		cfg.ReputationPath, len(b.prefixes), len(b.asns), len(data))
	return nil
}

type reputationBuilder struct {
	ctx context.Context
	// prefixes maps every listed address or block to the lists naming it.
	prefixes map[netip.Prefix]map[string]bool
	// listed holds the addresses and blocks from the address-level lists
	// (IPsum and FireHOL), which are what an ASN's listed IP count counts.
	listed map[netip.Prefix]bool
	// ipsum is each address's IPsum count, for an ASN's MaxLists.
	ipsum map[netip.Addr]uint32
	// drop holds the Spamhaus DROP blocks, counted per ASN.
	drop []netip.Prefix
	asns map[uint32]*ASNReputation
}

func newReputationBuilder(ctx context.Context) *reputationBuilder {
	return &reputationBuilder{
		ctx:      ctx,
		prefixes: make(map[netip.Prefix]map[string]bool),
		listed:   make(map[netip.Prefix]bool),
		ipsum:    make(map[netip.Addr]uint32),
		asns:     make(map[uint32]*ASNReputation),
	}
}

// parsePrefix reads an address or CIDR, returning it masked.
func parsePrefix(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		return p.Masked(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), true
}

func (b *reputationBuilder) addPrefix(p netip.Prefix, tag string) {
	set := b.prefixes[p]
	if set == nil {
		set = make(map[string]bool, 1)
		b.prefixes[p] = set
	}
	set[tag] = true
}

func (b *reputationBuilder) asn(asn uint32) *ASNReputation {
	r := b.asns[asn]
	if r == nil {
		r = &ASNReputation{}
		b.asns[asn] = r
	}
	return r
}

// ImportASNDropFrom reads Spamhaus ASN-DROP, one JSON object per line.
func (b *reputationBuilder) ImportASNDropFrom(url string) (int, error) {
	count := 0
	err := b.eachJSONLine(url, func(line []byte) {
		var rec struct {
			ASN uint32 `json:"asn"`
		}
		if json.Unmarshal(line, &rec) == nil && rec.ASN != 0 {
			b.asn(rec.ASN).ASNDrop = true
			count++
		}
	})
	return count, err
}

// ImportDropFrom reads a Spamhaus DROP list, one JSON object per line.
func (b *reputationBuilder) ImportDropFrom(url string) (int, error) {
	count := 0
	err := b.eachJSONLine(url, func(line []byte) {
		var rec struct {
			CIDR  string `json:"cidr"`
			SBLID string `json:"sblid"`
		}
		if json.Unmarshal(line, &rec) != nil {
			return
		}
		p, ok := parsePrefix(rec.CIDR)
		if !ok {
			return
		}
		tag := "spamhaus-drop"
		if rec.SBLID != "" {
			tag += ":" + rec.SBLID
		}
		b.addPrefix(p, tag)
		b.drop = append(b.drop, p)
		count++
	})
	return count, err
}

// ImportIPsumFrom reads IPsum: an address, a tab, and how many lists name it.
func (b *reputationBuilder) ImportIPsumFrom(url string) (int, error) {
	count := 0
	err := b.eachLine(url, func(line string) {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return
		}
		p, ok := parsePrefix(fields[0])
		n, err := strconv.ParseUint(fields[1], 10, 32)
		if !ok || err != nil || n == 0 {
			return
		}
		b.addPrefix(p, "ipsum:"+fields[1])
		b.listed[p] = true
		b.ipsum[p.Addr()] = uint32(n)
		count++
	})
	return count, err
}

// ImportNetsetFrom reads a FireHOL netset: one address or CIDR per line.
func (b *reputationBuilder) ImportNetsetFrom(url, tag string) (int, error) {
	count := 0
	err := b.eachLine(url, func(line string) {
		p, ok := parsePrefix(line)
		if !ok {
			return
		}
		b.addPrefix(p, tag)
		b.listed[p] = true
		count++
	})
	return count, err
}

func (b *reputationBuilder) eachLine(url string, fn func(string)) error {
	resp, err := httpGetUA(b.ctx, url, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return scanLines(resp.Body, fn)
}

func scanLines(r io.Reader, fn func(string)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		fn(line)
	}
	return sc.Err()
}

func (b *reputationBuilder) eachJSONLine(url string, fn func([]byte)) error {
	return b.eachLine(url, func(line string) { fn([]byte(line)) })
}

// Attribute counts each listed address and DROP block towards the ASN that
// announces it in asnDB.
func (b *reputationBuilder) Attribute(asnDB database.Database) {
	origin := func(a netip.Addr) (uint32, bool) {
		as, err := asnDB.Lookup(net.IP(a.AsSlice()).To16())
		if err != nil || as.Number == 0 {
			return 0, false
		}
		return as.Number, true
	}

	// An address can be on several lists, and a FireHOL block can cover an
	// IPsum address, so IPv4 addresses are counted once each.
	seen := make(map[netip.Addr]bool, len(b.listed))
	for p := range b.listed {
		if !p.Addr().Is4() || p.Bits() < 32-maxExpandBits {
			if asn, ok := origin(p.Addr()); ok {
				b.asn(asn).ListedIPs++
			}
			continue
		}
		for a := p.Addr(); p.Contains(a); a = a.Next() {
			if seen[a] {
				continue
			}
			seen[a] = true
			asn, ok := origin(a)
			if !ok {
				continue
			}
			r := b.asn(asn)
			r.ListedIPs++
			if n := b.ipsum[a]; n > r.MaxLists {
				r.MaxLists = n
			}
		}
	}
	for _, p := range b.drop {
		if asn, ok := origin(p.Addr()); ok {
			b.asn(asn).DropPrefixes++
		}
	}
}

// inheritCovering adds to each prefix the tags of every listed prefix that
// covers it, since a trie lookup returns only the most specific match.
func (b *reputationBuilder) inheritCovering() {
	lengths := map[bool][]int{}
	for p := range b.prefixes {
		v4 := p.Addr().Is4()
		if !slices.Contains(lengths[v4], p.Bits()) {
			lengths[v4] = append(lengths[v4], p.Bits())
		}
	}
	for p, set := range b.prefixes {
		for _, bits := range lengths[p.Addr().Is4()] {
			if bits >= p.Bits() {
				continue
			}
			parent, err := p.Addr().Prefix(bits)
			if err != nil {
				continue
			}
			for tag := range b.prefixes[parent] {
				set[tag] = true
			}
		}
	}
}

// Marshal serialises the database; built is recorded as when the lists were read.
func (b *reputationBuilder) Marshal(built time.Time) ([]byte, error) {
	b.inheritCovering()

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
	for p, tags := range b.prefixes {
		ipNet := &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
		if err := trie.InsertMapping(ipNet, intern(tags)); err != nil {
			return nil, fmt.Errorf("inserting %s: %v", p, err)
		}
	}
	trie.SetFillFactor(OptimizationFillFactor)
	table, err := trie.Build()
	if err != nil {
		return nil, fmt.Errorf("building prefix table: %v", err)
	}
	trieBytes, err := table.MarshalBinary()
	if err != nil {
		return nil, err
	}

	asns := make([]uint32, 0, len(b.asns))
	for asn := range b.asns {
		asns = append(asns, asn)
	}
	slices.Sort(asns)

	out := make([]byte, reputationHeaderSize, reputationHeaderSize+len(trieBytes)+len(asns)*reputationASNEntry+4096)
	copy(out[:8], reputationMagic)
	binary.LittleEndian.PutUint64(out[8:16], uint64(len(trieBytes)))
	binary.LittleEndian.PutUint32(out[16:20], uint32(len(sets)-1))
	binary.LittleEndian.PutUint32(out[20:24], uint32(len(asns)))
	binary.LittleEndian.PutUint64(out[24:32], uint64(built.Unix()))

	out = append(out, trieBytes...)
	for _, set := range sets[1:] {
		out = append(out, set...)
		out = append(out, 0)
	}
	for _, asn := range asns {
		r := b.asns[asn]
		var e [reputationASNEntry]byte
		var flags uint32
		if r.ASNDrop {
			flags |= repFlagASNDrop
		}
		binary.LittleEndian.PutUint32(e[0:4], asn)
		binary.LittleEndian.PutUint32(e[4:8], flags)
		binary.LittleEndian.PutUint32(e[8:12], r.ListedIPs)
		binary.LittleEndian.PutUint32(e[12:16], r.DropPrefixes)
		binary.LittleEndian.PutUint32(e[16:20], r.MaxLists)
		out = append(out, e[:]...)
	}
	return out, nil
}
