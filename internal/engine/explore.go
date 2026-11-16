package engine

import (
	"bytes"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flyingllama87/asname/internal/sources"
)

// Explore lists the announced address space, every prefix in the routing
// table with its origin AS, filtered by size, country, kind of network and
// reputation. The index behind it is built from the local databases the
// first time it is asked for (a few seconds) and kept with the engine.

// ExploreOptions filter and order Explore's prefixes. Zero values match
// everything.
type ExploreOptions struct {
	V4Only, V6Only bool
	// MinLen and MaxLen bound the prefix length: MinLen 8 and MaxLen 8 is
	// every /8. 0 is no bound.
	MinLen, MaxLen int
	// Country, a two-letter code, is where the registry says the prefix's
	// holder is (the country database); ASCountry is the origin AS's.
	Country, ASCountry string
	ASN                uint32
	// Tags keeps prefixes with any of these categories ("hosting", "vpn",
	// "tor-exit"...); a tag ending in ":" or "*" matches its family
	// ("vpn:" matches every vpn:<provider>).
	Tags []string
	// Reputation is one of "", "listed", "clean", "drop", "drop-inside",
	// "asn-drop", "firehol2", "firehol3", "c2".
	Reputation string
	// MinIPsum keeps prefixes holding an address on at least that many
	// IPsum feeds; MinListedPct those with at least that share listed.
	MinIPsum     int
	MinListedPct float64
	// Sort is "address" (default), "size", "listed" or "share"; the last
	// three are largest first.
	Sort          string
	Limit, Offset int
}

// ExplorePrefix is one announced prefix.
type ExplorePrefix struct {
	Prefix    string
	ASN       uint32
	ASName    string
	Country   string // the registry's, "AU, Australia"
	ASCountry string
	Tags      []string
	// Addresses is the prefix's size (IPv4 only; 0 for IPv6).
	Addresses uint64
	// ListedIPs counts its addresses on IPsum or FireHOL; MaxIPsum is the
	// most IPsum feeds naming any one of them.
	ListedIPs      uint64
	ListedSharePct float64
	MaxIPsum       int
	Drop           bool // all of it is on Spamhaus DROP
	DropInside     bool // some of it is on Spamhaus DROP
	ASNDrop        bool // the origin AS is on Spamhaus ASN-DROP
	FireHOL2       bool
	FireHOL3       bool
	// SBL holds the Spamhaus DROP record IDs inside it.
	SBL []string
	// C2 holds the malware families of the C2 servers inside it (Feodo
	// Tracker, C2IntelFeeds, ThreatFox).
	C2 []string
}

// ExploreFacet counts the matching prefixes per value.
type ExploreFacet struct {
	Value string // what to filter on: "AU", "hosting", "AS13335"
	Label string // how to show it: "Australia", "hosting", "AMAZON-02 - Amazon.com, Inc."
	Count int
}

// ExploreResult is a page of matching prefixes, the total, and what they
// break down into.
type ExploreResult struct {
	Total     int
	Addresses uint64 // IPv4 addresses in all matches (nested prefixes count twice)
	Prefixes  []ExplorePrefix
	Countries []ExploreFacet
	Tags      []ExploreFacet
	ASNs      []ExploreFacet
	// AllTags is every tag in the index, for a filter to offer.
	AllTags []string
	Built   time.Time
	Took    time.Duration
}

type exploreRow struct {
	prefix    netip.Prefix
	asn       uint32
	cc, ascc  [2]byte
	tags      uint16 // index into exploreIndex.tagSets
	listed    uint32
	maxIPsum  uint8
	flags     uint8
	sbl       uint16 // index into exploreIndex.sblSets
	c2        uint16 // index into exploreIndex.c2Sets
	addresses uint64
}

const (
	exDrop = 1 << iota // all of the prefix is on DROP
	exASNDrop
	exFH2
	exFH3
	exDropInside // some of it is
	exC2         // some of it is a malware C2 (Feodo, C2IntelFeeds, ThreatFox)
)

type exploreIndex struct {
	once    sync.Once
	err     error
	rows    []exploreRow
	tagSets [][]string
	sblSets [][]string
	c2Sets  [][]string
	allTags []string
	built   time.Time
}

// repSpan is a listed range, decoded once.
type repSpan struct {
	start, end [16]byte
	ipsum      uint8
	flags      uint8
	listed     bool // on IPsum or FireHOL, so counted as listed addresses
	sbl        string
	c2         []string // the malware families of its C2 entries
}

func (e *Engine) exploreIndex() (*exploreIndex, error) {
	x := e.explore
	if x == nil {
		return nil, fmt.Errorf("explore is not available")
	}
	x.once.Do(func() { x.err = e.buildExplore(x) })
	return x, x.err
}

func (e *Engine) buildExplore(x *exploreIndex) error {
	if e.prefixDB == nil {
		return fmt.Errorf("explore needs the prefix database (run `asname update`)")
	}
	var spans []repSpan
	if e.reputationDB != nil {
		err := e.reputationDB.Ranges(func(r sources.RepRange) bool {
			s := repSpan{start: r.Start, end: r.End}
			for _, l := range r.Lists {
				name, detail, _ := strings.Cut(l, ":")
				switch name {
				case "spamhaus-drop":
					s.flags |= exDropInside
					s.sbl = detail
				case "firehol-level2":
					s.flags |= exFH2
					s.listed = true
				case "firehol-level3":
					s.flags |= exFH3
					s.listed = true
				case "ipsum":
					if n, err := strconv.Atoi(detail); err == nil && n > int(s.ipsum) {
						s.ipsum = uint8(min(n, 255))
					}
					s.listed = true
				case "feodo", "c2intel", "threatfox":
					s.flags |= exC2
					s.listed = true
					if detail != "" && !slices.Contains(s.c2, detail) {
						s.c2 = append(s.c2, detail)
					}
				}
			}
			spans = append(spans, s)
			return true
		})
		if err != nil {
			return err
		}
	}

	tagIndex := map[string]uint16{"": 0}
	x.tagSets = [][]string{nil}
	sblIndex := map[string]uint16{"": 0}
	x.sblSets = [][]string{nil}
	c2Index := map[string]uint16{"": 0}
	x.c2Sets = [][]string{nil}
	allTags := map[string]bool{}
	asTags := map[uint32]string{}

	err := e.prefixDB.Each(func(asn uint32, v4, v6 []netip.Prefix) bool {
		_, ascc := splitNameCountry(e.names[asn])
		asDrop := e.reputationDB.ASNDropped(asn)
		for _, p := range append(v4, v6...) {
			p = p.Masked()
			r := exploreRow{prefix: p, asn: asn}
			copy(r.ascc[:], countryCode(ascc))
			first, last := p.Addr(), lastAddr(p)
			if e.countryDB != nil {
				copy(r.cc[:], countryCode(sources.LookupCountry(e.countryDB, net.IP(first.AsSlice()).To16())))
			}
			if p.Addr().Is4() {
				r.addresses = 1 << (32 - p.Bits())
			}
			if asDrop {
				r.flags |= exASNDrop
			}
			// Tags: those of both ends of the prefix, so a tag on part of
			// it is not given to all of it, and the AS's own.
			if e.categoryDB != nil {
				key := prefixTags(e.categoryDB, first, last, asn, asTags)
				id, ok := tagIndex[key]
				if !ok {
					id = uint16(len(x.tagSets))
					tagIndex[key] = id
					tags := strings.Split(key, ", ")
					x.tagSets = append(x.tagSets, tags)
					for _, t := range tags {
						allTags[t] = true
					}
				}
				r.tags = id
			}
			if len(spans) > 0 {
				var sbls []string
				var flags uint8
				flags, r.maxIPsum, r.listed, sbls = scanSpans(spans, first.As16(), lastAddr16(p), p.Addr().Is4())
				r.flags |= flags
				if len(sbls) > 0 {
					key := strings.Join(sbls, ",")
					id, ok := sblIndex[key]
					if !ok && len(x.sblSets) < math.MaxUint16 {
						id = uint16(len(x.sblSets))
						sblIndex[key] = id
						x.sblSets = append(x.sblSets, sbls)
					}
					r.sbl = id
				}
				if flags&exC2 != 0 {
					fams := c2Families(spans, first.As16(), lastAddr16(p))
					key := strings.Join(fams, "\x00")
					id, ok := c2Index[key]
					if !ok && len(x.c2Sets) < math.MaxUint16 {
						id = uint16(len(x.c2Sets))
						c2Index[key] = id
						x.c2Sets = append(x.c2Sets, fams)
					}
					r.c2 = id
				}
			}
			x.rows = append(x.rows, r)
		}
		return true
	})
	if err != nil {
		return err
	}
	sort.Slice(x.rows, func(i, j int) bool {
		a, b := x.rows[i].prefix, x.rows[j].prefix
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
	delete(allTags, "")
	for t := range allTags {
		x.allTags = append(x.allTags, t)
	}
	sort.Strings(x.allTags)
	x.built = time.Now()
	return nil
}

// prefixTags is the tags of both ends of a prefix, joined.
func prefixTags(db *sources.CategoryDB, first, last netip.Addr, asn uint32, asTags map[uint32]string) string {
	a := db.Lookup(net.IP(first.AsSlice()).To16(), asn, true)
	b := a
	if last != first {
		b = db.Lookup(net.IP(last.AsSlice()).To16(), asn, true)
	}
	set := map[string]bool{}
	bs := map[string]bool{}
	for _, t := range strings.Split(b, ", ") {
		bs[t] = true
	}
	for _, t := range strings.Split(a, ", ") {
		if t != "" && bs[t] {
			set[t] = true
		}
	}
	inf, ok := asTags[asn]
	if !ok {
		inf = strings.Join(db.Inferred(asn).Tags, ", ")
		asTags[asn] = inf
	}
	for _, t := range strings.Split(inf, ", ") {
		if t != "" {
			set[t] = true
		}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// scanSpans sums up the listed spans inside [lo, hi]: their flags (with
// exDrop when DROP spans cover all of it), the most IPsum feeds, the IPv4
// addresses on IPsum or FireHOL, and the DROP records, in order. spans are
// sorted and do not overlap, as a trie walk gives them.
func scanSpans(spans []repSpan, lo, hi [16]byte, v4 bool) (flags, maxIPsum uint8, listed uint32, sbls []string) {
	// next is the first address DROP spans have not yet covered, running
	// unbroken from lo.
	next, whole, reached := lo, true, false
	i := sort.Search(len(spans), func(k int) bool { return bytes.Compare(spans[k].end[:], lo[:]) >= 0 })
	for ; i < len(spans) && bytes.Compare(spans[i].start[:], hi[:]) <= 0; i++ {
		s := spans[i]
		flags |= s.flags
		switch {
		case s.flags&exDropInside == 0 || bytes.Compare(s.start[:], next[:]) > 0:
			whole = false
		case bytes.Compare(s.end[:], hi[:]) >= 0:
			reached = true
		default:
			next = incBytes(s.end)
		}
		maxIPsum = max(maxIPsum, s.ipsum)
		if s.listed && v4 {
			a, b := maxBytes(s.start, lo), minBytes(s.end, hi)
			listed += uint32(v4Of(b) - v4Of(a) + 1)
		}
		if s.sbl != "" && (len(sbls) == 0 || sbls[len(sbls)-1] != s.sbl) {
			sbls = append(sbls, s.sbl)
		}
	}
	if whole && reached {
		flags |= exDrop
	}
	return flags, maxIPsum, listed, sbls
}

// c2Families is the malware families of the C2 entries inside [lo, hi],
// sorted.
func c2Families(spans []repSpan, lo, hi [16]byte) []string {
	var out []string
	i := sort.Search(len(spans), func(k int) bool { return bytes.Compare(spans[k].end[:], lo[:]) >= 0 })
	for ; i < len(spans) && bytes.Compare(spans[i].start[:], hi[:]) <= 0; i++ {
		for _, f := range spans[i].c2 {
			if !slices.Contains(out, f) {
				out = append(out, f)
			}
		}
	}
	sort.Strings(out)
	return out
}

// lastAddr16 is lastAddr as 16 bytes, IPv4-mapped for IPv4.
func lastAddr16(p netip.Prefix) [16]byte {
	return lastAddr(p).As16()
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().As16()
	bits := p.Bits()
	if p.Addr().Is4() {
		bits += 96
	}
	for k := bits; k < 128; k++ {
		b[k/8] |= 0x80 >> (k % 8)
	}
	a := netip.AddrFrom16(b)
	if p.Addr().Is4() {
		return a.Unmap()
	}
	return a
}

// incBytes is b+1.
func incBytes(b [16]byte) [16]byte {
	for i := 15; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
	return b
}

func maxBytes(a, b [16]byte) [16]byte {
	if bytes.Compare(a[:], b[:]) >= 0 {
		return a
	}
	return b
}

func minBytes(a, b [16]byte) [16]byte {
	if bytes.Compare(a[:], b[:]) <= 0 {
		return a
	}
	return b
}

func v4Of(b [16]byte) uint64 {
	return uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])
}

func (x *exploreIndex) hasTag(r *exploreRow, want []string) bool {
	if len(want) == 0 {
		return true
	}
	for _, t := range x.tagSets[r.tags] {
		for _, w := range want {
			if fam, ok := strings.CutSuffix(w, "*"); ok {
				w = fam
			}
			if t == w || (strings.HasSuffix(w, ":") && strings.HasPrefix(t, w)) {
				return true
			}
		}
	}
	return false
}

func share(r *exploreRow) float64 {
	if r.addresses == 0 {
		return 0
	}
	return float64(r.listed) * 100 / float64(r.addresses)
}

func (o ExploreOptions) match(x *exploreIndex, r *exploreRow) bool {
	v4 := r.prefix.Addr().Is4()
	if (o.V4Only && !v4) || (o.V6Only && v4) {
		return false
	}
	if o.MinLen > 0 && r.prefix.Bits() < o.MinLen || o.MaxLen > 0 && r.prefix.Bits() > o.MaxLen {
		return false
	}
	if o.ASN != 0 && r.asn != o.ASN {
		return false
	}
	if o.Country != "" && string(r.cc[:]) != o.Country {
		return false
	}
	if o.ASCountry != "" && string(r.ascc[:]) != o.ASCountry {
		return false
	}
	listed := r.listed > 0 || r.flags&(exDrop|exDropInside|exFH2|exFH3|exC2) != 0 || r.maxIPsum > 0
	switch o.Reputation {
	case "listed":
		if !listed && r.flags&exASNDrop == 0 {
			return false
		}
	case "clean":
		if listed || r.flags&exASNDrop != 0 {
			return false
		}
	case "drop":
		if r.flags&exDrop == 0 {
			return false
		}
	case "drop-inside":
		if r.flags&exDropInside == 0 {
			return false
		}
	case "asn-drop":
		if r.flags&exASNDrop == 0 {
			return false
		}
	case "firehol2":
		if r.flags&exFH2 == 0 {
			return false
		}
	case "firehol3":
		if r.flags&(exFH2|exFH3) == 0 {
			return false
		}
	case "c2":
		if r.flags&exC2 == 0 {
			return false
		}
	}
	if o.MinIPsum > 0 && int(r.maxIPsum) < o.MinIPsum {
		return false
	}
	if o.MinListedPct > 0 && share(r) < o.MinListedPct {
		return false
	}
	return x.hasTag(r, o.Tags)
}

// ValidExploreReputation reports whether s is a reputation filter Explore
// knows.
func ValidExploreReputation(s string) bool {
	switch s {
	case "", "listed", "clean", "drop", "drop-inside", "asn-drop", "firehol2", "firehol3", "c2":
		return true
	}
	return false
}

// Explore returns the announced prefixes matching opts.
func (e *Engine) Explore(opts ExploreOptions) (ExploreResult, error) {
	began := time.Now()
	x, err := e.exploreIndex()
	if err != nil {
		return ExploreResult{}, err
	}
	opts.Country = strings.ToUpper(opts.Country)
	opts.ASCountry = strings.ToUpper(opts.ASCountry)
	if !ValidExploreReputation(opts.Reputation) {
		return ExploreResult{}, fmt.Errorf("unknown reputation filter %q", opts.Reputation)
	}

	var hits []int
	var addrs uint64
	countries := map[string]int{}
	tags := map[string]int{}
	asns := map[uint32]int{}
	for i := range x.rows {
		r := &x.rows[i]
		if !opts.match(x, r) {
			continue
		}
		hits = append(hits, i)
		addrs += r.addresses
		countries[string(r.cc[:])]++
		for _, t := range x.tagSets[r.tags] {
			tags[t]++
		}
		asns[r.asn]++
	}

	switch opts.Sort {
	case "size":
		sort.SliceStable(hits, func(i, j int) bool { return x.rows[hits[i]].prefix.Bits() < x.rows[hits[j]].prefix.Bits() })
	case "listed":
		sort.SliceStable(hits, func(i, j int) bool { return x.rows[hits[i]].listed > x.rows[hits[j]].listed })
	case "share":
		sort.SliceStable(hits, func(i, j int) bool { return share(&x.rows[hits[i]]) > share(&x.rows[hits[j]]) })
	}

	res := ExploreResult{Total: len(hits), Addresses: addrs, AllTags: x.allTags, Built: x.built}
	start := min(max(opts.Offset, 0), len(hits))
	end := len(hits)
	if opts.Limit > 0 {
		end = min(start+opts.Limit, len(hits))
	}
	for _, i := range hits[start:end] {
		r := &x.rows[i]
		name := e.names[r.asn]
		p := ExplorePrefix{
			Prefix:         r.prefix.String(),
			ASN:            r.asn,
			ASName:         name,
			Country:        countryLabel(r.cc),
			ASCountry:      countryLabel(r.ascc),
			Tags:           x.tagSets[r.tags],
			Addresses:      r.addresses,
			ListedIPs:      uint64(r.listed),
			ListedSharePct: share(r),
			MaxIPsum:       int(r.maxIPsum),
			Drop:           r.flags&exDrop != 0,
			DropInside:     r.flags&exDropInside != 0,
			ASNDrop:        r.flags&exASNDrop != 0,
			FireHOL2:       r.flags&exFH2 != 0,
			FireHOL3:       r.flags&exFH3 != 0,
			SBL:            x.sblSets[r.sbl],
			C2:             x.c2Sets[r.c2],
		}
		res.Prefixes = append(res.Prefixes, p)
	}
	res.Countries = topFacets(countries, 30, func(cc string) string {
		if n, ok := sources.CountryNames[cc]; ok {
			return n
		}
		return cc
	})
	res.Tags = topFacets(tags, 40, nil)
	asnFacets := map[string]int{}
	for a, n := range asns {
		asnFacets["AS"+strconv.FormatUint(uint64(a), 10)] = n
	}
	res.ASNs = topFacets(asnFacets, 30, func(v string) string {
		n, _ := strconv.ParseUint(strings.TrimPrefix(v, "AS"), 10, 32)
		org, _ := splitNameCountry(e.names[uint32(n)])
		return org
	})
	res.Took = time.Since(began)
	return res, nil
}

func countryLabel(cc [2]byte) string {
	return countryLabelString(string(cc[:]))
}

func countryLabelString(cc string) string {
	cc = strings.TrimRight(cc, "\x00")
	if cc == "" {
		return ""
	}
	if n, ok := sources.CountryNames[cc]; ok {
		return cc + ", " + n
	}
	return cc
}

func topFacets(m map[string]int, n int, label func(string) string) []ExploreFacet {
	out := make([]ExploreFacet, 0, len(m))
	for v, c := range m {
		v = strings.TrimRight(v, "\x00")
		if v == "" {
			continue
		}
		f := ExploreFacet{Value: v, Label: v, Count: c}
		if label != nil {
			f.Label = label(v)
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Value < out[j].Value
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
