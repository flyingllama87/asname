package sources

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/flyingllama87/asname/pkg/database"
)

const (
	CategoryEnvVar   = "ASNAME_CATEGORY"
	CategoryFilename = "category.db"

	categoryMagic      = "ASNCAT\x00\x01"
	categoryHeaderSize = 24
)

// CategoryDB says what kind of network an address belongs to.
type CategoryDB struct {
	prefixes database.Database
	asns     map[uint32]uint32
	sets     []string
	vpnLists map[string]VPNList
	inferred map[uint32]InferredTags
	// ranges and rangeSets hold the netname rules' range: tags.
	ranges    database.Database
	rangeSets []string
	// relay and relayLocs hold the iCloud Private Relay locations.
	relay     database.Database
	relayLocs []RelayLocation
	// selfReported holds, by AS, the tags only its own PeeringDB entry
	// gives it.
	selfReported map[uint32][]string
}

// VPNList says where the addresses behind a vpn:<provider> tag came from, and
// when that list was current. Date is zero when the source does not say.
type VPNList struct {
	Source string
	Date   time.Time
}

// CategoryDBPresent reports whether the user has opted in to category lookups.
func CategoryDBPresent(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// OpenCategoryDB reads the whole database into memory.
func OpenCategoryDB(path string) (*CategoryDB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < categoryHeaderSize || string(data[:8]) != categoryMagic {
		return nil, fmt.Errorf("not an asname category database (rebuild with `asname update --category-only`)")
	}

	trieLen := binary.LittleEndian.Uint64(data[8:16])
	setCount := binary.LittleEndian.Uint32(data[16:20])
	asnCount := binary.LittleEndian.Uint32(data[20:24])

	rest := data[categoryHeaderSize:]
	if uint64(len(rest)) < trieLen {
		return nil, fmt.Errorf("truncated database: prefix table is short")
	}
	prefixes, err := database.NewFromDump(bytes.NewReader(rest[:trieLen]))
	if err != nil {
		return nil, fmt.Errorf("parsing prefix table: %v", err)
	}
	rest = rest[trieLen:]

	db := &CategoryDB{prefixes: prefixes, sets: make([]string, 1, setCount+1)}
	for range setCount {
		i := bytes.IndexByte(rest, 0)
		if i < 0 {
			return nil, fmt.Errorf("truncated database: tag sets are short")
		}
		db.sets = append(db.sets, string(rest[:i]))
		rest = rest[i+1:]
	}

	if uint64(len(rest)) < uint64(asnCount)*8 {
		return nil, fmt.Errorf("truncated database: ASN table is short")
	}
	db.asns = make(map[uint32]uint32, asnCount)
	for i := range int(asnCount) {
		entry := rest[i*8 : i*8+8]
		db.asns[binary.LittleEndian.Uint32(entry[0:4])] = binary.LittleEndian.Uint32(entry[4:8])
	}
	rest = rest[asnCount*8:]

	// Databases built before the VPN lists were recorded end here.
	if len(rest) < 4 {
		return db, nil
	}
	listCount := binary.LittleEndian.Uint32(rest[:4])
	rest = rest[4:]
	db.vpnLists = make(map[string]VPNList, listCount)
	for range listCount {
		tag, after, ok := bytes.Cut(rest, []byte{0})
		if !ok {
			return nil, fmt.Errorf("truncated database: VPN lists are short")
		}
		source, after, ok := bytes.Cut(after, []byte{0})
		if !ok || len(after) < 8 {
			return nil, fmt.Errorf("truncated database: VPN lists are short")
		}
		list := VPNList{Source: string(source)}
		if unix := int64(binary.LittleEndian.Uint64(after[:8])); unix != 0 {
			list.Date = time.Unix(unix, 0).UTC()
		}
		db.vpnLists[string(tag)] = list
		rest = after[8:]
	}

	// Databases built before asname's own rules end here.
	if len(rest) < 4 {
		return db, nil
	}
	inferredCount := binary.LittleEndian.Uint32(rest[:4])
	rest = rest[4:]
	db.inferred = make(map[uint32]InferredTags, inferredCount)
	for range inferredCount {
		if len(rest) < 6 {
			return nil, fmt.Errorf("truncated database: inferred tags are short")
		}
		asn, from := binary.LittleEndian.Uint32(rest[:4]), rest[4]
		tags, after, ok := bytes.Cut(rest[5:], []byte{0})
		if !ok {
			return nil, fmt.Errorf("truncated database: inferred tags are short")
		}
		inf := InferredTags{Tags: strings.Split(string(tags), ", "), From: InferredFromName}
		if from == 'l' {
			inf.From = InferredFromList
		}
		db.inferred[asn] = inf
		rest = after
	}

	// Databases built before the netname rules end here.
	if len(rest) < 8 {
		return db, nil
	}
	rangeLen := binary.LittleEndian.Uint64(rest[:8])
	rest = rest[8:]
	if uint64(len(rest)) < rangeLen+4 {
		return nil, fmt.Errorf("truncated database: range tags are short")
	}
	if rangeLen > 0 {
		if db.ranges, err = database.NewFromDump(bytes.NewReader(rest[:rangeLen])); err != nil {
			return nil, fmt.Errorf("parsing range table: %v", err)
		}
	}
	rest = rest[rangeLen:]
	rangeSetCount := binary.LittleEndian.Uint32(rest[:4])
	rest = rest[4:]
	db.rangeSets = make([]string, 1, rangeSetCount+1)
	for range rangeSetCount {
		set, after, ok := bytes.Cut(rest, []byte{0})
		if !ok {
			return nil, fmt.Errorf("truncated database: range tag sets are short")
		}
		db.rangeSets = append(db.rangeSets, string(set))
		rest = after
	}

	// Databases built before the Private Relay locations end here.
	if len(rest) < 8 {
		return db, nil
	}
	relayLen := binary.LittleEndian.Uint64(rest[:8])
	rest = rest[8:]
	if uint64(len(rest)) < relayLen+4 {
		return nil, fmt.Errorf("truncated database: relay locations are short")
	}
	if relayLen > 0 {
		if db.relay, err = database.NewFromDump(bytes.NewReader(rest[:relayLen])); err != nil {
			return nil, fmt.Errorf("parsing relay table: %v", err)
		}
	}
	rest = rest[relayLen:]
	locCount := binary.LittleEndian.Uint32(rest[:4])
	rest = rest[4:]
	db.relayLocs = make([]RelayLocation, 1, locCount+1)
	for range locCount {
		loc, after, ok := bytes.Cut(rest, []byte{0})
		if !ok {
			return nil, fmt.Errorf("truncated database: relay locations are short")
		}
		f := strings.SplitN(string(loc), "|", 3)
		for len(f) < 3 {
			f = append(f, "")
		}
		db.relayLocs = append(db.relayLocs, RelayLocation{Country: f[0], Region: f[1], City: f[2]})
		rest = after
	}

	// Databases built before self-reported tags were told apart end here.
	if len(rest) < 4 {
		return db, nil
	}
	selfCount := binary.LittleEndian.Uint32(rest[:4])
	rest = rest[4:]
	db.selfReported = make(map[uint32][]string, selfCount)
	for range selfCount {
		if len(rest) < 5 {
			return nil, fmt.Errorf("truncated database: self-reported tags are short")
		}
		asn := binary.LittleEndian.Uint32(rest[:4])
		tags, after, ok := bytes.Cut(rest[4:], []byte{0})
		if !ok {
			return nil, fmt.Errorf("truncated database: self-reported tags are short")
		}
		db.selfReported[asn] = strings.Split(string(tags), ", ")
		rest = after
	}
	return db, nil
}

// SelfReported returns the tags only asn's own PeeringDB entry gives it:
// what the network says it is, which no other source confirms.
func (d *CategoryDB) SelfReported(asn uint32) []string {
	if d == nil {
		return nil
	}
	return d.selfReported[asn]
}

// RelayLocation returns where Apple says the users of the iCloud Private
// Relay egress range holding ip are.
func (d *CategoryDB) RelayLocation(ip net.IP) (RelayLocation, bool) {
	if d == nil || d.relay == nil {
		return RelayLocation{}, false
	}
	v, err := d.relay.Lookup(ip)
	if err != nil || v.Number == 0 || int(v.Number) >= len(d.relayLocs) {
		return RelayLocation{}, false
	}
	return d.relayLocs[v.Number], true
}

// RangeTag is a tag asname's rules gave the registry range holding an
// address, and what from: InferredFromNetname or InferredFromOwner.
type RangeTag struct {
	Tag, From string
}

// InferredRange returns the tags the netname and netblock-owner rules gave
// the registry range holding ip, or none.
func (d *CategoryDB) InferredRange(ip net.IP) []RangeTag {
	if d.ranges == nil {
		return nil
	}
	v, err := d.ranges.Lookup(ip)
	if err != nil || v.Number == 0 || int(v.Number) >= len(d.rangeSets) {
		return nil
	}
	var out []RangeTag
	for _, tag := range strings.Split(d.rangeSets[v.Number], ", ") {
		if owner, ok := strings.CutPrefix(tag, OwnerTagPrefix); ok {
			out = append(out, RangeTag{Tag: owner, From: InferredFromOwner})
		} else if tag != "" {
			out = append(out, RangeTag{Tag: tag, From: InferredFromNetname})
		}
	}
	return out
}

// asnTags returns every AS's tags, for evaluating the rules.
func (d *CategoryDB) asnTags() map[uint32][]string {
	out := make(map[uint32][]string, len(d.asns))
	for asn, set := range d.asns {
		if set != 0 && int(set) < len(d.sets) {
			out[asn] = strings.Split(d.sets[set], ", ")
		}
	}
	return out
}

// Inferred returns the tags asname's own rules gave asn when the database
// was built (see inferrules.yaml), or none.
func (d *CategoryDB) Inferred(asn uint32) InferredTags {
	return d.inferred[asn]
}

// VPNLists returns where the addresses behind each vpn:<provider> tag in tags
// came from. tags is a Lookup result.
func (d *CategoryDB) VPNLists(tags string) map[string]VPNList {
	var out map[string]VPNList
	for tag := range strings.SplitSeq(tags, ", ") {
		if list, ok := d.vpnLists[tag]; ok {
			if out == nil {
				out = make(map[string]VPNList)
			}
			out[tag] = list
		}
	}
	return out
}

// Lookup returns the categories known for an address and the AS announcing it.
func (d *CategoryDB) Lookup(ip net.IP, asn uint32, haveASN bool) string {
	tags := make(map[string]bool)

	if value, err := d.prefixes.Lookup(ip); err == nil {
		d.collect(value.Number, tags)
	}
	// The network's own tags count unless the address's tags already say
	// what kind of network it is on.
	if haveASN && !hasPrimaryTag(tags) {
		d.collect(d.asns[asn], tags)
	}
	if len(tags) == 0 {
		return ""
	}

	out := make([]string, 0, len(tags))
	for tag := range tags {
		out = append(out, tag)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// LookupASN returns the categories known for an ASN alone.
func (d *CategoryDB) LookupASN(asn uint32) string {
	if d == nil {
		return ""
	}
	tags := make(map[string]bool)
	d.collect(d.asns[asn], tags)
	if len(tags) == 0 {
		return ""
	}
	out := make([]string, 0, len(tags))
	for tag := range tags {
		out = append(out, tag)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func hasPrimaryTag(tags map[string]bool) bool {
	for t := range tags {
		if !SupplementaryTag(t) {
			return true
		}
	}
	return false
}

func (d *CategoryDB) collect(i uint32, tags map[string]bool) {
	if i == 0 || int(i) >= len(d.sets) {
		return
	}
	for tag := range strings.SplitSeq(d.sets[i], ",") {
		if tag != "" {
			tags[tag] = true
		}
	}
}
