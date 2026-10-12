package sources

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/flyingllama87/asname/pkg/database"
)

const (
	ReputationEnvVar   = "ASNAME_REPUTATION"
	ReputationFilename = "reputation.db"

	// ReputationMaxAge is how old the CLI lets the reputation database get
	// before refreshing it. Blocklists change daily, so this is much shorter
	// than the default for the other databases.
	ReputationMaxAge = 24 * time.Hour

	reputationMagic      = "ASNREP\x00\x01"
	reputationHeaderSize = 32
	reputationASNEntry   = 20

	repFlagASNDrop = 1 << 0
)

// ASNReputation is what the blocklists say about an Autonomous System as a
// whole. ListedIPs counts the distinct addresses the IPsum and FireHOL lists
// name inside the ASN's routes when the database was built; MaxLists is the
// highest IPsum count among them. AnnouncedIPv4 is filled in by the engine
// from the prefix database, so ListedIPs can be read as a share of the
// ASN's address space; it is zero when that is unknown.
type ASNReputation struct {
	ASNDrop       bool
	ListedIPs     uint32
	DropPrefixes  uint32
	MaxLists      uint32
	AnnouncedIPv4 uint64
}

// Listed reports whether any list names the ASN or anything inside it.
func (r ASNReputation) Listed() bool {
	return r.ASNDrop || r.ListedIPs > 0 || r.DropPrefixes > 0
}

// ListedShare is ListedIPs as a percentage of AnnouncedIPv4, or -1 when the
// announced space is unknown.
func (r ASNReputation) ListedShare() float64 {
	if r.AnnouncedIPv4 == 0 {
		return -1
	}
	return float64(r.ListedIPs) * 100 / float64(r.AnnouncedIPv4)
}

// String renders the ASN's reputation on one line, such as "Spamhaus
// ASN-DROP; 11 listed IPs (0.54% of 2048 announced IPv4), max 7 lists".
func (r ASNReputation) String() string {
	if !r.Listed() {
		return "not listed"
	}
	var parts []string
	if r.ASNDrop {
		parts = append(parts, "Spamhaus ASN-DROP")
	}
	if r.DropPrefixes > 0 {
		parts = append(parts, plural(r.DropPrefixes, "Spamhaus DROP prefix", "Spamhaus DROP prefixes"))
	}
	if r.ListedIPs > 0 {
		s := plural(r.ListedIPs, "listed IP", "listed IPs")
		if share := r.ListedShare(); share >= 0 {
			s += fmt.Sprintf(" (%s of %d announced IPv4)", FormatShare(share), r.AnnouncedIPv4)
		}
		if r.MaxLists > 0 {
			s += fmt.Sprintf(", max %d lists", r.MaxLists)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "; ")
}

func plural(n uint32, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// FormatShare renders a percentage with enough precision to tell a small
// share from none.
func FormatShare(p float64) string {
	switch {
	case p >= 10:
		return fmt.Sprintf("%.0f%%", p)
	case p >= 0.1:
		return fmt.Sprintf("%.2f%%", p)
	default:
		return fmt.Sprintf("%.4f%%", p)
	}
}

// ReputationDB says which public blocklists name an address or an ASN.
type ReputationDB struct {
	prefixes database.Database
	asns     map[uint32]ASNReputation
	sets     []string
	Built    time.Time
}

// ReputationDBPresent reports whether the user has opted in to reputation lookups.
func ReputationDBPresent(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// OpenReputationDB reads the whole database into memory.
func OpenReputationDB(path string) (*ReputationDB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < reputationHeaderSize || string(data[:8]) != reputationMagic {
		return nil, fmt.Errorf("not an asname reputation database (rebuild with `asname update --reputation-only`)")
	}

	trieLen := binary.LittleEndian.Uint64(data[8:16])
	setCount := binary.LittleEndian.Uint32(data[16:20])
	asnCount := binary.LittleEndian.Uint32(data[20:24])
	built := int64(binary.LittleEndian.Uint64(data[24:32]))

	rest := data[reputationHeaderSize:]
	if uint64(len(rest)) < trieLen {
		return nil, fmt.Errorf("truncated database: prefix table is short")
	}
	prefixes, err := database.NewFromDump(bytes.NewReader(rest[:trieLen]))
	if err != nil {
		return nil, fmt.Errorf("parsing prefix table: %v", err)
	}
	rest = rest[trieLen:]

	db := &ReputationDB{prefixes: prefixes, sets: make([]string, 1, setCount+1), Built: time.Unix(built, 0)}
	for range setCount {
		i := bytes.IndexByte(rest, 0)
		if i < 0 {
			return nil, fmt.Errorf("truncated database: tag sets are short")
		}
		db.sets = append(db.sets, string(rest[:i]))
		rest = rest[i+1:]
	}

	if uint64(len(rest)) < uint64(asnCount)*reputationASNEntry {
		return nil, fmt.Errorf("truncated database: ASN table is short")
	}
	db.asns = make(map[uint32]ASNReputation, asnCount)
	for i := range int(asnCount) {
		e := rest[i*reputationASNEntry : (i+1)*reputationASNEntry]
		db.asns[binary.LittleEndian.Uint32(e[0:4])] = ASNReputation{
			ASNDrop:      binary.LittleEndian.Uint32(e[4:8])&repFlagASNDrop != 0,
			ListedIPs:    binary.LittleEndian.Uint32(e[8:12]),
			DropPrefixes: binary.LittleEndian.Uint32(e[12:16]),
			MaxLists:     binary.LittleEndian.Uint32(e[16:20]),
		}
	}
	return db, nil
}

// Lookup returns the lists naming ip, such as "firehol-level2" or "ipsum:7",
// sorted; nil when none do.
func (d *ReputationDB) Lookup(ip net.IP) []string {
	value, err := d.prefixes.Lookup(ip)
	if err != nil || value.Number == 0 || int(value.Number) >= len(d.sets) {
		return nil
	}
	return strings.Split(d.sets[value.Number], ",")
}

// LookupASN returns what the lists say about asn as a whole.
func (d *ReputationDB) LookupASN(asn uint32) ASNReputation {
	if d == nil {
		return ASNReputation{}
	}
	return d.asns[asn]
}

// CountIPv4 returns how many IPv4 addresses the CIDRs cover, counting an
// address covered by several of them once.
func CountIPv4(cidrs []string) uint64 {
	var ps []netip.Prefix
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil && p.Addr().Is4() {
			ps = append(ps, p.Masked())
		}
	}
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	var total uint64
	var last netip.Prefix
	for _, p := range ps {
		if last.IsValid() && last.Contains(p.Addr()) {
			continue
		}
		total += 1 << (32 - p.Bits())
		last = p
	}
	return total
}
