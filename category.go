package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/flyingllama87/asname/pkg/database"
)

const (
	categoryEnvVar   = "ASNAME_CATEGORY"
	categoryFilename = "category.db"

	// categoryMagic identifies the file and its layout version.
	categoryMagic      = "ASNCAT\x00\x01"
	categoryHeaderSize = 24
)

// categoryDB says what kind of network an address belongs to — cloud, CDN,
// hosting, residential ISP and so on — which is a different question from who
// owns it. It answers from two directions at once:
//
// Prefixes, from the providers' own published ranges. AWS, Google, Cloudflare
// and the rest publish the exact prefixes they use, which makes this the one
// part of the classification that is authoritative rather than inferred.
//
// ASNs, from bgp.tools' operator tags and PeeringDB's self-reported network
// type. Coarser, and only as good as what operators declare, but it covers the
// long tail no provider publishes a range file for.
//
// Both are small enough to hold in memory, unlike the netblock database.
type categoryDB struct {
	prefixes database.Database // prefix -> index into sets
	asns     map[uint32]uint32 // ASN -> index into sets
	sets     []string          // comma-joined tag sets, 1-based; 0 means none
}

// categoryDBPresent reports whether the user has opted in to category lookups
// by having the database on disk.
func categoryDBPresent(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// openCategoryDB reads the whole database into memory.
func openCategoryDB(path string) (*categoryDB, error) {
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

	// Set 0 is the empty set, so that a trie miss and an unlabelled ASN both
	// land on "nothing known".
	db := &categoryDB{prefixes: prefixes, sets: make([]string, 1, setCount+1)}
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
	return db, nil
}

// Lookup returns the categories known for an address and the AS announcing it,
// as a single sorted list. Both sources contribute: an address inside AWS's
// published CloudFront range is a CDN whatever its AS is tagged as.
func (d *categoryDB) Lookup(ip net.IP, asn uint32, haveASN bool) string {
	tags := make(map[string]bool)

	// A prefix match is the provider naming its own address, so it settles the
	// question and the AS-level tags are not consulted. They describe what the
	// operator does somewhere in its network, which for a hyperscaler is a
	// little of everything: without this, every EC2 address inherits "vpn"
	// from Amazon's AS, because somebody does run a VPN on EC2.
	if value, err := d.prefixes.Lookup(ip); err == nil {
		d.collect(value.Number, tags)
	}
	if len(tags) == 0 && haveASN {
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

// collect adds the tags of set index i to tags.
func (d *categoryDB) collect(i uint32, tags map[string]bool) {
	if i == 0 || int(i) >= len(d.sets) {
		return
	}
	for tag := range strings.SplitSeq(d.sets[i], ",") {
		if tag != "" {
			tags[tag] = true
		}
	}
}
