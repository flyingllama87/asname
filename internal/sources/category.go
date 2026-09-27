package sources

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
	return db, nil
}

// Lookup returns the categories known for an address and the AS announcing it.
func (d *CategoryDB) Lookup(ip net.IP, asn uint32, haveASN bool) string {
	tags := make(map[string]bool)

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
