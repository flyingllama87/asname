package sources

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/flyingllama87/asname/pkg/database"
)

// Geofeeds (RFC 8805) are CSV files in which a network says where its own
// addresses are. Registry ranges point to them with a geofeed: attribute, or
// a "remarks: Geofeed <url>" line (RFC 9092). The netblock update keeps those
// references in GeofeedRefsFilename; the geofeed update fetches each feed and
// keeps only the entries inside the ranges that reference it, so a feed
// cannot place anyone else's addresses.

const (
	GeofeedEnvVar   = "ASNAME_GEOFEED"
	GeofeedFilename = "geofeed.db"

	// GeofeedRefsFilename lists, next to the netblock database, every
	// registry range that names a geofeed: start, end and URL per line.
	GeofeedRefsFilename = "geofeed-refs.tsv.gz"

	geofeedMagic = "ASNGEO\x00\x01"
)

// GeofeedRefsPresent reports whether the netblock database at netblockPath
// has its geofeed references beside it. A netblock database built before
// asname kept them lacks them, and the geofeed update needs them.
func GeofeedRefsPresent(netblockPath string) bool {
	info, err := os.Stat(GeofeedRefsPath(netblockPath))
	return err == nil && info.Mode().IsRegular()
}

// GeofeedRefsPath is where the netblock database at netblockPath keeps its
// geofeed references.
func GeofeedRefsPath(netblockPath string) string {
	return filepath.Join(filepath.Dir(netblockPath), GeofeedRefsFilename)
}

// GeofeedLocation is where a network's own geofeed places an address.
type GeofeedLocation struct {
	// Country is the ISO 3166-1 code, Region the ISO 3166-2 code ("NL-LI"),
	// City free text. Only Country is always set.
	Country, Region, City string
	// Feed is the URL of the geofeed that says so.
	Feed string
}

// String reads "Kerkrade, NL-LI, Netherlands", leaving out what is missing.
func (l GeofeedLocation) String() string {
	parts := make([]string, 0, 3)
	if l.City != "" {
		parts = append(parts, l.City)
	}
	if l.Region != "" {
		parts = append(parts, l.Region)
	}
	if name := CountryNames[l.Country]; name != "" {
		parts = append(parts, name)
	} else {
		parts = append(parts, l.Country)
	}
	return strings.Join(parts, ", ")
}

func (l GeofeedLocation) encode() string {
	return l.Country + "\t" + l.Region + "\t" + l.City + "\t" + l.Feed
}

func decodeGeofeedLocation(s string) GeofeedLocation {
	f := strings.SplitN(s, "\t", 4)
	for len(f) < 4 {
		f = append(f, "")
	}
	return GeofeedLocation{Country: f[0], Region: f[1], City: f[2], Feed: f[3]}
}

// GeofeedDB maps addresses to what their networks' geofeeds say.
type GeofeedDB struct {
	trie database.Database
	locs []string
}

// GeofeedDBPresent reports whether the user has opted in to geofeeds.
func GeofeedDBPresent(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// OpenGeofeedDB reads the whole database into memory.
func OpenGeofeedDB(path string) (*GeofeedDB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < 20 || string(data[:8]) != geofeedMagic {
		return nil, fmt.Errorf("not an asname geofeed database (rebuild with `asname update --geofeed-only`)")
	}
	trieLen := binary.LittleEndian.Uint64(data[8:16])
	rest := data[16:]
	if uint64(len(rest)) < trieLen+4 {
		return nil, fmt.Errorf("truncated database: prefix table is short")
	}
	db := &GeofeedDB{locs: []string{""}}
	if trieLen > 0 {
		if db.trie, err = database.NewFromDump(bytes.NewReader(rest[:trieLen])); err != nil {
			return nil, fmt.Errorf("parsing prefix table: %v", err)
		}
	}
	rest = rest[trieLen:]
	count := binary.LittleEndian.Uint32(rest[:4])
	rest = rest[4:]
	for range count {
		loc, after, ok := bytes.Cut(rest, []byte{0})
		if !ok {
			return nil, fmt.Errorf("truncated database: locations are short")
		}
		db.locs = append(db.locs, string(loc))
		rest = after
	}
	return db, nil
}

// Lookup returns where the geofeed of ip's network places it.
func (d *GeofeedDB) Lookup(ip net.IP) (GeofeedLocation, bool) {
	if d == nil || d.trie == nil {
		return GeofeedLocation{}, false
	}
	v, err := d.trie.Lookup(ip)
	if err != nil || v.Number == 0 || int(v.Number) >= len(d.locs) {
		return GeofeedLocation{}, false
	}
	return decodeGeofeedLocation(d.locs[v.Number]), true
}

// geofeedEntry is one line of a geofeed. Country is empty for an entry that
// withholds the location of its prefix.
type geofeedEntry struct {
	Prefix                netip.Prefix
	Country, Region, City string
}

// maxGeofeedCity bounds the city field; anything longer is not a place name.
const maxGeofeedCity = 80

// parseGeofeed reads an RFC 8805 feed: one "prefix,country,region,city,
// postal" line per prefix, '#' comments. Lines that do not parse are
// skipped and counted. A region that is not an ISO 3166-2 code within the
// line's country, or a city that is not plain text, is dropped from that
// line rather than trusted.
func parseGeofeed(r io.Reader) (entries []geofeedEntry, bad int, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first {
			line = strings.TrimPrefix(line, "\xef\xbb\xbf")
			first = false
		}
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		var fields []string
		if strings.ContainsRune(line, '"') {
			cr := csv.NewReader(strings.NewReader(line))
			cr.FieldsPerRecord, cr.LazyQuotes, cr.TrimLeadingSpace = -1, true, true
			if fields, err = cr.Read(); err != nil {
				bad++
				continue
			}
		} else {
			fields = strings.Split(line, ",")
		}
		e, ok := geofeedLine(fields)
		if !ok {
			bad++
			continue
		}
		entries = append(entries, e)
	}
	return entries, bad, sc.Err()
}

func geofeedLine(fields []string) (geofeedEntry, bool) {
	for len(fields) < 4 {
		fields = append(fields, "")
	}
	raw := strings.TrimSpace(fields[0])
	p, err := netip.ParsePrefix(raw)
	if err != nil {
		a, aerr := netip.ParseAddr(raw)
		if aerr != nil {
			return geofeedEntry{}, false
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	if !p.IsValid() || p.Addr().Zone() != "" {
		return geofeedEntry{}, false
	}
	e := geofeedEntry{Prefix: p.Masked()}
	cc := strings.ToUpper(strings.TrimSpace(fields[1]))
	switch {
	case cc == "":
		// An empty country withholds the location: no region or city.
		return e, true
	case len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' || cc == "ZZ":
		return geofeedEntry{}, false
	}
	e.Country = cc
	region := strings.ToUpper(strings.TrimSpace(fields[2]))
	if region != "" && !isISO3166_2(region, cc) {
		// A region of another country contradicts the line: its city
		// cannot be trusted either, only the country.
		return e, true
	}
	e.Region = region
	e.City = cleanGeofeedCity(fields[3])
	return e, true
}

// isISO3166_2 reports whether s looks like a subdivision code of country cc:
// "CC-" and one to three letters or digits.
func isISO3166_2(s, cc string) bool {
	sub, ok := strings.CutPrefix(s, cc+"-")
	if !ok || len(sub) < 1 || len(sub) > 3 {
		return false
	}
	for _, c := range sub {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func cleanGeofeedCity(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if s == "" || len(s) > maxGeofeedCity || !utf8.ValidString(s) {
		return ""
	}
	letters := 0
	for _, r := range s {
		if unicode.IsControl(r) || r == '\t' {
			return ""
		}
		if unicode.IsLetter(r) {
			letters++
		}
	}
	if letters == 0 {
		return ""
	}
	return s
}

// geofeedRef is one registry range's reference to a geofeed.
type geofeedRef struct {
	Start, End netip.Addr
	URL        string
}

// cleanGeofeedURL returns the URL a geofeed attribute or remark names, or
// "" if it is not a usable HTTPS URL; RFC 9092 requires HTTPS.
func cleanGeofeedURL(s string) string {
	s = strings.TrimSpace(s)
	if f := strings.Fields(s); len(f) > 0 {
		s = f[0]
	}
	if len(s) > 512 {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.User != nil {
		return ""
	}
	return s
}

// geofeedRemark returns the URL in a "Geofeed <url>" remark (RFC 9092), or "".
func geofeedRemark(value string) string {
	f := strings.Fields(value)
	if len(f) != 2 || !strings.EqualFold(f[0], "geofeed") {
		return ""
	}
	return f[1]
}

// writeGeofeedRefs writes refs to path as gzipped "start\tend\turl" lines,
// replacing the file atomically. With no refs it removes the file.
func writeGeofeedRefs(path string, refs []geofeedRef) error {
	if len(refs) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	w := bufio.NewWriter(zw)
	fmt.Fprintln(w, "# asname geofeed references: registry ranges and the RFC 8805 geofeed each names")
	for _, r := range refs {
		fmt.Fprintf(w, "%s\t%s\t%s\n", r.Start, r.End, r.URL)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return WriteFileAtomic(path, buf.Bytes())
}

// readGeofeedRefs reads what writeGeofeedRefs wrote.
func readGeofeedRefs(path string) ([]geofeedRef, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %v", path, err)
	}
	var refs []geofeedRef
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.SplitN(line, "\t", 3)
		if len(f) != 3 {
			continue
		}
		start, err1 := netip.ParseAddr(f[0])
		end, err2 := netip.ParseAddr(f[1])
		if err1 != nil || err2 != nil || start.Is4() != end.Is4() || end.Less(start) {
			continue
		}
		refs = append(refs, geofeedRef{Start: start, End: end, URL: f[2]})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %v", path, err)
	}
	return refs, nil
}
