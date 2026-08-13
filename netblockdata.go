package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// The RIRs publish their whois databases in bulk, and it is the inetnum (and
// inet6num) objects in them that carry what the delegation statistics do not:
// the name of the organisation a range was actually assigned to. That is the
// customer holding a suballocation, not the network announcing it, which is
// why a lookup can say "Secure Internet Storage Solutions" where the ASN only
// says "Equinix".
//
// Three of the five registries publish this openly. LACNIC is deliberately
// absent: its public dump (ftp.lacnic.net/lacnic/dbase/lacnic.db.gz) is
// anonymised down to status, city and country, with no owner attribute at all,
// so it would add ranges with nothing to name them. ARIN gates its dump behind
// a signed acceptable-use agreement; see arinNetblockSource.
const (
	apnicWhoisBase   = "https://ftp.apnic.net/apnic/whois/"
	ripeWhoisBase    = "https://ftp.ripe.net/ripe/dbase/split/"
	afrinicWhoisDump = "https://ftp.afrinic.net/dbase/afrinic.db.gz"

	// arinKeyEnvVar holds an ARIN Bulk Whois API key. ARIN does not publish its
	// database openly: access requires signing the Bulk Whois Terms of Use and
	// having the request approved, after which an API key is issued. Their
	// terms restrict redistribution, so asname can only ever build this part of
	// the database from a key the user obtained themselves.
	arinKeyEnvVar = "ASNAME_ARIN_APIKEY"
	arinBulkURL   = "https://accountws.arin.net/public/rest/downloads/bulkwhois?apikey="
)

// netblockSchema names the attributes to read, since ARIN's dump uses its own
// vocabulary for the same things the RPSL registries express as inetnum.
type netblockSchema struct {
	rangeKeys  []string // attributes whose value is the address range
	netnameKey string
	orgRefKey  string // the range's reference to an organisation object
	orgKey     string // the organisation object's primary key
	orgNameKey string
	descrKey   string // free-text description, "" when the schema has none
}

var (
	rpslSchema = netblockSchema{
		rangeKeys:  []string{"inetnum", "inet6num"},
		netnameKey: "netname",
		orgRefKey:  "org",
		orgKey:     "organisation",
		orgNameKey: "org-name",
		descrKey:   "descr",
	}
	arinSchema = netblockSchema{
		rangeKeys:  []string{"netrange", "v6netrange"},
		netnameKey: "netname",
		orgRefKey:  "orgid",
		orgKey:     "orgid",
		orgNameKey: "orgname",
	}
)

// netblockSource is one registry's dump. orgURLs are scanned first to resolve
// organisation handles to names; netURLs then supply the ranges. A registry
// that ships everything in one file simply names it in both.
type netblockSource struct {
	name    string
	orgURLs []string
	netURLs []string
	schema  netblockSchema
}

var netblockSources = []netblockSource{
	{
		name:    "APNIC",
		orgURLs: []string{apnicWhoisBase + "apnic.db.organisation.gz"},
		netURLs: []string{apnicWhoisBase + "apnic.db.inetnum.gz", apnicWhoisBase + "apnic.db.inet6num.gz"},
		schema:  rpslSchema,
	},
	{
		name:    "RIPE",
		orgURLs: []string{ripeWhoisBase + "ripe.db.organisation.gz"},
		netURLs: []string{ripeWhoisBase + "ripe.db.inetnum.gz", ripeWhoisBase + "ripe.db.inet6num.gz"},
		schema:  rpslSchema,
	},
	{
		name:    "AFRINIC",
		orgURLs: []string{afrinicWhoisDump},
		netURLs: []string{afrinicWhoisDump},
		schema:  rpslSchema,
	},
}

// arinNetblockSource builds the ARIN source for an API key. Their bulk file
// holds both the Org and the Net records, so it is scanned twice like AFRINIC's.
func arinNetblockSource(apiKey string) netblockSource {
	url := arinBulkURL + apiKey
	return netblockSource{
		name:    "ARIN",
		orgURLs: []string{url},
		netURLs: []string{url},
		schema:  arinSchema,
	}
}

// updateNetblockDB downloads every available registry dump, flattens their
// nested ranges into disjoint segments and atomically replaces
// cfg.netblockPath.
func updateNetblockDB(cfg config) error {
	fmt.Fprintln(os.Stderr, "asname: building IP->netblock database from RIR whois dumps")

	sources := netblockSources
	if key := os.Getenv(arinKeyEnvVar); key != "" {
		sources = append(append([]netblockSource{}, sources...), arinNetblockSource(key))
	} else {
		fmt.Fprintf(os.Stderr, "asname: note: no %s set, so ARIN ranges (most of North America) will be missing;\n"+
			"asname:       see https://www.arin.net/reference/research/bulkwhois/\n", arinKeyEnvVar)
	}

	b := newNetblockBuilder()
	workDir := filepath.Dir(cfg.netblockPath)
	imported := 0
	for _, src := range sources {
		n, err := b.importSource(src, workDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "asname: warning: %s: %v\n", src.name, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "asname: %s: %d ranges\n", src.name, n)
		imported += n
	}
	if imported == 0 {
		return fmt.Errorf("no netblock ranges imported")
	}

	n, err := b.write(cfg.netblockPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "asname: wrote %s (%d ranges, %d bytes)\n", cfg.netblockPath, imported, n)
	return nil
}

// netblockBuilder accumulates ranges from every registry before flattening
// them in one pass, since ranges from different registries never nest but the
// sweep is simpler if it sees them all at once.
//
// Strings are appended to a blob as they are parsed rather than held as Go
// strings on the ranges: there are several million of them, and carrying two
// string headers per range costs more than the text itself.
type netblockBuilder struct {
	v4   []interval[uint32]
	v6   []interval[[16]byte]
	blob []byte
	// orgOffsets dedupes organisation names, which repeat across every range a
	// single organisation holds. Netnames are near enough unique per range that
	// interning them would cost more in map overhead than it saves.
	orgOffsets map[string]uint32
}

func newNetblockBuilder() *netblockBuilder {
	return &netblockBuilder{
		blob:       []byte{0}, // offset 0 is the empty string
		orgOffsets: make(map[string]uint32),
	}
}

// addString appends s to the blob and returns its offset.
func (b *netblockBuilder) addString(s string) uint32 {
	if s == "" {
		return 0
	}
	off := uint32(len(b.blob))
	b.blob = append(b.blob, s...)
	b.blob = append(b.blob, 0)
	return off
}

// internString is addString for values that repeat often enough to be worth a
// map lookup.
func (b *netblockBuilder) internString(s string) uint32 {
	if s == "" {
		return 0
	}
	if off, ok := b.orgOffsets[s]; ok {
		return off
	}
	off := b.addString(s)
	b.orgOffsets[s] = off
	return off
}

// importSource fetches one registry's files and adds its ranges. Each URL is
// downloaded once into workDir and scanned from there, so a dump that holds
// both organisations and ranges is not fetched twice.
func (b *netblockBuilder) importSource(src netblockSource, workDir string) (int, error) {
	local := make(map[string]string)
	defer func() {
		for _, path := range local {
			os.Remove(path)
		}
	}()

	fetch := func(url string) (string, error) {
		if path, ok := local[url]; ok {
			return path, nil
		}
		path, err := downloadTemp(url, workDir)
		if err != nil {
			return "", err
		}
		local[url] = path
		return path, nil
	}

	// Pass one: organisation handle -> name.
	orgs := make(map[string]string)
	for _, url := range src.orgURLs {
		path, err := fetch(url)
		if err != nil {
			return 0, err
		}
		if err := scanDump(path, func(attrs []attr) error {
			handle := attrValue(attrs, src.schema.orgKey)
			name := attrValue(attrs, src.schema.orgNameKey)
			if handle != "" && name != "" {
				orgs[handle] = name
			}
			return nil
		}, src.schema.orgKey, src.schema.orgNameKey); err != nil {
			return 0, err
		}
	}

	// Pass two: the ranges themselves.
	want := append([]string{src.schema.netnameKey, src.schema.orgRefKey}, src.schema.rangeKeys...)
	if src.schema.descrKey != "" {
		want = append(want, src.schema.descrKey)
	}

	count := 0
	for _, url := range src.netURLs {
		path, err := fetch(url)
		if err != nil {
			return count, err
		}
		if err := scanDump(path, func(attrs []attr) error {
			var raw string
			for _, key := range src.schema.rangeKeys {
				if raw = attrValue(attrs, key); raw != "" {
					break
				}
			}
			if raw == "" {
				return nil
			}
			start, end, ok := parseNetRange(raw)
			if !ok {
				return nil
			}

			// The description is the assignment holder and the organisation is
			// often the LIR above it, so the more specific one is preferred.
			org := ""
			if src.schema.descrKey != "" {
				org = attrValue(attrs, src.schema.descrKey)
			}
			if org == "" {
				org = orgs[attrValue(attrs, src.schema.orgRefKey)]
			}
			netname := attrValue(attrs, src.schema.netnameKey)
			if netname == "" && org == "" {
				return nil
			}
			if isPlaceholderRange(netname, org) {
				return nil
			}

			b.add(start, end, netname, org)
			count++
			return nil
		}, want...); err != nil {
			return count, err
		}
	}
	return count, nil
}

// add records one range, discarding the whole-address-space placeholders the
// registries keep for IANA, which would otherwise name every unassigned
// address after them.
func (b *netblockBuilder) add(start, end net.IP, netname, org string) {
	if s4, e4 := start.To4(), end.To4(); s4 != nil && e4 != nil {
		lo, hi := binary.BigEndian.Uint32(s4), binary.BigEndian.Uint32(e4)
		if lo > hi || (lo == 0 && hi == math.MaxUint32) {
			return
		}
		b.v4 = append(b.v4, interval[uint32]{
			start: lo, end: hi,
			netname: b.addString(netname), org: b.internString(org),
		})
		return
	}

	s16, e16 := start.To16(), end.To16()
	if s16 == nil || e16 == nil || bytes.Compare(s16, e16) > 0 {
		return
	}
	if isUnspecifiedV6Range(s16, e16) {
		return
	}
	var lo, hi [16]byte
	copy(lo[:], s16)
	copy(hi[:], e16)
	b.v6 = append(b.v6, interval[[16]byte]{
		start: lo, end: hi,
		netname: b.addString(netname), org: b.internString(org),
	})
}

// Each registry publishes placeholder objects covering the ranges it does not
// hold, so that a whois query for someone else's address returns an answer
// pointing elsewhere rather than nothing. Left in, they would name every ARIN
// address after APNIC's "IANA-NETBLOCK-8" or RIPE's
// "NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK" — worse than saying nothing, since the
// whole point is to name the actual holder.
//
// The registries say so themselves in the description, which is the signal
// used here; the netnames are matched too, for placeholders whose description
// leads with something else.
var (
	placeholderDescrs = []string{
		"not allocated to",
		"not allocated by",
		"not managed by",
		"not set up in this registry",
	}
	placeholderNetnames = map[string]bool{
		"non-ripe-ncc-managed-address-block": true,
		"iana-blk":                           true,
		"iana-rsvd":                          true,
		"root":                               true,
	}
	placeholderNetnameParts = []string{"iana-netblock-", "-cidr-block"}
)

// isPlaceholderRange reports whether a range is one of those placeholders.
func isPlaceholderRange(netname, descr string) bool {
	name := strings.ToLower(netname)
	if placeholderNetnames[name] {
		return true
	}
	for _, part := range placeholderNetnameParts {
		if strings.Contains(name, part) {
			return true
		}
	}
	text := strings.ToLower(descr)
	for _, phrase := range placeholderDescrs {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}

// isUnspecifiedV6Range reports whether a range covers the whole IPv6 address
// space, the ::/0 placeholder the registries keep for IANA.
func isUnspecifiedV6Range(start, end net.IP) bool {
	for i := range start {
		if start[i] != 0 || end[i] != 0xff {
			return false
		}
	}
	return true
}

// write flattens the collected ranges and serialises the database.
func (b *netblockBuilder) write(path string) (int64, error) {
	if len(b.blob) > math.MaxUint32 {
		return 0, fmt.Errorf("string table too large: %d bytes", len(b.blob))
	}

	v4 := flatten(b.v4, compareUint32, incUint32)
	v6 := flatten(b.v6, compareBytes16, incBytes16)

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return 0, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	w := bufio.NewWriterSize(tmp, 1<<20)

	var hdr [netblockHeaderSize]byte
	copy(hdr[:8], netblockMagic)
	binary.LittleEndian.PutUint64(hdr[8:16], uint64(time.Now().Unix()))
	binary.LittleEndian.PutUint32(hdr[16:20], uint32(len(v4)))
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(len(v6)))
	strOff := netblockHeaderSize + int64(len(v4))*netblockSeg4Size + int64(len(v6))*netblockSeg6Size
	binary.LittleEndian.PutUint64(hdr[24:32], uint64(strOff))
	binary.LittleEndian.PutUint64(hdr[32:40], uint64(len(b.blob)))
	if _, err := w.Write(hdr[:]); err != nil {
		return 0, err
	}

	var rec [netblockSeg6Size]byte
	for _, seg := range v4 {
		binary.LittleEndian.PutUint32(rec[0:4], seg.start)
		binary.LittleEndian.PutUint32(rec[4:8], seg.netname)
		binary.LittleEndian.PutUint32(rec[8:12], seg.org)
		if _, err := w.Write(rec[:netblockSeg4Size]); err != nil {
			return 0, err
		}
	}
	for _, seg := range v6 {
		copy(rec[0:16], seg.start[:])
		binary.LittleEndian.PutUint32(rec[16:20], seg.netname)
		binary.LittleEndian.PutUint32(rec[20:24], seg.org)
		if _, err := w.Write(rec[:netblockSeg6Size]); err != nil {
			return 0, err
		}
	}
	if _, err := w.Write(b.blob); err != nil {
		return 0, err
	}
	if err := w.Flush(); err != nil {
		return 0, err
	}

	size, err := tmp.Seek(0, io.SeekCurrent)
	if err != nil {
		tmp.Close()
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}
	return size, os.Rename(tmpName, path)
}

// interval is one registry range before flattening.
type interval[K any] struct {
	start, end   K
	netname, org uint32
}

// segment is one disjoint slice of the address space in the built database. It
// runs until the next segment's start, and a segment naming nothing is a gap
// between assignments.
type segment[K any] struct {
	start        K
	netname, org uint32
}

// flatten turns possibly-nested registry ranges into the disjoint segments the
// database stores, each naming the most specific range that covers it — a /29
// assignment inside a /22 allocation wins over the /22.
//
// Registry ranges nest properly: an assignment is either inside its allocation
// or disjoint from it. A range that only partially overlaps the one enclosing
// it is malformed, and is clipped to fit rather than being allowed to unwind
// the sweep out of order.
func flatten[K any](ivs []interval[K], cmp func(a, b K) int, inc func(K) (K, bool)) []segment[K] {
	sort.Slice(ivs, func(i, j int) bool {
		if c := cmp(ivs[i].start, ivs[j].start); c != 0 {
			return c < 0
		}
		// Widest first, so that an enclosing range is always opened before the
		// ranges nested inside it.
		return cmp(ivs[i].end, ivs[j].end) > 0
	})

	out := make([]segment[K], 0, len(ivs)*2)

	// emit records a boundary. Boundaries arrive in address order, so a second
	// one at the same address comes from a more specific range and replaces the
	// first, and one that says what the previous segment already said is
	// dropped rather than stored twice.
	emit := func(at K, netname, org uint32) {
		if n := len(out); n > 0 && cmp(out[n-1].start, at) == 0 {
			out[n-1].netname, out[n-1].org = netname, org
			if n > 1 && out[n-2].netname == netname && out[n-2].org == org {
				out = out[:n-1]
			}
			return
		}
		if n := len(out); n == 0 {
			if netname == 0 && org == 0 {
				return // nothing to say before the first range
			}
		} else if out[n-1].netname == netname && out[n-1].org == org {
			return
		}
		out = append(out, segment[K]{start: at, netname: netname, org: org})
	}

	// stack holds the ranges covering the current address, innermost last.
	var stack []interval[K]

	// closeEnded pops every range that has ended, reopening whichever range
	// encloses it — or a gap, once nothing does.
	closeEnded := func(ended func(interval[K]) bool) {
		for len(stack) > 0 && ended(stack[len(stack)-1]) {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			next, ok := inc(top.end)
			if !ok {
				stack = stack[:0] // the range ran to the end of the address space
				return
			}
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				emit(next, parent.netname, parent.org)
			} else {
				emit(next, 0, 0)
			}
		}
	}

	for _, iv := range ivs {
		closeEnded(func(open interval[K]) bool { return cmp(open.end, iv.start) < 0 })
		if len(stack) > 0 {
			if top := stack[len(stack)-1]; cmp(iv.end, top.end) > 0 {
				iv.end = top.end
			}
		}
		emit(iv.start, iv.netname, iv.org)
		stack = append(stack, iv)
	}
	closeEnded(func(interval[K]) bool { return true })

	return out
}

func compareUint32(a, b uint32) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func incUint32(v uint32) (uint32, bool) {
	if v == math.MaxUint32 {
		return 0, false
	}
	return v + 1, true
}

func compareBytes16(a, b [16]byte) int { return bytes.Compare(a[:], b[:]) }

func incBytes16(v [16]byte) ([16]byte, bool) {
	for i := 15; i >= 0; i-- {
		v[i]++
		if v[i] != 0 {
			return v, true
		}
	}
	return v, false
}

// attr is one whois attribute we cared enough to keep.
type attr struct{ name, value string }

func attrValue(attrs []attr, name string) string {
	for _, a := range attrs {
		if a.name == name {
			return a.value
		}
	}
	return ""
}

// scanDump streams a whois dump and calls emit once per object with the
// attributes named in want. The slice passed to emit is reused between
// objects, so it must not be retained.
//
// Objects are separated by blank lines and attributes are "name: value", with
// continuations indented or introduced by '+'. ARIN's flat text dump follows
// the same shape with different attribute names, so both parse here.
func scanDump(path string, emit func([]attr) error, want ...string) error {
	r, err := openDump(path)
	if err != nil {
		return err
	}
	defer r.Close()

	wanted := make(map[string]bool, len(want))
	for _, name := range want {
		if name != "" {
			wanted[strings.ToLower(name)] = true
		}
	}

	sc := bufio.NewScanner(bufio.NewReaderSize(r, 1<<20))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	attrs := make([]attr, 0, 8)
	keeping := false // whether the attribute being read is one we kept
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			if len(attrs) > 0 {
				if err := emit(attrs); err != nil {
					return err
				}
				attrs = attrs[:0]
			}
			keeping = false
			continue
		}
		switch line[0] {
		case '#', '%':
			continue
		case ' ', '\t', '+':
			if keeping && len(attrs) > 0 {
				last := &attrs[len(attrs)-1]
				if cont := cleanValue(line); cont != "" {
					last.value = strings.TrimSpace(last.value + " " + cont)
				}
			}
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			keeping = false
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if keeping = wanted[name]; !keeping {
			continue
		}
		// Only the first occurrence is kept: a range with several descr lines
		// leads with the organisation and follows with its address.
		if attrValue(attrs, name) != "" {
			keeping = false
			continue
		}
		attrs = append(attrs, attr{name: name, value: cleanValue(value)})
	}
	if len(attrs) > 0 {
		if err := emit(attrs); err != nil {
			return err
		}
	}
	return sc.Err()
}

// cleanValue trims an attribute value, drops any RPSL trailing comment and
// repairs the Latin-1 text some registries still publish, so that a name does
// not reach the terminal as invalid UTF-8.
func cleanValue(s string) string {
	if i := strings.Index(s, " #"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if s == "" || utf8.ValidString(s) {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		sb.WriteRune(rune(s[i]))
	}
	return sb.String()
}

// parseNetRange parses the two forms a range is written in: "start - end", and
// CIDR notation.
func parseNetRange(s string) (net.IP, net.IP, bool) {
	if lo, hi, ok := strings.Cut(s, "-"); ok {
		start, end := net.ParseIP(strings.TrimSpace(lo)), net.ParseIP(strings.TrimSpace(hi))
		if start == nil || end == nil {
			return nil, nil, false
		}
		return start, end, true
	}

	_, nw, err := net.ParseCIDR(strings.TrimSpace(s))
	if err != nil {
		return nil, nil, false
	}
	start := nw.IP.Mask(nw.Mask)
	end := make(net.IP, len(start))
	for i := range start {
		end[i] = start[i] | ^nw.Mask[i]
	}
	return start, end, true
}

// downloadTemp streams url into a temporary file in dir and returns its path.
// The dumps are scanned more than once and are far too large to buffer, so
// they land on disk for the duration of the build.
func downloadTemp(url, dir string) (string, error) {
	fmt.Fprintf(os.Stderr, "asname: downloading %s\n", redactURL(url))
	resp, err := httpGet(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	f, err := os.CreateTemp(dir, ".netblock-dump.*.tmp")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// redactURL hides the ARIN API key, which is carried in the query string and
// would otherwise be printed on every build.
func redactURL(url string) string {
	if i := strings.Index(url, "apikey="); i >= 0 {
		return url[:i+len("apikey=")] + "..."
	}
	return url
}

// openDump opens a downloaded dump, transparently handling the three forms the
// registries hand them out in: gzip, a zip archive (ARIN) and plain text.
func openDump(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var magic [4]byte
	n, _ := io.ReadFull(f, magic[:])

	switch {
	case n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			f.Close()
			return nil, err
		}
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &dumpReader{Reader: gz, closers: []io.Closer{gz, f}}, nil

	case n == 4 && string(magic[:]) == "PK\x03\x04":
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, err
		}
		zr, err := zip.NewReader(f, info.Size())
		if err != nil {
			f.Close()
			return nil, err
		}
		for _, entry := range zr.File {
			if entry.FileInfo().IsDir() {
				continue
			}
			rc, err := entry.Open()
			if err != nil {
				f.Close()
				return nil, err
			}
			return &dumpReader{Reader: rc, closers: []io.Closer{rc, f}}, nil
		}
		f.Close()
		return nil, fmt.Errorf("empty zip archive")

	default:
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			f.Close()
			return nil, err
		}
		return f, nil
	}
}

// dumpReader ties a decompressor's lifetime to the file underneath it.
type dumpReader struct {
	io.Reader
	closers []io.Closer
}

func (d *dumpReader) Close() error {
	var err error
	for _, c := range d.closers {
		if cerr := c.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}
