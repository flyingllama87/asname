package sources

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
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

const (
	apnicWhoisBase   = "https://ftp.apnic.net/apnic/whois/"
	ripeWhoisBase    = "https://ftp.ripe.net/ripe/dbase/split/"
	afrinicWhoisDump = "https://ftp.afrinic.net/dbase/afrinic.db.gz"

	ArinKeyEnvVar = "ASNAME_ARIN_APIKEY"
	arinBulkURL   = "https://accountws.arin.net/public/rest/downloads/bulkwhois?apikey="
)

type netblockSchema struct {
	rangeKeys  []string
	netnameKey string
	orgRefKey  string
	orgKey     string
	orgNameKey string
	descrKey   string
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

func arinNetblockSource(apiKey string) netblockSource {
	url := arinBulkURL + apiKey
	return netblockSource{
		name:    "ARIN",
		orgURLs: []string{url},
		netURLs: []string{url},
		schema:  arinSchema,
	}
}

// UpdateNetblockDB downloads every available registry dump, flattens ranges
// into disjoint segments and atomically replaces cfg.NetblockPath.
func UpdateNetblockDB(ctx context.Context, cfg Config) error {
	logf(ctx, "asname: building IP->netblock database from RIR whois dumps\n")

	// Bulk Whois is the better ARIN source where a key is available: it names
	// every range rather than only those an ASN holder registered, and it
	// carries the netnames. The delegated statistics stand in when it is not.
	sources := netblockSources
	delegated := true
	if key := os.Getenv(ArinKeyEnvVar); key != "" {
		sources = append(append([]netblockSource{}, sources...), arinNetblockSource(key))
		delegated = false
	} else {
		logf(ctx, "asname: note: no %s set, so ARIN ranges are named from the delegated\n"+
			"asname:       statistics file instead. Ranges held by an organisation that holds no\n"+
			"asname:       ASN stay unnamed. For the complete ARIN data see\n"+
			"asname:       https://www.arin.net/reference/research/bulkwhois/\n", ArinKeyEnvVar)
	}

	b := newNetblockBuilder()
	cache := cfg.CacheDir()
	imported := 0
	for _, src := range sources {
		n, err := b.importSource(ctx, src, cache)
		if err != nil {
			logf(ctx, "asname: warning: %s: %v\n", src.name, err)
			continue
		}
		logf(ctx, "asname: %s: %d ranges\n", src.name, n)
		imported += n
	}
	if delegated {
		imported += importARINDelegatedInto(ctx, b, cfg, cache)
	}
	if imported == 0 {
		return fmt.Errorf("no netblock ranges imported")
	}

	n, err := b.write(cfg.NetblockPath)
	if err != nil {
		return err
	}
	logf(ctx, "asname: wrote %s (%d ranges, %d bytes)\n", cfg.NetblockPath, imported, n)
	return nil
}

type netblockBuilder struct {
	v4         []interval[uint32]
	v6         []interval[[16]byte]
	blob       []byte
	orgOffsets map[string]uint32
}

func newNetblockBuilder() *netblockBuilder {
	return &netblockBuilder{
		blob:       []byte{0},
		orgOffsets: make(map[string]uint32),
	}
}

func (b *netblockBuilder) addString(s string) uint32 {
	if s == "" {
		return 0
	}
	off := uint32(len(b.blob))
	b.blob = append(b.blob, s...)
	b.blob = append(b.blob, 0)
	return off
}

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

func (b *netblockBuilder) importSource(ctx context.Context, src netblockSource, cache string) (int, error) {
	local := make(map[string]string)

	fetch := func(url string) (string, error) {
		if path, ok := local[url]; ok {
			return path, nil
		}
		path, err := fetchCached(ctx, cache, url, "")
		if err != nil {
			return "", err
		}
		local[url] = path
		return path, nil
	}

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
			start, end, ok := ParseNetRange(raw)
			if !ok {
				return nil
			}

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
			if IsPlaceholderRange(netname, org) {
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

func IsPlaceholderRange(netname, descr string) bool {
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

func isUnspecifiedV6Range(start, end net.IP) bool {
	for i := range start {
		if start[i] != 0 || end[i] != 0xff {
			return false
		}
	}
	return true
}

// NetblockRecord is one registry range for WriteNetblockDB.
type NetblockRecord struct {
	Start, End   net.IP
	Netname, Org string
}

// WriteNetblockDB writes records to a netblock database at path. It exists for
// test fixtures; UpdateNetblockDB builds the real database from registry dumps.
func WriteNetblockDB(path string, records []NetblockRecord) error {
	b := newNetblockBuilder()
	for _, r := range records {
		b.add(r.Start, r.End, r.Netname, r.Org)
	}
	_, err := b.write(path)
	return err
}

func (b *netblockBuilder) write(path string) (int64, error) {
	if len(b.blob) > math.MaxUint32 {
		return 0, fmt.Errorf("string table too large: %d bytes", len(b.blob))
	}

	v4 := Flatten(b.v4, CompareUint32, IncUint32)
	v6 := Flatten(b.v6, CompareBytes16, IncBytes16)

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
		binary.LittleEndian.PutUint32(rec[0:4], seg.Start)
		binary.LittleEndian.PutUint32(rec[4:8], seg.Netname)
		binary.LittleEndian.PutUint32(rec[8:12], seg.Org)
		if _, err := w.Write(rec[:netblockSeg4Size]); err != nil {
			return 0, err
		}
	}
	for _, seg := range v6 {
		copy(rec[0:16], seg.Start[:])
		binary.LittleEndian.PutUint32(rec[16:20], seg.Netname)
		binary.LittleEndian.PutUint32(rec[20:24], seg.Org)
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

type interval[K any] struct {
	start, end   K
	netname, org uint32
}

type Segment[K any] struct {
	Start        K
	Netname, Org uint32
}

func Flatten[K any](ivs []interval[K], cmp func(a, b K) int, inc func(K) (K, bool)) []Segment[K] {
	sort.Slice(ivs, func(i, j int) bool {
		if c := cmp(ivs[i].start, ivs[j].start); c != 0 {
			return c < 0
		}
		return cmp(ivs[i].end, ivs[j].end) > 0
	})

	out := make([]Segment[K], 0, len(ivs)*2)

	emit := func(at K, netname, org uint32) {
		if n := len(out); n > 0 && cmp(out[n-1].Start, at) == 0 {
			out[n-1].Netname, out[n-1].Org = netname, org
			if n > 1 && out[n-2].Netname == netname && out[n-2].Org == org {
				out = out[:n-1]
			}
			return
		}
		if n := len(out); n == 0 {
			if netname == 0 && org == 0 {
				return
			}
		} else if out[n-1].Netname == netname && out[n-1].Org == org {
			return
		}
		out = append(out, Segment[K]{Start: at, Netname: netname, Org: org})
	}

	var stack []interval[K]

	closeEnded := func(ended func(interval[K]) bool) {
		for len(stack) > 0 && ended(stack[len(stack)-1]) {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			next, ok := inc(top.end)
			if !ok {
				stack = stack[:0]
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

func CompareUint32(a, b uint32) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func IncUint32(v uint32) (uint32, bool) {
	if v == math.MaxUint32 {
		return 0, false
	}
	return v + 1, true
}

func CompareBytes16(a, b [16]byte) int { return bytes.Compare(a[:], b[:]) }

func IncBytes16(v [16]byte) ([16]byte, bool) {
	for i := 15; i >= 0; i-- {
		v[i]++
		if v[i] != 0 {
			return v, true
		}
	}
	return v, false
}

type attr struct{ name, value string }

func attrValue(attrs []attr, name string) string {
	for _, a := range attrs {
		if a.name == name {
			return a.value
		}
	}
	return ""
}

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
	keeping := false
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
				if cont := CleanValue(line); cont != "" {
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
		if attrValue(attrs, name) != "" {
			keeping = false
			continue
		}
		attrs = append(attrs, attr{name: name, value: CleanValue(value)})
	}
	if len(attrs) > 0 {
		if err := emit(attrs); err != nil {
			return err
		}
	}
	return sc.Err()
}

func CleanValue(s string) string {
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

func ParseNetRange(s string) (net.IP, net.IP, bool) {
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

func redactURL(url string) string {
	if i := strings.Index(url, "apikey="); i >= 0 {
		return url[:i+len("apikey=")] + "..."
	}
	return url
}

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
