package sources

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"math/bits"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	NetblockEnvVar   = "ASNAME_NETBLOCK"
	NetblockFilename = "netblock.db"

	netblockMagic      = "ASNBLK\x00\x02"
	netblockHeaderSize = 40
	netblockSeg4Size   = 16
	netblockSeg6Size   = 28

	// Version 1 records lack the metadata reference; they are still read.
	netblockMagicV1    = "ASNBLK\x00\x01"
	netblockSeg4SizeV1 = 12
	netblockSeg6SizeV1 = 24
)

// NetblockDB maps an address to the registry netblock it was assigned in.
type NetblockDB struct {
	f       *os.File
	v4Count int
	v6Count int
	v6Off   int64
	strOff  int64
	strLen  int64
	// rec4 and rec6 are the record sizes; meta is false for a version 1
	// database, whose records carry no metadata.
	rec4, rec6 int64
	meta       bool
}

// NetblockInfo is what the database knows about one address.
type NetblockInfo struct {
	Netname string
	Org     string
	NetblockMeta
}

func (i NetblockInfo) Empty() bool { return i.Netname == "" && i.Org == "" }

func (i NetblockInfo) String() string {
	switch {
	case i.Netname != "" && i.Org != "" && !strings.EqualFold(i.Netname, i.Org):
		return i.Netname + " (" + i.Org + ")"
	case i.Netname != "":
		return i.Netname
	default:
		return i.Org
	}
}

// NetblockDBPresent reports whether the user has opted in to netblock lookups.
func NetblockDBPresent(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// OpenNetblockDB opens the database and validates its header.
func OpenNetblockDB(path string) (*NetblockDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	var hdr [netblockHeaderSize]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil {
		f.Close()
		return nil, fmt.Errorf("reading header: %v", err)
	}
	rec4, rec6, meta := int64(netblockSeg4Size), int64(netblockSeg6Size), true
	switch string(hdr[:8]) {
	case netblockMagic:
	case netblockMagicV1:
		rec4, rec6, meta = netblockSeg4SizeV1, netblockSeg6SizeV1, false
	default:
		f.Close()
		return nil, fmt.Errorf("not an asname netblock database (rebuild with `asname update --netblock-only`)")
	}

	db := &NetblockDB{
		f:       f,
		v4Count: int(binary.LittleEndian.Uint32(hdr[16:20])),
		v6Count: int(binary.LittleEndian.Uint32(hdr[20:24])),
		strOff:  int64(binary.LittleEndian.Uint64(hdr[24:32])),
		strLen:  int64(binary.LittleEndian.Uint64(hdr[32:40])),
		rec4:    rec4,
		rec6:    rec6,
		meta:    meta,
	}
	db.v6Off = netblockHeaderSize + int64(db.v4Count)*rec4

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if want := db.strOff + db.strLen; want != info.Size() {
		f.Close()
		return nil, fmt.Errorf("truncated database: %d bytes, expected %d", info.Size(), want)
	}
	return db, nil
}

func (d *NetblockDB) Close() error {
	if d == nil || d.f == nil {
		return nil
	}
	return d.f.Close()
}

// Lookup returns the most specific netblock covering ip.
func (d *NetblockDB) Lookup(ip net.IP) (NetblockInfo, error) {
	if ip4 := ip.To4(); ip4 != nil {
		return d.lookup4(binary.BigEndian.Uint32(ip4))
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return NetblockInfo{}, fmt.Errorf("invalid IP address")
	}
	var key [16]byte
	copy(key[:], ip16)
	return d.lookup6(key)
}

func (d *NetblockDB) lookup4(v uint32) (NetblockInfo, error) {
	lo, hi := 0, d.v4Count
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		start, err := d.start4(mid)
		if err != nil {
			return NetblockInfo{}, err
		}
		if start <= v {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		return NetblockInfo{}, nil
	}
	return d.info(netblockHeaderSize + int64(lo-1)*d.rec4 + 4)
}

func (d *NetblockDB) lookup6(v [16]byte) (NetblockInfo, error) {
	lo, hi := 0, d.v6Count
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		start, err := d.start6(mid)
		if err != nil {
			return NetblockInfo{}, err
		}
		if bytes.Compare(start[:], v[:]) <= 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		return NetblockInfo{}, nil
	}
	return d.info(d.v6Off + int64(lo-1)*d.rec6 + 16)
}

func (d *NetblockDB) start4(i int) (uint32, error) {
	var buf [4]byte
	if _, err := d.f.ReadAt(buf[:], netblockHeaderSize+int64(i)*d.rec4); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(buf[:]), nil
}

func (d *NetblockDB) start6(i int) ([16]byte, error) {
	var buf [16]byte
	if _, err := d.f.ReadAt(buf[:], d.v6Off+int64(i)*d.rec6); err != nil {
		return buf, err
	}
	return buf, nil
}

func (d *NetblockDB) info(off int64) (NetblockInfo, error) {
	var buf [12]byte
	n := 8
	if d.meta {
		n = 12
	}
	if _, err := d.f.ReadAt(buf[:n], off); err != nil {
		return NetblockInfo{}, err
	}
	var meta NetblockMeta
	if d.meta {
		raw, err := d.str(binary.LittleEndian.Uint32(buf[8:12]))
		if err != nil {
			return NetblockInfo{}, err
		}
		meta = decodeNetblockMeta(raw)
	}
	netname, err := d.str(binary.LittleEndian.Uint32(buf[0:4]))
	if err != nil {
		return NetblockInfo{}, err
	}
	org, err := d.str(binary.LittleEndian.Uint32(buf[4:8]))
	if err != nil {
		return NetblockInfo{}, err
	}
	if IsVerificationToken(org) {
		// A database built before descrValue skipped them; the netname says more.
		org = ""
	}
	return NetblockInfo{Netname: netname, Org: org, NetblockMeta: meta}, nil
}

func (d *NetblockDB) str(off uint32) (string, error) {
	if off == 0 || int64(off) >= d.strLen {
		return "", nil
	}
	var out []byte
	buf := make([]byte, 128)
	pos := int64(off)
	for pos < d.strLen {
		n := int64(len(buf))
		if pos+n > d.strLen {
			n = d.strLen - pos
		}
		read, err := d.f.ReadAt(buf[:n], d.strOff+pos)
		if i := bytes.IndexByte(buf[:read], 0); i >= 0 {
			return string(append(out, buf[:i]...)), nil
		}
		out = append(out, buf[:read]...)
		pos += int64(read)
		if err != nil {
			return string(out), nil
		}
	}
	return string(out), nil
}

// NetblockSearchResult represents one matched IP range.
type NetblockSearchResult struct {
	RangeStart net.IP
	RangeEnd   net.IP
	CIDRs      []string
	Netname    string
	Org        string
	IsV6       bool
	// Match is how the netname or org matched, as NameMatcher ranks it.
	Match int
}

// NetblockSearchOptions controls search filters and limits.
type NetblockSearchOptions struct {
	Limit  int
	V4Only bool
	V6Only bool
	// Fuzzy also finds names that match ignoring spaces and punctuation, or
	// word by word; see NameMatcher. Results come best match first.
	Fuzzy bool
	// Country, a two-letter code, is for the engine, which turns it into
	// Keep: SearchOrg itself has no country data.
	Country string
	// Keep, when set, is asked about each matching range by its first
	// address; ranges it rejects are dropped before the limit is applied.
	Keep func(start net.IP) bool
}

// SearchOrg searches the netblock database for ranges matching query in either org name or netname.
func (d *NetblockDB) SearchOrg(query string, opts NetblockSearchOptions) ([]NetblockSearchResult, error) {
	if d == nil || d.f == nil {
		return nil, fmt.Errorf("netblock database is not open")
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, nil
	}

	matchedOffsets, err := d.searchStrings(NewNameMatcher(query, opts.Fuzzy))
	if err != nil {
		return nil, fmt.Errorf("searching netblock strings: %v", err)
	}
	if len(matchedOffsets) == 0 {
		return nil, nil
	}

	// full reports whether the search can stop. A plain search stops at the
	// limit; a fuzzy one ranks its results, so it stops only once the limit
	// is filled with exact matches, which nothing else outranks.
	var results []NetblockSearchResult
	exactFound := 0
	full := func(r NetblockSearchResult) bool {
		if r.Match == MatchExact {
			exactFound++
		}
		if opts.Limit <= 0 {
			return false
		}
		if opts.Fuzzy {
			return exactFound >= opts.Limit
		}
		return len(results) >= opts.Limit
	}

	// 1. Search IPv4 segments
	if !opts.V6Only && d.v4Count > 0 {
		recSize := int(d.rec4)
		recBuf := make([]byte, 1024*recSize*64) // 64K records per chunk
		totalBytes := int64(d.v4Count) * int64(recSize)
		var filePos int64 = 0

		for filePos < totalBytes {
			toRead := int64(len(recBuf))
			if filePos+toRead > totalBytes {
				toRead = totalBytes - filePos
			}
			n, err := d.f.ReadAt(recBuf[:toRead], netblockHeaderSize+filePos)
			if n == 0 {
				break
			}
			numRecs := n / recSize
			for i := 0; i < numRecs; i++ {
				globalIdx := int(filePos/int64(recSize)) + i
				rec := recBuf[i*recSize : (i+1)*recSize]
				netnameOff := binary.LittleEndian.Uint32(rec[4:8])
				orgOff := binary.LittleEndian.Uint32(rec[8:12])

				org, orgMatch := matchedOffsets[orgOff]
				nn, netMatch := matchedOffsets[netnameOff]
				orgName, netName := org.s, nn.s

				if orgMatch || netMatch {
					startInt := binary.LittleEndian.Uint32(rec[0:4])
					var endInt uint32
					if globalIdx+1 < d.v4Count {
						if i+1 < numRecs {
							endInt = binary.LittleEndian.Uint32(recBuf[(i+1)*recSize:(i+1)*recSize+4]) - 1
						} else {
							var nextStartBuf [4]byte
							if _, err := d.f.ReadAt(nextStartBuf[:], netblockHeaderSize+int64(globalIdx+1)*int64(recSize)); err == nil {
								endInt = binary.LittleEndian.Uint32(nextStartBuf[:]) - 1
							} else {
								endInt = 0xffffffff
							}
						}
					} else {
						endInt = 0xffffffff
					}

					if orgName == "" && orgOff != 0 {
						orgName, _ = d.str(orgOff)
						if IsVerificationToken(orgName) {
							orgName = ""
						}
					}
					if netName == "" && netnameOff != 0 {
						netName, _ = d.str(netnameOff)
					}

					var startIP, endIP [4]byte
					binary.BigEndian.PutUint32(startIP[:], startInt)
					binary.BigEndian.PutUint32(endIP[:], endInt)
					if opts.Keep != nil && !opts.Keep(net.IP(startIP[:])) {
						continue
					}

					results = append(results, NetblockSearchResult{
						RangeStart: net.IP(startIP[:]),
						RangeEnd:   net.IP(endIP[:]),
						CIDRs:      IPv4RangeToCIDRs(startInt, endInt),
						Netname:    netName,
						Org:        orgName,
						IsV6:       false,
						Match:      bestMatch(org, orgMatch, nn, netMatch),
					})

					if full(results[len(results)-1]) {
						return rankResults(results, opts), nil
					}
				}
			}
			filePos += int64(n)
			if err != nil {
				break
			}
		}
	}

	// 2. Search IPv6 segments
	if !opts.V4Only && d.v6Count > 0 {
		recSize := int(d.rec6)
		recBuf := make([]byte, 1024*recSize*32) // 32K records per chunk
		totalBytes := int64(d.v6Count) * int64(recSize)
		var filePos int64 = 0

		for filePos < totalBytes {
			toRead := int64(len(recBuf))
			if filePos+toRead > totalBytes {
				toRead = totalBytes - filePos
			}
			n, err := d.f.ReadAt(recBuf[:toRead], d.v6Off+filePos)
			if n == 0 {
				break
			}
			numRecs := n / recSize
			for i := 0; i < numRecs; i++ {
				globalIdx := int(filePos/int64(recSize)) + i
				rec := recBuf[i*recSize : (i+1)*recSize]
				netnameOff := binary.LittleEndian.Uint32(rec[16:20])
				orgOff := binary.LittleEndian.Uint32(rec[20:24])

				org, orgMatch := matchedOffsets[orgOff]
				nn, netMatch := matchedOffsets[netnameOff]
				orgName, netName := org.s, nn.s

				if orgMatch || netMatch {
					var startBytes, endBytes [16]byte
					copy(startBytes[:], rec[0:16])
					if opts.Keep != nil && !opts.Keep(net.IP(startBytes[:])) {
						continue
					}

					if globalIdx+1 < d.v6Count {
						var nextStart [16]byte
						if i+1 < numRecs {
							copy(nextStart[:], recBuf[(i+1)*recSize:(i+1)*recSize+16])
							endBytes = decBytes16(nextStart)
						} else {
							if _, err := d.f.ReadAt(nextStart[:], d.v6Off+int64(globalIdx+1)*int64(recSize)); err == nil {
								endBytes = decBytes16(nextStart)
							} else {
								for j := range endBytes {
									endBytes[j] = 0xff
								}
							}
						}
					} else {
						for j := range endBytes {
							endBytes[j] = 0xff
						}
					}

					if orgName == "" && orgOff != 0 {
						orgName, _ = d.str(orgOff)
						if IsVerificationToken(orgName) {
							orgName = ""
						}
					}
					if netName == "" && netnameOff != 0 {
						netName, _ = d.str(netnameOff)
					}

					results = append(results, NetblockSearchResult{
						RangeStart: net.IP(append([]byte(nil), startBytes[:]...)),
						RangeEnd:   net.IP(append([]byte(nil), endBytes[:]...)),
						CIDRs:      IPv6RangeToCIDRs(startBytes, endBytes),
						Netname:    netName,
						Org:        orgName,
						IsV6:       true,
						Match:      bestMatch(org, orgMatch, nn, netMatch),
					})

					if full(results[len(results)-1]) {
						return rankResults(results, opts), nil
					}
				}
			}
			filePos += int64(n)
			if err != nil {
				break
			}
		}
	}

	return rankResults(results, opts), nil
}

// matchedString is a string from the netblock string table that matched a
// search, and how.
type matchedString struct {
	s    string
	rank int
}

// bestMatch is the better of how a range's org and netname matched.
func bestMatch(org matchedString, orgOK bool, net matchedString, netOK bool) int {
	switch {
	case orgOK && netOK:
		return min(org.rank, net.rank)
	case orgOK:
		return org.rank
	}
	return net.rank
}

// rankResults puts a fuzzy search's results best match first, keeping the
// address order within each rank, and applies the limit.
func rankResults(results []NetblockSearchResult, opts NetblockSearchOptions) []NetblockSearchResult {
	if opts.Fuzzy {
		sort.SliceStable(results, func(i, j int) bool { return results[i].Match < results[j].Match })
	} else {
		// How a plain search matched goes without saying.
		for i := range results {
			results[i].Match = MatchNone
		}
	}
	if opts.Limit > 0 && len(results) > opts.Limit {
		results = results[:opts.Limit]
	}
	return results
}

func (d *NetblockDB) searchStrings(m *NameMatcher) (map[uint32]matchedString, error) {
	matched := make(map[uint32]matchedString)
	err := d.EachString(func(off uint32, str []byte) {
		if rank := m.Rank(str); rank != MatchNone && !IsVerificationToken(string(str)) {
			matched[off] = matchedString{string(str), rank}
		}
	})
	return matched, err
}

// EachString calls fn with every string in the string table and its
// offset, reading the table sequentially. str is only valid during the call.
func (d *NetblockDB) EachString(fn func(off uint32, str []byte)) error {
	buf := make([]byte, 1024*1024)
	var curStr []byte
	var strStartOff uint32 = 0
	var filePos int64 = 0

	for filePos < d.strLen {
		toRead := int64(len(buf))
		if filePos+toRead > d.strLen {
			toRead = d.strLen - filePos
		}
		n, err := d.f.ReadAt(buf[:toRead], d.strOff+filePos)
		if n == 0 {
			break
		}
		chunk := buf[:n]
		idx := 0
		for {
			nullIdx := bytes.IndexByte(chunk[idx:], 0)
			if nullIdx < 0 {
				curStr = append(curStr, chunk[idx:]...)
				break
			}
			str := chunk[idx : idx+nullIdx]
			if len(curStr) > 0 {
				// The string began in the previous chunk.
				curStr = append(curStr, str...)
				str = curStr
			}
			fn(strStartOff, str)
			idx += nullIdx + 1
			strStartOff = uint32(filePos + int64(idx))
			curStr = curStr[:0]
		}
		filePos += int64(n)
		if err != nil && err != io.EOF {
			return err
		}
	}
	return nil
}

// foldMatcher reports whether a string contains a query, ignoring case. An
// ASCII query is matched by folding bytes as it compares them, so the search
// does not allocate a lower-cased copy of each of the millions of strings;
// any other query falls back to bytes.ToLower.
type foldMatcher struct {
	query []byte // lower-cased
	ascii bool
}

func newFoldMatcher(query string) foldMatcher {
	m := foldMatcher{query: []byte(strings.ToLower(query)), ascii: true}
	for _, c := range m.query {
		if c >= utf8.RuneSelf {
			m.ascii = false
			break
		}
	}
	return m
}

func (m foldMatcher) match(s []byte) bool {
	q := m.query
	if !m.ascii {
		return bytes.Contains(bytes.ToLower(s), q)
	}
	if len(q) == 0 {
		return true
	}
	first, firstUpper := q[0], upperASCII(q[0])
	for i := 0; i+len(q) <= len(s); i++ {
		if c := s[i]; c != first && c != firstUpper {
			continue
		}
		j := 1
		for j < len(q) && lowerASCII(s[i+j]) == q[j] {
			j++
		}
		if j == len(q) {
			return true
		}
	}
	return false
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

func upperASCII(c byte) byte {
	if 'a' <= c && c <= 'z' {
		return c - ('a' - 'A')
	}
	return c
}

func decBytes16(b [16]byte) [16]byte {
	for i := 15; i >= 0; i-- {
		b[i]--
		if b[i] != 0xff {
			break
		}
	}
	return b
}

// IPv4RangeToCIDRs converts an IPv4 [start, end] integer range into minimal CIDR notation prefixes.
func IPv4RangeToCIDRs(start, end uint32) []string {
	var cidrs []string
	cur := uint64(start)
	end64 := uint64(end)

	for cur <= end64 {
		tz := 32
		if cur != 0 {
			tz = bits.TrailingZeros32(uint32(cur))
		}
		diff := end64 - cur + 1
		maxK := 63 - bits.LeadingZeros64(diff)
		if maxK > tz {
			maxK = tz
		}
		maskLen := 32 - maxK

		var ip [4]byte
		binary.BigEndian.PutUint32(ip[:], uint32(cur))
		cidrs = append(cidrs, fmt.Sprintf("%d.%d.%d.%d/%d", ip[0], ip[1], ip[2], ip[3], maskLen))

		cur += 1 << maxK
	}
	return cidrs
}

// IPv6RangeToCIDRs converts an IPv6 [start, end] byte range into minimal CIDR notation prefixes.
func IPv6RangeToCIDRs(start, end [16]byte) []string {
	var startInt, endInt big.Int
	startInt.SetBytes(start[:])
	endInt.SetBytes(end[:])

	var one big.Int
	one.SetInt64(1)

	var cidrs []string
	cur := new(big.Int).Set(&startInt)

	for cur.Cmp(&endInt) <= 0 {
		diff := new(big.Int).Sub(&endInt, cur)
		diff.Add(diff, &one)

		tz := 128
		if cur.Sign() != 0 {
			for i := 0; i < 128; i++ {
				if cur.Bit(i) != 0 {
					tz = i
					break
				}
			}
		}

		maxK := diff.BitLen() - 1
		if maxK > tz {
			maxK = tz
		}
		maskLen := 128 - maxK

		ipBytes := cur.Bytes()
		var fullIP [16]byte
		copy(fullIP[16-len(ipBytes):], ipBytes)
		ip := net.IP(fullIP[:])
		cidrs = append(cidrs, fmt.Sprintf("%s/%d", ip.String(), maskLen))

		step := new(big.Int).Lsh(&one, uint(maxK))
		cur.Add(cur, step)
	}
	return cidrs
}

// NetblockRange is one segment of the netblock database: the addresses
// from Start to End and the offsets of its netname and organisation in the
// string table (0 for none). Netname and Org are filled in when asked for.
type NetblockRange struct {
	Start, End         netip.Addr
	NetnameOff, OrgOff uint32
}

// EachRange calls fn for every segment that has a netname or organisation,
// IPv4 then IPv6, in address order. It stops at the first error fn returns.
func (d *NetblockDB) EachRange(fn func(NetblockRange) error) error {
	if d == nil || d.f == nil {
		return fmt.Errorf("netblock database is not open")
	}
	for _, v6 := range []bool{false, true} {
		count, recSize, base, addrLen := d.v4Count, d.rec4, int64(netblockHeaderSize), 4
		if v6 {
			count, recSize, base, addrLen = d.v6Count, d.rec6, d.v6Off, 16
		}
		if count == 0 {
			continue
		}
		const chunk = 32 * 1024
		buf := make([]byte, (chunk+1)*int(recSize))
		for first := 0; first < count; first += chunk {
			n := min(chunk+1, count-first) // one more, for the last segment's end
			if _, err := d.f.ReadAt(buf[:n*int(recSize)], base+int64(first)*recSize); err != nil && err != io.EOF {
				return err
			}
			for i := 0; i < n && first+i < count && i < chunk; i++ {
				rec := buf[i*int(recSize) : (i+1)*int(recSize)]
				netOff := binary.LittleEndian.Uint32(rec[addrLen : addrLen+4])
				orgOff := binary.LittleEndian.Uint32(rec[addrLen+4 : addrLen+8])
				if netOff == 0 && orgOff == 0 {
					continue
				}
				r := NetblockRange{NetnameOff: netOff, OrgOff: orgOff}
				last := first+i+1 >= count
				if v6 {
					var s, e [16]byte
					copy(s[:], rec[:16])
					if last {
						e = [16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
					} else {
						var next [16]byte
						copy(next[:], buf[(i+1)*int(recSize):])
						e = decBytes16(next)
					}
					r.Start, r.End = netip.AddrFrom16(s), netip.AddrFrom16(e)
				} else {
					s := binary.LittleEndian.Uint32(rec[:4])
					e := uint32(0xffffffff)
					if !last {
						e = binary.LittleEndian.Uint32(buf[(i+1)*int(recSize):]) - 1
					}
					r.Start, r.End = addr4(s), addr4(e)
				}
				if err := fn(r); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Strings returns the strings at the given offsets of the string table.
func (d *NetblockDB) Strings(offsets map[uint32]bool) (map[uint32]string, error) {
	out := make(map[uint32]string, len(offsets))
	for off := range offsets {
		s, err := d.str(off)
		if err != nil {
			return nil, err
		}
		out[off] = s
	}
	return out, nil
}

func addr4(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// Within returns the registry ranges inside prefix, the most specific record
// for each part of it, clipped to the prefix, in address order. Parts with
// no record are left out. opts.Keep filters as in SearchOrg; opts.Limit, when
// positive, stops the walk once that many are found.
func (d *NetblockDB) Within(prefix netip.Prefix, opts NetblockSearchOptions) ([]NetblockSearchResult, error) {
	if d == nil || d.f == nil {
		return nil, fmt.Errorf("netblock database is not open")
	}
	prefix = prefix.Masked()
	first := prefix.Addr()
	if first.Is4() {
		if opts.V6Only {
			return nil, nil
		}
		return d.within4(first, prefix.Bits(), opts)
	}
	if opts.V4Only {
		return nil, nil
	}
	return d.within6(first, prefix.Bits(), opts)
}

// segmentRecord reads the netname and org offsets of a record.
func (d *NetblockDB) segmentRecord(off int64) (netname, org string, ok bool, err error) {
	var buf [8]byte
	if _, err := d.f.ReadAt(buf[:], off); err != nil {
		return "", "", false, err
	}
	nOff, oOff := binary.LittleEndian.Uint32(buf[0:4]), binary.LittleEndian.Uint32(buf[4:8])
	if nOff == 0 && oOff == 0 {
		return "", "", false, nil
	}
	if netname, err = d.str(nOff); err != nil {
		return "", "", false, err
	}
	if org, err = d.str(oOff); err != nil {
		return "", "", false, err
	}
	if IsVerificationToken(org) {
		org = ""
	}
	return netname, org, netname != "" || org != "", nil
}

func (d *NetblockDB) within4(first netip.Addr, bitsLen int, opts NetblockSearchOptions) ([]NetblockSearchResult, error) {
	b := first.As4()
	lo := binary.BigEndian.Uint32(b[:])
	hi := lo | uint32(uint64(1)<<(32-bitsLen)-1)
	// The record holding lo: the last whose start is <= lo.
	i := sort.Search(d.v4Count, func(k int) bool {
		s, err := d.start4(k)
		return err != nil || s > lo
	}) - 1
	if i < 0 {
		i = 0
	}
	var out []NetblockSearchResult
	for ; i < d.v4Count; i++ {
		start, err := d.start4(i)
		if err != nil {
			return out, err
		}
		if start > hi {
			break
		}
		end := uint32(0xffffffff)
		if i+1 < d.v4Count {
			next, err := d.start4(i + 1)
			if err != nil {
				return out, err
			}
			end = next - 1
		}
		if end < lo {
			continue
		}
		s, e := max(start, lo), min(end, hi)
		netname, org, ok, err := d.segmentRecord(netblockHeaderSize + int64(i)*d.rec4 + 4)
		if err != nil {
			return out, err
		}
		if !ok {
			continue
		}
		var sIP, eIP [4]byte
		binary.BigEndian.PutUint32(sIP[:], s)
		binary.BigEndian.PutUint32(eIP[:], e)
		if opts.Keep != nil && !opts.Keep(net.IP(sIP[:])) {
			continue
		}
		out = append(out, NetblockSearchResult{
			RangeStart: net.IP(sIP[:]),
			RangeEnd:   net.IP(eIP[:]),
			CIDRs:      IPv4RangeToCIDRs(s, e),
			Netname:    netname,
			Org:        org,
		})
		if opts.Limit > 0 && len(out) >= opts.Limit {
			break
		}
	}
	return out, nil
}

func (d *NetblockDB) within6(first netip.Addr, bitsLen int, opts NetblockSearchOptions) ([]NetblockSearchResult, error) {
	lo := first.As16()
	hi := lo
	for k := bitsLen; k < 128; k++ {
		hi[k/8] |= 0x80 >> (k % 8)
	}
	i := sort.Search(d.v6Count, func(k int) bool {
		s, err := d.start6(k)
		return err != nil || bytes.Compare(s[:], lo[:]) > 0
	}) - 1
	if i < 0 {
		i = 0
	}
	var out []NetblockSearchResult
	for ; i < d.v6Count; i++ {
		start, err := d.start6(i)
		if err != nil {
			return out, err
		}
		if bytes.Compare(start[:], hi[:]) > 0 {
			break
		}
		end := [16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		if i+1 < d.v6Count {
			next, err := d.start6(i + 1)
			if err != nil {
				return out, err
			}
			end = decBytes16(next)
		}
		if bytes.Compare(end[:], lo[:]) < 0 {
			continue
		}
		s, e := start, end
		if bytes.Compare(s[:], lo[:]) < 0 {
			s = lo
		}
		if bytes.Compare(e[:], hi[:]) > 0 {
			e = hi
		}
		netname, org, ok, err := d.segmentRecord(d.v6Off + int64(i)*d.rec6 + 16)
		if err != nil {
			return out, err
		}
		if !ok {
			continue
		}
		if opts.Keep != nil && !opts.Keep(net.IP(append([]byte(nil), s[:]...))) {
			continue
		}
		out = append(out, NetblockSearchResult{
			RangeStart: net.IP(append([]byte(nil), s[:]...)),
			RangeEnd:   net.IP(append([]byte(nil), e[:]...)),
			CIDRs:      IPv6RangeToCIDRs(s, e),
			Netname:    netname,
			Org:        org,
			IsV6:       true,
		})
		if opts.Limit > 0 && len(out) >= opts.Limit {
			break
		}
	}
	return out, nil
}
