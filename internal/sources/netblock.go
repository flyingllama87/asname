package sources

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"math/bits"
	"net"
	"os"
	"strings"
	"unicode/utf8"
)

const (
	NetblockEnvVar   = "ASNAME_NETBLOCK"
	NetblockFilename = "netblock.db"

	netblockMagic      = "ASNBLK\x00\x01"
	netblockHeaderSize = 40
	netblockSeg4Size   = 12
	netblockSeg6Size   = 24
)

// NetblockDB maps an address to the registry netblock it was assigned in.
type NetblockDB struct {
	f       *os.File
	v4Count int
	v6Count int
	v6Off   int64
	strOff  int64
	strLen  int64
}

// NetblockInfo is what the database knows about one address.
type NetblockInfo struct {
	Netname string
	Org     string
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
	if string(hdr[:8]) != netblockMagic {
		f.Close()
		return nil, fmt.Errorf("not an asname netblock database (rebuild with `asname update --netblock-only`)")
	}

	db := &NetblockDB{
		f:       f,
		v4Count: int(binary.LittleEndian.Uint32(hdr[16:20])),
		v6Count: int(binary.LittleEndian.Uint32(hdr[20:24])),
		strOff:  int64(binary.LittleEndian.Uint64(hdr[24:32])),
		strLen:  int64(binary.LittleEndian.Uint64(hdr[32:40])),
	}
	db.v6Off = netblockHeaderSize + int64(db.v4Count)*netblockSeg4Size

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
	return d.info(netblockHeaderSize + int64(lo-1)*netblockSeg4Size + 4)
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
	return d.info(d.v6Off + int64(lo-1)*netblockSeg6Size + 16)
}

func (d *NetblockDB) start4(i int) (uint32, error) {
	var buf [4]byte
	if _, err := d.f.ReadAt(buf[:], netblockHeaderSize+int64(i)*netblockSeg4Size); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(buf[:]), nil
}

func (d *NetblockDB) start6(i int) ([16]byte, error) {
	var buf [16]byte
	if _, err := d.f.ReadAt(buf[:], d.v6Off+int64(i)*netblockSeg6Size); err != nil {
		return buf, err
	}
	return buf, nil
}

func (d *NetblockDB) info(off int64) (NetblockInfo, error) {
	var buf [8]byte
	if _, err := d.f.ReadAt(buf[:], off); err != nil {
		return NetblockInfo{}, err
	}
	netname, err := d.str(binary.LittleEndian.Uint32(buf[0:4]))
	if err != nil {
		return NetblockInfo{}, err
	}
	org, err := d.str(binary.LittleEndian.Uint32(buf[4:8]))
	if err != nil {
		return NetblockInfo{}, err
	}
	return NetblockInfo{Netname: netname, Org: org}, nil
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
}

// NetblockSearchOptions controls search filters and limits.
type NetblockSearchOptions struct {
	Limit  int
	V4Only bool
	V6Only bool
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

	matchedOffsets, err := d.searchStrings(query)
	if err != nil {
		return nil, fmt.Errorf("searching netblock strings: %v", err)
	}
	if len(matchedOffsets) == 0 {
		return nil, nil
	}

	var results []NetblockSearchResult

	// 1. Search IPv4 segments
	if !opts.V6Only && d.v4Count > 0 {
		const recSize = netblockSeg4Size
		recBuf := make([]byte, 1024*recSize*64) // 64K records per chunk
		totalBytes := int64(d.v4Count) * recSize
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
				globalIdx := int(filePos/recSize) + i
				rec := recBuf[i*recSize : (i+1)*recSize]
				netnameOff := binary.LittleEndian.Uint32(rec[4:8])
				orgOff := binary.LittleEndian.Uint32(rec[8:12])

				orgName, orgMatch := matchedOffsets[orgOff]
				netName, netMatch := matchedOffsets[netnameOff]

				if orgMatch || netMatch {
					startInt := binary.LittleEndian.Uint32(rec[0:4])
					var endInt uint32
					if globalIdx+1 < d.v4Count {
						if i+1 < numRecs {
							endInt = binary.LittleEndian.Uint32(recBuf[(i+1)*recSize:(i+1)*recSize+4]) - 1
						} else {
							var nextStartBuf [4]byte
							if _, err := d.f.ReadAt(nextStartBuf[:], netblockHeaderSize+int64(globalIdx+1)*recSize); err == nil {
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
					}
					if netName == "" && netnameOff != 0 {
						netName, _ = d.str(netnameOff)
					}

					var startIP, endIP [4]byte
					binary.BigEndian.PutUint32(startIP[:], startInt)
					binary.BigEndian.PutUint32(endIP[:], endInt)

					results = append(results, NetblockSearchResult{
						RangeStart: net.IP(startIP[:]),
						RangeEnd:   net.IP(endIP[:]),
						CIDRs:      IPv4RangeToCIDRs(startInt, endInt),
						Netname:    netName,
						Org:        orgName,
						IsV6:       false,
					})

					if opts.Limit > 0 && len(results) >= opts.Limit {
						return results, nil
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
		const recSize = netblockSeg6Size
		recBuf := make([]byte, 1024*recSize*32) // 32K records per chunk
		totalBytes := int64(d.v6Count) * recSize
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
				globalIdx := int(filePos/recSize) + i
				rec := recBuf[i*recSize : (i+1)*recSize]
				netnameOff := binary.LittleEndian.Uint32(rec[16:20])
				orgOff := binary.LittleEndian.Uint32(rec[20:24])

				orgName, orgMatch := matchedOffsets[orgOff]
				netName, netMatch := matchedOffsets[netnameOff]

				if orgMatch || netMatch {
					var startBytes, endBytes [16]byte
					copy(startBytes[:], rec[0:16])

					if globalIdx+1 < d.v6Count {
						var nextStart [16]byte
						if i+1 < numRecs {
							copy(nextStart[:], recBuf[(i+1)*recSize:(i+1)*recSize+16])
							endBytes = decBytes16(nextStart)
						} else {
							if _, err := d.f.ReadAt(nextStart[:], d.v6Off+int64(globalIdx+1)*recSize); err == nil {
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
					})

					if opts.Limit > 0 && len(results) >= opts.Limit {
						return results, nil
					}
				}
			}
			filePos += int64(n)
			if err != nil {
				break
			}
		}
	}

	return results, nil
}

func (d *NetblockDB) searchStrings(query string) (map[uint32]string, error) {
	m := newFoldMatcher(query)
	matched := make(map[uint32]string)

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
			if m.match(str) {
				matched[strStartOff] = string(str)
			}
			idx += nullIdx + 1
			strStartOff = uint32(filePos + int64(idx))
			curStr = curStr[:0]
		}
		filePos += int64(n)
		if err != nil && err != io.EOF {
			return nil, err
		}
	}
	return matched, nil
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
