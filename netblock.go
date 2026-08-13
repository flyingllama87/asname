package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
)

const (
	netblockEnvVar   = "ASNAME_NETBLOCK"
	netblockFilename = "netblock.db"

	// netblockMagic identifies the file and its layout. The trailing byte is a
	// version that is bumped whenever the layout changes, so that a database
	// written by an older asname is rejected rather than misread.
	netblockMagic = "ASNBLK\x00\x01"

	// netblockHeaderSize is the fixed header: magic, build time, the two
	// segment counts and the location of the string blob.
	netblockHeaderSize = 40
	// netblockSeg4Size is a v4 segment: start address, netname and org offsets.
	netblockSeg4Size = 12
	// netblockSeg6Size is the same for v6, whose start is a full 16 bytes.
	netblockSeg6Size = 24
)

// netblockDB maps an address to the registry netblock it was assigned in — the
// inetnum object the RIRs publish, which names the organisation the range was
// handed to rather than the AS announcing it.
//
// The file is a sorted array of disjoint segments, each naming the most
// specific range covering it, so a lookup is a binary search. It is read
// through the file handle rather than parsed into memory: at a few hundred
// megabytes it is far too large to inflate for a single query, and a search
// only ever touches a couple of dozen twelve-byte records.
type netblockDB struct {
	f       *os.File
	v4Count int
	v6Count int
	v6Off   int64 // start of the v6 segments
	strOff  int64 // start of the string blob
	strLen  int64
}

// netblockInfo is what the database knows about one address.
type netblockInfo struct {
	netname string // the registry's handle for the range, e.g. "SISS-SY4"
	org     string // the organisation it is assigned to
}

func (i netblockInfo) empty() bool { return i.netname == "" && i.org == "" }

// String renders the pair as "NETNAME (Organisation)", dropping either half
// when the registry only recorded one, or when both say the same thing.
func (i netblockInfo) String() string {
	switch {
	case i.netname != "" && i.org != "" && !strings.EqualFold(i.netname, i.org):
		return i.netname + " (" + i.org + ")"
	case i.netname != "":
		return i.netname
	default:
		return i.org
	}
}

// netblockDBPresent reports whether the user has opted in to netblock lookups
// by having the database on disk.
func netblockDBPresent(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// openNetblockDB opens the database and validates its header against the file
// it was read from, so that a truncated or half-written file fails here rather
// than returning nonsense from a lookup.
func openNetblockDB(path string) (*netblockDB, error) {
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

	db := &netblockDB{
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

func (d *netblockDB) Close() error {
	if d == nil || d.f == nil {
		return nil
	}
	return d.f.Close()
}

// Lookup returns the most specific netblock covering ip, or a zero
// netblockInfo when no registry range does.
func (d *netblockDB) Lookup(ip net.IP) (netblockInfo, error) {
	if ip4 := ip.To4(); ip4 != nil {
		return d.lookup4(binary.BigEndian.Uint32(ip4))
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return netblockInfo{}, fmt.Errorf("invalid IP address")
	}
	var key [16]byte
	copy(key[:], ip16)
	return d.lookup6(key)
}

func (d *netblockDB) lookup4(v uint32) (netblockInfo, error) {
	// Invariant: every segment below lo starts at or before v, every segment
	// from hi up starts after it, so lo-1 is the segment v falls in.
	lo, hi := 0, d.v4Count
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		start, err := d.start4(mid)
		if err != nil {
			return netblockInfo{}, err
		}
		if start <= v {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		return netblockInfo{}, nil
	}
	return d.info(netblockHeaderSize + int64(lo-1)*netblockSeg4Size + 4)
}

func (d *netblockDB) lookup6(v [16]byte) (netblockInfo, error) {
	lo, hi := 0, d.v6Count
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		start, err := d.start6(mid)
		if err != nil {
			return netblockInfo{}, err
		}
		if bytes.Compare(start[:], v[:]) <= 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		return netblockInfo{}, nil
	}
	return d.info(d.v6Off + int64(lo-1)*netblockSeg6Size + 16)
}

func (d *netblockDB) start4(i int) (uint32, error) {
	var buf [4]byte
	if _, err := d.f.ReadAt(buf[:], netblockHeaderSize+int64(i)*netblockSeg4Size); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(buf[:]), nil
}

func (d *netblockDB) start6(i int) ([16]byte, error) {
	var buf [16]byte
	if _, err := d.f.ReadAt(buf[:], d.v6Off+int64(i)*netblockSeg6Size); err != nil {
		return buf, err
	}
	return buf, nil
}

// info reads the pair of string offsets a segment stores at off and resolves
// both against the string blob.
func (d *netblockDB) info(off int64) (netblockInfo, error) {
	var buf [8]byte
	if _, err := d.f.ReadAt(buf[:], off); err != nil {
		return netblockInfo{}, err
	}
	netname, err := d.str(binary.LittleEndian.Uint32(buf[0:4]))
	if err != nil {
		return netblockInfo{}, err
	}
	org, err := d.str(binary.LittleEndian.Uint32(buf[4:8]))
	if err != nil {
		return netblockInfo{}, err
	}
	return netblockInfo{netname: netname, org: org}, nil
}

// str reads the NUL-terminated string at off within the blob. Offset 0 is
// always the empty string, so it doubles as "the registry did not say".
func (d *netblockDB) str(off uint32) (string, error) {
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
