package sources

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
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
