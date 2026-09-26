package sources

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	PrefixEnvVar   = "ASNAME_PREFIXES"
	PrefixFilename = "prefixes.db"

	prefixMagic      = "ASNPRX\x00\x01"
	prefixHeaderSize = 32
	prefixIndexSize  = 16
)

// ASNPrefixResult holds the announced prefixes for an ASN.
type ASNPrefixResult struct {
	ASN    uint32   `json:"asn"`
	IPv4   []string `json:"ipv4"`
	IPv6   []string `json:"ipv6"`
	Source string   `json:"source"` // "offline" or "ripe-stat"
}

func (r ASNPrefixResult) Total() int {
	return len(r.IPv4) + len(r.IPv6)
}

func (r ASNPrefixResult) All() []string {
	all := make([]string, 0, len(r.IPv4)+len(r.IPv6))
	all = append(all, r.IPv4...)
	all = append(all, r.IPv6...)
	return all
}

// PrefixDB is a read-only offline database of ASN to announced IP prefixes.
type PrefixDB struct {
	f        *os.File
	asnCount int
}

func PrefixDBPresent(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// OpenPrefixDB opens and validates an offline prefixes database.
func OpenPrefixDB(path string) (*PrefixDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	var hdr [prefixHeaderSize]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		f.Close()
		return nil, fmt.Errorf("reading prefixes header: %v", err)
	}

	if string(hdr[:8]) != prefixMagic {
		f.Close()
		return nil, fmt.Errorf("not an asname prefix database (rebuild with `asname update --db-only`)")
	}

	asnCount := int(binary.LittleEndian.Uint32(hdr[16:20]))
	return &PrefixDB{
		f:        f,
		asnCount: asnCount,
	}, nil
}

func (d *PrefixDB) Close() error {
	if d == nil || d.f == nil {
		return nil
	}
	return d.f.Close()
}

// Lookup finds the announced prefixes for asn via binary search.
func (d *PrefixDB) Lookup(targetASN uint32) (ASNPrefixResult, error) {
	if d == nil || d.f == nil || d.asnCount == 0 {
		return ASNPrefixResult{ASN: targetASN, Source: "offline"}, nil
	}

	lo, hi := 0, d.asnCount-1
	var foundEntry [prefixIndexSize]byte
	found := false

	for lo <= hi {
		mid := int(uint(lo+hi) >> 1)
		var entry [prefixIndexSize]byte
		off := int64(prefixHeaderSize + mid*prefixIndexSize)
		if _, err := d.f.ReadAt(entry[:], off); err != nil {
			return ASNPrefixResult{}, fmt.Errorf("reading prefix index: %v", err)
		}
		curASN := binary.LittleEndian.Uint32(entry[0:4])
		if curASN == targetASN {
			foundEntry = entry
			found = true
			break
		} else if curASN < targetASN {
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}

	if !found {
		return ASNPrefixResult{ASN: targetASN, Source: "offline"}, nil
	}

	v4Count := int(binary.LittleEndian.Uint16(foundEntry[4:6]))
	v6Count := int(binary.LittleEndian.Uint16(foundEntry[6:8]))
	dataOff := int64(binary.LittleEndian.Uint64(foundEntry[8:16]))

	res := ASNPrefixResult{
		ASN:    targetASN,
		IPv4:   make([]string, 0, v4Count),
		IPv6:   make([]string, 0, v6Count),
		Source: "offline",
	}

	if v4Count > 0 {
		buf := make([]byte, v4Count*5)
		if _, err := d.f.ReadAt(buf, dataOff); err != nil {
			return ASNPrefixResult{}, fmt.Errorf("reading v4 prefixes: %v", err)
		}
		for i := 0; i < v4Count; i++ {
			b := buf[i*5 : (i+1)*5]
			res.IPv4 = append(res.IPv4, fmt.Sprintf("%d.%d.%d.%d/%d", b[0], b[1], b[2], b[3], b[4]))
		}
		dataOff += int64(len(buf))
	}

	if v6Count > 0 {
		buf := make([]byte, v6Count*17)
		if _, err := d.f.ReadAt(buf, dataOff); err != nil {
			return ASNPrefixResult{}, fmt.Errorf("reading v6 prefixes: %v", err)
		}
		for i := 0; i < v6Count; i++ {
			b := buf[i*17 : (i+1)*17]
			ip := net.IP(b[:16])
			res.IPv6 = append(res.IPv6, fmt.Sprintf("%s/%d", ip.String(), b[16]))
		}
	}

	return res, nil
}

// PrefixDBBuilder collects prefixes per ASN from RIB entries and writes them to disk.
type PrefixDBBuilder struct {
	v4Map map[uint32]map[string]uint8
	v6Map map[uint32]map[string]uint8
}

func NewPrefixDBBuilder() *PrefixDBBuilder {
	return &PrefixDBBuilder{
		v4Map: make(map[uint32]map[string]uint8),
		v6Map: make(map[uint32]map[string]uint8),
	}
}

func (b *PrefixDBBuilder) Add(asn uint32, ipNet *net.IPNet) {
	if asn == 0 || ipNet == nil {
		return
	}
	ones, _ := ipNet.Mask.Size()
	if ip4 := ipNet.IP.To4(); ip4 != nil {
		m, ok := b.v4Map[asn]
		if !ok {
			m = make(map[string]uint8)
			b.v4Map[asn] = m
		}
		m[string(ip4)] = uint8(ones)
	} else if ip16 := ipNet.IP.To16(); ip16 != nil {
		m, ok := b.v6Map[asn]
		if !ok {
			m = make(map[string]uint8)
			b.v6Map[asn] = m
		}
		m[string(ip16)] = uint8(ones)
	}
}

func (b *PrefixDBBuilder) Write(path string) (int64, error) {
	// Collect all unique ASNs
	asnSet := make(map[uint32]bool)
	for asn := range b.v4Map {
		asnSet[asn] = true
	}
	for asn := range b.v6Map {
		asnSet[asn] = true
	}

	asns := make([]uint32, 0, len(asnSet))
	for asn := range asnSet {
		asns = append(asns, asn)
	}
	sort.Slice(asns, func(i, j int) bool { return asns[i] < asns[j] })

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return 0, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	w := bufio.NewWriterSize(tmp, 1<<20)

	// Write header
	var hdr [prefixHeaderSize]byte
	copy(hdr[:8], prefixMagic)
	binary.LittleEndian.PutUint64(hdr[8:16], uint64(time.Now().Unix()))
	binary.LittleEndian.PutUint32(hdr[16:20], uint32(len(asns)))
	if _, err := w.Write(hdr[:]); err != nil {
		tmp.Close()
		return 0, err
	}

	// Calculate index offset and data start
	dataStart := int64(prefixHeaderSize + len(asns)*prefixIndexSize)
	currentDataOffset := dataStart

	// First pass: build index records and data buffer
	type asnRecord struct {
		asn     uint32
		v4Count uint16
		v6Count uint16
		offset  uint64
		data    []byte
	}

	records := make([]asnRecord, len(asns))
	for i, asn := range asns {
		v4m := b.v4Map[asn]
		v6m := b.v6Map[asn]

		rec := asnRecord{
			asn:     asn,
			v4Count: uint16(len(v4m)),
			v6Count: uint16(len(v6m)),
			offset:  uint64(currentDataOffset),
		}

		// Pack v4
		data := make([]byte, 0, len(v4m)*5+len(v6m)*17)
		// Sort v4 prefixes
		type v4Item struct {
			ip   string
			mask uint8
		}
		var v4List []v4Item
		for ip, mask := range v4m {
			v4List = append(v4List, v4Item{ip: ip, mask: mask})
		}
		sort.Slice(v4List, func(i, j int) bool {
			return bytes.Compare([]byte(v4List[i].ip), []byte(v4List[j].ip)) < 0
		})
		for _, item := range v4List {
			data = append(data, item.ip...)
			data = append(data, item.mask)
		}

		// Sort v6 prefixes
		type v6Item struct {
			ip   string
			mask uint8
		}
		var v6List []v6Item
		for ip, mask := range v6m {
			v6List = append(v6List, v6Item{ip: ip, mask: mask})
		}
		sort.Slice(v6List, func(i, j int) bool {
			return bytes.Compare([]byte(v6List[i].ip), []byte(v6List[j].ip)) < 0
		})
		for _, item := range v6List {
			data = append(data, item.ip...)
			data = append(data, item.mask)
		}

		rec.data = data
		currentDataOffset += int64(len(data))
		records[i] = rec
	}

	// Write index table
	var idxBuf [prefixIndexSize]byte
	for _, rec := range records {
		binary.LittleEndian.PutUint32(idxBuf[0:4], rec.asn)
		binary.LittleEndian.PutUint16(idxBuf[4:6], rec.v4Count)
		binary.LittleEndian.PutUint16(idxBuf[6:8], rec.v6Count)
		binary.LittleEndian.PutUint64(idxBuf[8:16], rec.offset)
		if _, err := w.Write(idxBuf[:]); err != nil {
			tmp.Close()
			return 0, err
		}
	}

	// Write data section
	for _, rec := range records {
		if len(rec.data) > 0 {
			if _, err := w.Write(rec.data); err != nil {
				tmp.Close()
				return 0, err
			}
		}
	}

	if err := w.Flush(); err != nil {
		tmp.Close()
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

// FetchASNPrefixesOnline queries the public RIPE Stat API for announced prefixes of an ASN.
func FetchASNPrefixesOnline(ctx context.Context, asn uint32) (ASNPrefixResult, error) {
	url := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%d", asn)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ASNPrefixResult{}, err
	}
	req.Header.Set("User-Agent", "asname/"+Version+" (https://github.com/flyingllama87/asname)")

	client := &http.Client{Timeout: 7 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ASNPrefixResult{}, fmt.Errorf("querying RIPE Stat API: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ASNPrefixResult{}, fmt.Errorf("RIPE Stat API returned HTTP %d", resp.StatusCode)
	}

	var payload struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return ASNPrefixResult{}, fmt.Errorf("decoding RIPE Stat API response: %v", err)
	}

	var v4, v6 []string
	seen := make(map[string]bool)

	for _, p := range payload.Data.Prefixes {
		cidr := strings.TrimSpace(p.Prefix)
		if cidr == "" || seen[cidr] {
			continue
		}
		seen[cidr] = true

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.IP.To4() != nil {
			v4 = append(v4, cidr)
		} else {
			v6 = append(v6, cidr)
		}
	}

	// Sort CIDRs
	sort.Slice(v4, func(i, j int) bool {
		ipA, _, _ := net.ParseCIDR(v4[i])
		ipB, _, _ := net.ParseCIDR(v4[j])
		return bytes.Compare(ipA.To4(), ipB.To4()) < 0
	})
	sort.Slice(v6, func(i, j int) bool {
		ipA, _, _ := net.ParseCIDR(v6[i])
		ipB, _, _ := net.ParseCIDR(v6[j])
		return bytes.Compare(ipA.To16(), ipB.To16()) < 0
	})

	return ASNPrefixResult{
		ASN:    asn,
		IPv4:   v4,
		IPv6:   v6,
		Source: "ripe-stat",
	}, nil
}
