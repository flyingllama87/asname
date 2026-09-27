package sources

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/flyingllama87/asname/pkg/database"
)

const (
	CountryEnvVar   = "ASNAME_COUNTRY"
	CountryFilename = "country.db"
)

// LoadCountryDB inflates the IP->country LC-trie.
func LoadCountryDB(path string) (database.Database, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return database.NewFromDump(f)
}

// LookupCountry returns "CC, Country Name" for an IP, or just "CC" when the
// name is unknown, or "" when the IP is not in the database.
func LookupCountry(db database.Database, ip net.IP) string {
	as, err := db.Lookup(ip)
	if err != nil {
		return ""
	}
	cc := DecodeCC(as.Number)
	if name, ok := CountryNames[cc]; ok {
		return cc + ", " + name
	}
	return cc
}

// EncodeCC packs a 2-letter country code into a uint32.
func EncodeCC(cc string) uint32 {
	if len(cc) != 2 {
		return 0
	}
	return uint32(cc[0])<<8 | uint32(cc[1])
}

// DecodeCC reverses EncodeCC.
func DecodeCC(v uint32) string {
	return string([]byte{byte(v >> 8), byte(v)})
}

// v4Mapped is the IPv4-mapped block ::ffff:0:0/96 in which the country
// database holds IPv4 ranges.
var (
	v4MappedStart = [16]byte{10: 0xff, 11: 0xff}
	v4MappedEnd   = [16]byte{10: 0xff, 11: 0xff, 12: 0xff, 13: 0xff, 14: 0xff, 15: 0xff}
)

// CountryPrefixes returns the minimal CIDR blocks db assigns to the country
// with ISO code cc, IPv4 and IPv6 separately, in ascending address order.
func CountryPrefixes(db database.Database, cc string) (v4, v6 []string, err error) {
	want := EncodeCC(strings.ToUpper(cc))
	if want == 0 {
		return nil, nil, fmt.Errorf("invalid country code %q: want two letters, such as AU", cc)
	}
	err = database.Walk(db, func(start, end [16]byte, value uint32) bool {
		if value != want {
			return true
		}
		// A range can straddle the edges of the IPv4-mapped block; the parts
		// outside it are IPv6.
		if bytes.Compare(start[:], v4MappedStart[:]) < 0 {
			v6End := end
			if bytes.Compare(end[:], v4MappedStart[:]) >= 0 {
				v6End = decBytes16(v4MappedStart)
			}
			v6 = append(v6, IPv6RangeToCIDRs(start, v6End)...)
			if v6End == end {
				return true
			}
			start = v4MappedStart
		}
		if bytes.Compare(start[:], v4MappedEnd[:]) <= 0 {
			v4End := end
			if bytes.Compare(end[:], v4MappedEnd[:]) > 0 {
				v4End = v4MappedEnd
			}
			v4 = append(v4, IPv4RangeToCIDRs(binary.BigEndian.Uint32(start[12:]), binary.BigEndian.Uint32(v4End[12:]))...)
			if v4End == end {
				return true
			}
			start, _ = IncBytes16(v4MappedEnd)
		}
		v6 = append(v6, IPv6RangeToCIDRs(start, end)...)
		return true
	})
	return v4, v6, err
}

// ParseCountry resolves a two-letter ISO code or an English country name,
// ignoring case, to its upper-case code.
func ParseCountry(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) == 2 {
		return strings.ToUpper(s), nil
	}
	for cc, name := range CountryNames {
		if strings.EqualFold(name, s) {
			return cc, nil
		}
	}
	return "", fmt.Errorf("unknown country %q: give a two-letter ISO code, such as AU, or an English name, such as Australia", s)
}
