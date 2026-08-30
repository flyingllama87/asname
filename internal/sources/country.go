package sources

import (
	"net"
	"os"

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
