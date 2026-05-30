package main

import (
	"net"
	"os"

	"asname/pkg/database"
)

const (
	countryEnvVar   = "ASNAME_COUNTRY"
	countryFilename = "country.db"
)

// loadCountryDB inflates the IP->country LC-trie. The trie stores the ISO
// 3166-1 alpha-2 country code packed into the uint32 "AS number" slot, which
// lets us reuse asnlookup's database/trie machinery unchanged.
func loadCountryDB(path string) (database.Database, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return database.NewFromDump(f)
}

// lookupCountry returns "CC, Country Name" for an IP, or just "CC" when the
// name is unknown, or "" when the IP is not in the database.
func lookupCountry(db database.Database, ip net.IP) string {
	as, err := db.Lookup(ip)
	if err != nil {
		return ""
	}
	cc := decodeCC(as.Number)
	if name, ok := countryNames[cc]; ok {
		return cc + ", " + name
	}
	return cc
}

// encodeCC packs a 2-letter country code into a uint32 (always non-zero for a
// valid code, so it never collides with the trie's "not found" sentinel of 0).
func encodeCC(cc string) uint32 {
	if len(cc) != 2 {
		return 0
	}
	return uint32(cc[0])<<8 | uint32(cc[1])
}

// decodeCC reverses encodeCC.
func decodeCC(v uint32) string {
	return string([]byte{byte(v >> 8), byte(v)})
}
