package main

import (
	"net"
	"net/netip"
	"os"
	"sort"

	"github.com/oschwald/maxminddb-golang/v2"
)

const (
	cityEnvVar   = "ASNAME_CITY"
	cityFilename = "city.mmdb"
)

// cityRecord is the subset of the DB-IP Lite / GeoLite2 City schema we display.
// Both use the same layout, so either file works.
type cityRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
}

// loadCityDB memory-maps the city database. Unlike the other two databases this
// one is left on disk rather than parsed into memory: at ~125MB it is an order
// of magnitude larger, and the MaxMind DB format is built for random access.
func loadCityDB(path string) (*maxminddb.Reader, error) {
	return maxminddb.Open(path)
}

// cityDBPresent reports whether the user has opted in to city lookups by
// having the database on disk.
func cityDBPresent(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// lookupCity returns "City, Region", or whichever of the two the database
// knows, or "" when the address is not in it.
func lookupCity(db *maxminddb.Reader, ip net.IP) string {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return ""
	}
	// The tries want the 16-byte form, but an IPv4-mapped address has to be
	// unmapped again here or it is looked up as IPv6.
	res := db.Lookup(addr.Unmap())
	if !res.Found() {
		return ""
	}
	var rec cityRecord
	if err := res.Decode(&rec); err != nil {
		return ""
	}

	region := ""
	if len(rec.Subdivisions) > 0 {
		region = preferredName(rec.Subdivisions[0].Names)
	}
	return formatCity(preferredName(rec.City.Names), region)
}

// formatCity joins a city and its region, tolerating either being missing and
// avoiding "Singapore, Singapore" where a city-state repeats itself.
func formatCity(city, region string) string {
	switch {
	case city != "" && region != "" && city != region:
		return city + ", " + region
	case city != "":
		return city
	default:
		return region
	}
}

// preferredName picks the English label, falling back to the alphabetically
// first available language so that records without an "en" key still say
// something rather than nothing.
func preferredName(names map[string]string) string {
	if n := names["en"]; n != "" {
		return n
	}
	langs := make([]string, 0, len(names))
	for lang := range names {
		langs = append(langs, lang)
	}
	sort.Strings(langs)
	for _, lang := range langs {
		if names[lang] != "" {
			return names[lang]
		}
	}
	return ""
}
