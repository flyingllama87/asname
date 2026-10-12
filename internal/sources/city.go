package sources

import (
	"net"
	"net/netip"
	"os"
	"sort"

	"github.com/oschwald/maxminddb-golang/v2"
)

const (
	CityEnvVar   = "ASNAME_CITY"
	CityFilename = "city.mmdb"
)

type cityRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// LoadCityDB memory-maps the city database.
func LoadCityDB(path string) (*maxminddb.Reader, error) {
	return maxminddb.Open(path)
}

// CityDBPresent reports whether the user has opted in to city lookups.
func CityDBPresent(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// LookupCity returns "City, Region, Country", leaving out any part the
// database does not know. The country is DB-IP's geolocated country, which can
// differ from the registration country LookupCountry returns.
func LookupCity(db *maxminddb.Reader, ip net.IP) string {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return ""
	}
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
		region = PreferredName(rec.Subdivisions[0].Names)
	}
	place := FormatCity(PreferredName(rec.City.Names), region)
	country := rec.Country.ISOCode
	if name := CountryNames[country]; name != "" {
		country = name
	}
	switch {
	case place == "":
		return country
	case country == "":
		return place
	default:
		return place + ", " + country
	}
}

// FormatCity joins a city and its region.
func FormatCity(city, region string) string {
	switch {
	case city != "" && region != "" && city != region:
		return city + ", " + region
	case city != "":
		return city
	default:
		return region
	}
}

// PreferredName picks the English label or alphabetically first available language.
func PreferredName(names map[string]string) string {
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
