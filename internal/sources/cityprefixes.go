package sources

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"
)

// CityPlace is one place a city search matched, with the minimal CIDR blocks
// the city database locates there.
type CityPlace struct {
	City    string
	Region  string
	Country string // ISO code
	IPv4    []string
	IPv6    []string
}

// cityPlaceRecord is the part of a city database record CityPrefixes reads.
type cityPlaceRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
}

// CityPrefixes returns every place whose city is named query, with the blocks
// the city database locates there, the place with the most networks first.
// query may end in ", " and a region, country code or country name to pick one
// of several places with that name, as in "Brisbane, AU" or "Brisbane,
// Queensland". Names match in any language the database holds, ignoring case.
func CityPrefixes(db *maxminddb.Reader, query string) ([]CityPlace, error) {
	city, qualifier := strings.TrimSpace(query), ""
	if i := strings.LastIndex(city, ","); i >= 0 {
		city, qualifier = strings.TrimSpace(city[:i]), strings.TrimSpace(city[i+1:])
	}
	if city == "" {
		return nil, fmt.Errorf("invalid city %q: want a city name, such as Brisbane or \"Brisbane, AU\"", query)
	}
	qualifierCC, _ := ParseCountry(qualifier)

	var places []*cityBlocks
	byName := map[[3]string]*cityBlocks{}
	// Many networks share one record, so each record is decoded and matched
	// once; a nil entry is a record that does not match.
	byRecord := map[uintptr]*cityBlocks{}
	for res := range db.Networks() {
		if err := res.Err(); err != nil {
			return nil, err
		}
		blocks, seen := byRecord[res.Offset()]
		if !seen {
			var rec cityPlaceRecord
			if err := res.Decode(&rec); err != nil {
				return nil, err
			}
			if matchCity(rec, city, qualifier, qualifierCC) {
				p := CityPlace{City: PreferredName(rec.City.Names), Country: rec.Country.ISOCode}
				if len(rec.Subdivisions) > 0 {
					p.Region = PreferredName(rec.Subdivisions[0].Names)
				}
				key := [3]string{p.City, p.Region, p.Country}
				if blocks = byName[key]; blocks == nil {
					blocks = &cityBlocks{place: p}
					byName[key] = blocks
					places = append(places, blocks)
				}
			}
			byRecord[res.Offset()] = blocks
		}
		if blocks != nil {
			blocks.add(res.Prefix())
		}
	}

	sort.SliceStable(places, func(i, j int) bool { return places[i].networks > places[j].networks })
	out := make([]CityPlace, len(places))
	for i, b := range places {
		b.flush4()
		b.flush6()
		out[i] = b.place
	}
	return out, nil
}

// matchCity reports whether rec is the city named city and, when qualifier is
// set, whether it lies in that region or country.
func matchCity(rec cityPlaceRecord, city, qualifier, qualifierCC string) bool {
	if !anyNameFold(rec.City.Names, city) {
		return false
	}
	if qualifier == "" || (qualifierCC != "" && rec.Country.ISOCode == qualifierCC) {
		return true
	}
	for _, s := range rec.Subdivisions {
		if anyNameFold(s.Names, qualifier) {
			return true
		}
	}
	return false
}

func anyNameFold(names map[string]string, s string) bool {
	for _, n := range names {
		if strings.EqualFold(n, s) {
			return true
		}
	}
	return false
}

// cityBlocks gathers a place's networks, which the database yields in address
// order, merging each run of adjacent networks into one range.
type cityBlocks struct {
	place        CityPlace
	networks     int
	open4        bool
	start4, end4 uint32
	open6        bool
	start6, end6 [16]byte
}

func (b *cityBlocks) add(p netip.Prefix) {
	b.networks++
	if p.Addr().Is4() {
		a := p.Masked().Addr().As4()
		start := binary.BigEndian.Uint32(a[:])
		end := start | uint32(uint64(1)<<(32-p.Bits())-1)
		if b.open4 && start == b.end4+1 {
			b.end4 = end
			return
		}
		b.flush4()
		b.open4, b.start4, b.end4 = true, start, end
		return
	}
	start := p.Masked().Addr().As16()
	end := start
	for bit := p.Bits(); bit < 128; bit++ {
		end[bit/8] |= byte(0x80) >> (bit % 8)
	}
	if next, _ := IncBytes16(b.end6); b.open6 && start == next {
		b.end6 = end
		return
	}
	b.flush6()
	b.open6, b.start6, b.end6 = true, start, end
}

func (b *cityBlocks) flush4() {
	if b.open4 {
		b.place.IPv4 = append(b.place.IPv4, IPv4RangeToCIDRs(b.start4, b.end4)...)
		b.open4 = false
	}
}

func (b *cityBlocks) flush6() {
	if b.open6 {
		b.place.IPv6 = append(b.place.IPv6, IPv6RangeToCIDRs(b.start6, b.end6)...)
		b.open6 = false
	}
}
