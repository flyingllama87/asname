package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"math/bits"
	"net"
	"os"
	"strconv"
	"strings"

	"asname/pkg/database"
)

// rirDelegatedURLs are the five Regional Internet Registries' delegation
// statistics files (RIR statistics exchange format). Together they map every
// allocated/assigned IP range to the country it was registered to.
var rirDelegatedURLs = []string{
	"https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
	"https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest",
	"https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest",
	"https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest",
	"https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest",
}

// countryBuilder is the subset of database.NewBuilder()'s (unexported) return
// type that we need, expressed as an interface so we can name it here.
type countryBuilder interface {
	InsertMapping(*net.IPNet, uint32) error
	SetFillFactor(float32)
	Build() (database.Database, error)
}

// updateCountryDB downloads every RIR delegation file, builds an IP->country
// LC-trie and atomically replaces cfg.countryPath.
func updateCountryDB(cfg config) error {
	fmt.Fprintln(os.Stderr, "asname: building IP->country database from RIR delegation stats")
	var b countryBuilder = database.NewBuilder()

	total := 0
	for _, url := range rirDelegatedURLs {
		n, err := importDelegated(b, url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "asname: warning: %s: %v\n", url, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "asname: %s: %d ranges\n", url, n)
		total += n
	}
	if total == 0 {
		return fmt.Errorf("no country ranges imported")
	}

	b.SetFillFactor(optimizationFillFactor)
	db, err := b.Build()
	if err != nil {
		return fmt.Errorf("building database: %v", err)
	}
	data, err := db.MarshalBinary()
	if err != nil {
		return err
	}
	if err := writeFileAtomic(cfg.countryPath, data); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "asname: wrote %s (%d ranges, %d bytes)\n", cfg.countryPath, total, len(data))
	return nil
}

// importDelegated streams one RIR file and inserts its IPv4/IPv6 country ranges
// into the builder. Lines look like:
//
//	ripencc|PS|ipv4|1.178.112.0|4096|20071126|allocated
//	apnic|AU|ipv6|2001:200::|35|19990813|allocated
//
// For ipv4 the 5th field is an address count; for ipv6 it is a prefix length.
func importDelegated(b countryBuilder, url string) (int, error) {
	resp, err := httpGet(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	count := 0
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Split(line, "|")
		if len(f) < 7 {
			continue
		}
		cc, typ, status := f[1], f[2], f[6]
		if status != "allocated" && status != "assigned" {
			continue
		}
		if !validCC(cc) {
			continue
		}
		ccVal := encodeCC(cc)

		switch typ {
		case "ipv4":
			cnt, err := strconv.ParseUint(f[4], 10, 64)
			if err != nil || cnt == 0 {
				continue
			}
			ip4 := net.ParseIP(f[3]).To4()
			if ip4 == nil {
				continue
			}
			start := binary.BigEndian.Uint32(ip4)
			for _, nw := range rangeToCIDRs(start, cnt) {
				if b.InsertMapping(nw, ccVal) == nil {
					count++
				}
			}
		case "ipv6":
			if _, err := strconv.Atoi(f[4]); err != nil {
				continue
			}
			_, nw, err := net.ParseCIDR(f[3] + "/" + f[4])
			if err != nil {
				continue
			}
			if b.InsertMapping(nw, ccVal) == nil {
				count++
			}
		}
	}
	return count, sc.Err()
}

// validCC reports whether cc is a usable 2-letter country code (rejecting the
// "ZZ" placeholder used for unknown/unassigned ranges).
func validCC(cc string) bool {
	if len(cc) != 2 {
		return false
	}
	if cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
		return false
	}
	return cc != "ZZ"
}

// rangeToCIDRs splits the IPv4 range [start, start+count) into the minimal set
// of aligned CIDR blocks. RIR counts are usually powers of two, but this copes
// with any count.
func rangeToCIDRs(start uint32, count uint64) []*net.IPNet {
	var nets []*net.IPNet
	s := uint64(start)
	end := s + count // exclusive
	for s < end {
		// Largest block aligned to the current start.
		size := uint(32)
		if s != 0 {
			if tz := uint(bits.TrailingZeros64(s)); tz < size {
				size = tz
			}
		}
		// Largest block that still fits in the remaining range.
		if fit := uint(bits.Len64(end-s) - 1); fit < size {
			size = fit
		}
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, uint32(s))
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(32-int(size), 32)})
		s += uint64(1) << size
	}
	return nets
}
