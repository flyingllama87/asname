package sources

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"math/bits"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/flyingllama87/asname/pkg/database"
)

// rirDelegatedURLs are the five Regional Internet Registries' delegation
// statistics files (RIR statistics exchange format).
var rirDelegatedURLs = []string{
	arinDelegatedURL,
	"https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest",
	"https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest",
	"https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest",
	"https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest",
}

// trieBuilder is the subset of database.NewBuilder()'s return type needed.
type trieBuilder interface {
	InsertMapping(*net.IPNet, uint32) error
	SetFillFactor(float32)
	Build() (database.Database, error)
}

// UpdateCountryDB downloads every RIR delegation file, builds an IP->country
// LC-trie and atomically replaces cfg.CountryPath.
func UpdateCountryDB(cfg Config) error {
	fmt.Fprintln(os.Stderr, "asname: building IP->country database from RIR delegation stats")
	var b trieBuilder = database.NewBuilder()

	cache := cfg.CacheDir()
	total := 0
	for _, url := range rirDelegatedURLs {
		n, err := importDelegated(b, url, cache)
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

	b.SetFillFactor(OptimizationFillFactor)
	db, err := b.Build()
	if err != nil {
		return fmt.Errorf("building database: %v", err)
	}
	data, err := db.MarshalBinary()
	if err != nil {
		return err
	}
	if err := WriteFileAtomic(cfg.CountryPath, data); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "asname: wrote %s (%d ranges, %d bytes)\n", cfg.CountryPath, total, len(data))
	return nil
}

// importDelegated streams one RIR file and inserts its IPv4/IPv6 country ranges
// into the builder.
func importDelegated(b trieBuilder, url, cache string) (int, error) {
	f, err := openCached(cache, url, "")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
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
		ccVal := EncodeCC(cc)

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

// validCC reports whether cc is a usable 2-letter country code.
func validCC(cc string) bool {
	if len(cc) != 2 {
		return false
	}
	if cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
		return false
	}
	return cc != "ZZ"
}

// rangeToCIDRs splits the IPv4 range [start, start+count) into the minimal set of aligned CIDR blocks.
func rangeToCIDRs(start uint32, count uint64) []*net.IPNet {
	var nets []*net.IPNet
	s := uint64(start)
	end := s + count
	for s < end {
		size := uint(32)
		if s != 0 {
			if tz := uint(bits.TrailingZeros64(s)); tz < size {
				size = tz
			}
		}
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
