package sources

import (
	"bufio"
	"context"
	"encoding/binary"
	"math"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

// arinDelegatedURL is ARIN's daily extended delegation statistics file. Unlike
// the bulk Whois download it is published openly and needs no API key.
const arinDelegatedURL = "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest"

// importARINDelegated names ARIN ranges without a bulk Whois key.
//
// The delegated file carries no organisation names, only an opaque identifier
// shared by every resource one organisation holds. Joining a netblock's
// identifier to the ASNs registered under the same identifier yields an AS
// number, and names maps that number to a name. Ranges held by an organisation
// that holds no ASN cannot be named this way and are skipped.
func importARINDelegated(ctx context.Context, b *netblockBuilder, cache string, names map[uint32]string) (int, error) {
	path, err := fetchCached(ctx, cache, arinDelegatedURL, "")
	if err != nil {
		return 0, err
	}

	asns := make(map[string][]uint32)
	if err := scanDelegated(path, func(f []string) {
		if f[2] != "asn" {
			return
		}
		num, err := strconv.ParseUint(f[3], 10, 32)
		if err != nil {
			return
		}
		asns[f[7]] = append(asns[f[7]], uint32(num))
	}); err != nil {
		return 0, err
	}

	orgs := make(map[string]string, len(asns))
	for id, held := range asns {
		if org := organisationName(held, names); org != "" {
			orgs[id] = org
		}
	}

	count := 0
	if err := scanDelegated(path, func(f []string) {
		org, ok := orgs[f[7]]
		if !ok {
			return
		}
		start, end, ok := delegatedRange(f[2], f[3], f[4])
		if !ok {
			return
		}
		// The delegated file has no netname, and the AS handle is not one:
		// it names the AS, and for an organisation holding several it is
		// often an acquired company's handle. So only the organisation is set.
		b.add(start, end, "", org)
		count++
	}); err != nil {
		return count, err
	}
	return count, nil
}

// organisationName picks the name for an organisation from the ASNs it holds.
// One organisation may hold dozens, and their names can disagree, so the name
// most of them carry wins and the lowest-numbered ASN breaks a tie.
func organisationName(held []uint32, names map[uint32]string) string {
	sort.Slice(held, func(i, j int) bool { return held[i] < held[j] })

	counts := make(map[string]int, len(held))
	best, bestCount := "", 0
	for _, asn := range held {
		org := organisationFromASName(names[asn])
		if org == "" {
			continue
		}
		counts[org]++
		if counts[org] > bestCount {
			best, bestCount = org, counts[org]
		}
	}
	return best
}

// organisationFromASName reduces a RIPE asn.txt name such as
// "LVLT-1 - Level 3 Parent, LLC, US" to the organisation it names. The leading
// AS handle is dropped because it names the AS rather than the organisation,
// and the trailing country code because the country database already covers it.
func organisationFromASName(name string) string {
	if i := strings.LastIndex(name, ", "); i >= 0 && isCountryCode(name[i+2:]) {
		name = name[:i]
	}
	handle, rest, ok := SplitFirstField(name)
	if !ok {
		return ""
	}
	if rest = strings.TrimSpace(strings.TrimPrefix(rest, "- ")); rest == "" {
		return handle
	}
	return rest
}

func isCountryCode(s string) bool {
	return len(s) == 2 &&
		s[0] >= 'A' && s[0] <= 'Z' &&
		s[1] >= 'A' && s[1] <= 'Z'
}

// delegatedRange converts one record's address fields into the first and last
// address it covers. IPv4 records carry a host count, which need not be a power
// of two; IPv6 records carry a prefix length.
func delegatedRange(typ, start, value string) (net.IP, net.IP, bool) {
	switch typ {
	case "ipv4":
		ip4 := net.ParseIP(start).To4()
		count, err := strconv.ParseUint(value, 10, 64)
		if ip4 == nil || err != nil || count == 0 {
			return nil, nil, false
		}
		last := uint64(binary.BigEndian.Uint32(ip4)) + count - 1
		if last > math.MaxUint32 {
			return nil, nil, false
		}
		end := make(net.IP, 4)
		binary.BigEndian.PutUint32(end, uint32(last))
		return ip4, end, true
	case "ipv6":
		return ParseNetRange(start + "/" + value)
	}
	return nil, nil, false
}

// scanDelegated calls emit for every allocated or assigned record in an
// extended RIR delegation statistics file, with the record split on "|".
// Summary, header and reserved records are skipped, so emit always receives
// the full eight fields of a resource record.
func scanDelegated(path string, emit func(fields []string)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) < 8 {
			continue
		}
		if status := fields[6]; status != "allocated" && status != "assigned" {
			continue
		}
		if fields[7] == "" {
			continue
		}
		emit(fields)
	}
	return sc.Err()
}

// importARINDelegatedInto adds the delegated-statistics ARIN layer to b,
// reporting progress and failures the same way a whois dump source does.
func importARINDelegatedInto(ctx context.Context, b *netblockBuilder, cfg Config, cache string) int {
	names, err := LoadNames(cfg.NamesPath)
	if err != nil {
		logf(ctx, "asname: warning: ARIN: delegated statistics need the AS name database: %v\n", err)
		return 0
	}
	n, err := importARINDelegated(ctx, b, cache, names)
	if err != nil {
		logf(ctx, "asname: warning: ARIN: %v\n", err)
		return 0
	}
	logf(ctx, "asname: ARIN (delegated statistics): %d ranges\n", n)
	return n
}
