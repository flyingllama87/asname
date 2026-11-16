package sources

import (
	"embed"
	"encoding/csv"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// IANA's special-purpose address registries (RFC 6890) name the blocks set
// aside for a purpose other than ordinary addressing: private use, carrier
// NAT, documentation, loopback, translation and so on. They change a few
// times a decade, so asname carries a copy (iana/*.csv, from
// https://www.iana.org/assignments/iana-ipv4-special-registry/ and
// iana-ipv6-special-registry/) rather than downloading them.

//go:embed iana/*.csv
var ianaFiles embed.FS

// Special is a special-purpose block an address is in.
type Special struct {
	Prefix string // "100.64.0.0/10"
	Name   string // "Shared Address Space"
	RFC    string // "RFC 6598"
	// Global is IANA's "Globally Reachable": "true", "false" or "" when
	// the registry says it depends (6to4, Teredo).
	Global string
}

var special struct {
	once  sync.Once
	table []specialEntry // most specific first
}

type specialEntry struct {
	prefix netip.Prefix
	Special
}

// specialNames expands names the registry abbreviates or words for a
// specialist, and adds what a reader needs to place them.
var specialNames = map[string]string{
	"IPv4-IPv6 Translat.":  "IPv4/IPv6 translation (NAT64)",
	"Shared Address Space": "Shared Address Space (carrier-grade NAT)",
	"Private-Use":          "Private use (RFC 1918)",
	"Unique-Local":         "Unique local (private IPv6)",
}

var footnote = regexp.MustCompile(`\s*\[\d+\]`)

func loadSpecial() {
	for _, name := range []string{"iana/ipv4-special-registry.csv", "iana/ipv6-special-registry.csv"} {
		data, err := ianaFiles.ReadFile(name)
		if err != nil {
			continue
		}
		rows, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
		if err != nil || len(rows) < 2 {
			continue
		}
		for _, row := range rows[1:] {
			if len(row) < 9 || row[4] != "N/A" { // a termination date: no longer special
				continue
			}
			n := strings.Trim(row[1], `"`)
			if full, ok := specialNames[n]; ok {
				n = full
			}
			rfc := strings.Trim(strings.SplitN(row[2], "]", 2)[0], "[")
			rfc, _, _ = strings.Cut(rfc, ",")
			global := strings.ToLower(footnote.ReplaceAllString(row[8], ""))
			if global != "true" && global != "false" {
				global = ""
			}
			for _, block := range strings.Split(footnote.ReplaceAllString(row[0], ""), ",") {
				p, err := netip.ParsePrefix(strings.TrimSpace(block))
				if err != nil {
					continue
				}
				special.table = append(special.table, specialEntry{p.Masked(), Special{Prefix: p.Masked().String(), Name: n, RFC: rfc, Global: global}})
			}
		}
	}
	// Multicast is in IANA's address-space registries, not the special-purpose
	// ones, but an analyst meets it in the same way.
	for _, m := range []specialEntry{
		{netip.MustParsePrefix("224.0.0.0/4"), Special{Prefix: "224.0.0.0/4", Name: "Multicast", RFC: "RFC 5771", Global: "false"}},
		{netip.MustParsePrefix("ff00::/8"), Special{Prefix: "ff00::/8", Name: "Multicast", RFC: "RFC 4291", Global: "false"}},
	} {
		special.table = append(special.table, m)
	}
	sort.SliceStable(special.table, func(i, j int) bool { return special.table[i].prefix.Bits() > special.table[j].prefix.Bits() })
}

// SpecialPurpose returns the most specific special-purpose block holding
// ip, if any.
func SpecialPurpose(ip net.IP) (Special, bool) {
	special.once.Do(loadSpecial)
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return Special{}, false
	}
	a = a.Unmap()
	for _, e := range special.table {
		if e.prefix.Contains(a) {
			return e.Special, true
		}
	}
	return Special{}, false
}
