package engine

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

// On an IPv6-only network (most mobile carriers), the resolver does DNS64:
// for a name with no AAAA record it makes one up, putting the name's IPv4
// address inside the carrier's NAT64 prefix, so that traffic goes through
// the carrier's translator. Such an address belongs to the carrier, not the
// site: nsa.gov looked up over Vodafone Australia's mobile network comes
// back as 2405:6e00:64::172e:2f6c, which is 23.46.47.108 inside Vodafone's
// prefix 2405:6e00:64::/96. Lookups take the IPv4 address back out.

// NAT64 says a looked-up address was an IPv4 address inside a NAT64 prefix.
type NAT64 struct {
	Address string // the IPv6 address, e.g. 2405:6e00:64::172e:2f6c
	Prefix  string // the NAT64 prefix, e.g. 2405:6e00:64::/96
	// DNS64 is set when the address came from resolving a hostname: the
	// resolver made it up because the name has no IPv6 address.
	DNS64 bool
}

// wellKnownNAT64 is RFC 6052's prefix, which means NAT64 on any network.
var wellKnownNAT64 = netip.MustParsePrefix("64:ff9b::/96")

// nat64Lengths are the prefix lengths RFC 6052 allows.
var nat64Lengths = []int{96, 64, 56, 48, 40, 32}

// embeddedIPv4 takes the IPv4 address out of a, an address in a NAT64 prefix
// of length bits. Bits 64-71 are reserved and skipped (RFC 6052 section 2.2).
func embeddedIPv4(a netip.Addr, bits int) (netip.Addr, bool) {
	b := a.As16()
	var pos []int
	switch bits {
	case 32:
		pos = []int{4, 5, 6, 7}
	case 40:
		pos = []int{5, 6, 7, 9}
	case 48:
		pos = []int{6, 7, 9, 10}
	case 56:
		pos = []int{7, 9, 10, 11}
	case 64:
		pos = []int{9, 10, 11, 12}
	case 96:
		pos = []int{12, 13, 14, 15}
	default:
		return netip.Addr{}, false
	}
	if bits < 96 && b[8] != 0 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{b[pos[0]], b[pos[1]], b[pos[2]], b[pos[3]]}), true
}

// ipv4onlyAddrs are ipv4only.arpa's addresses (RFC 7050), which a DNS64
// resolver returns inside its NAT64 prefix.
var ipv4onlyAddrs = []netip.Addr{netip.MustParseAddr("192.0.0.170"), netip.MustParseAddr("192.0.0.171")}

// nat64PrefixesFrom finds the NAT64 prefixes in the AAAA answers for
// ipv4only.arpa.
func nat64PrefixesFrom(answers []netip.Addr) []netip.Prefix {
	var out []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for _, a := range answers {
		if !a.Is6() || a.Is4In6() {
			continue
		}
		for _, bits := range nat64Lengths {
			v4, ok := embeddedIPv4(a, bits)
			if !ok || (v4 != ipv4onlyAddrs[0] && v4 != ipv4onlyAddrs[1]) {
				continue
			}
			p, err := a.Prefix(bits)
			if err == nil && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
			break
		}
	}
	return out
}

var localNAT64 struct {
	sync.Mutex
	prefixes []netip.Prefix
	expires  time.Time
}

// localNAT64TTL is how long the local NAT64 prefixes are trusted: the
// network can change under a long-running server.
const localNAT64TTL = 10 * time.Minute

// LocalNAT64Prefixes are the NAT64 prefixes of the network this machine's
// resolver is on, found by asking it for ipv4only.arpa's IPv6 address
// (RFC 7050). None when the network does no DNS64.
func LocalNAT64Prefixes(ctx context.Context) []netip.Prefix {
	localNAT64.Lock()
	defer localNAT64.Unlock()
	if time.Now().Before(localNAT64.expires) {
		return localNAT64.prefixes
	}
	qctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addrs, _ := net.DefaultResolver.LookupNetIP(qctx, "ip6", "ipv4only.arpa")
	localNAT64.prefixes = nat64PrefixesFrom(addrs)
	localNAT64.expires = time.Now().Add(localNAT64TTL)
	return localNAT64.prefixes
}

// UnmapNAT64 replaces each IPv6 address of t that sits in a NAT64 prefix
// (the well-known one, or one of local) with the IPv4 address it carries,
// dropping duplicates. The returned map, keyed by IPv4 address, records
// what was replaced.
func (t Target) UnmapNAT64(local []netip.Prefix) (Target, map[string]*NAT64) {
	var found map[string]*NAT64
	ips := make([]net.IP, 0, len(t.IPs))
	seen := map[string]bool{}
	for _, ip := range t.IPs {
		a, ok := netip.AddrFromSlice(ip)
		if ok && a.Is6() && !a.Is4In6() {
			for _, p := range append([]netip.Prefix{wellKnownNAT64}, local...) {
				if !p.Contains(a) {
					continue
				}
				if v4, ok := embeddedIPv4(a, p.Bits()); ok {
					if found == nil {
						found = map[string]*NAT64{}
					}
					if found[v4.String()] == nil {
						found[v4.String()] = &NAT64{Address: a.String(), Prefix: p.String(), DNS64: t.Host != ""}
					}
					ip = net.IP(v4.AsSlice())
				}
				break
			}
		}
		if k := ip.String(); !seen[k] {
			seen[k] = true
			ips = append(ips, ip)
		}
	}
	t.IPs = ips
	return t, found
}

// hasPlainIPv6 says whether t has an IPv6 address that only a local
// NAT64 prefix could explain, so the local prefixes are worth asking for.
func (t Target) hasPlainIPv6() bool {
	for _, ip := range t.IPs {
		if ip.To4() == nil {
			if a, ok := netip.AddrFromSlice(ip); ok && !wellKnownNAT64.Contains(a) {
				return true
			}
		}
	}
	return false
}
