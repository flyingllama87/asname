package sources

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	gluetunServerLists = "https://api.github.com/repos/qdm12/gluetun-servers/contents/pkg/servers"

	nordVPNServers    = "https://api.nordvpn.com/v2/servers?limit=0"
	mullvadRelays     = "https://api.mullvad.net/www/relays/all/"
	surfsharkClusters = "https://api.surfshark.com/v4/server/clusters/"
	piaServers        = "https://serverlist.piaservers.net/vpninfo/servers/v7"
	ivpnServers       = "https://api.ivpn.net/v4/servers/stats"
	airVPNStatus      = "https://airvpn.org/api/status/"
	windscribeServers = "https://assets.windscribe.com/serverlist/mob-v2/1/"
	privadoServers    = "https://privadovpn.com/apps/servers_export.json"

	// resolveWorkers bounds the concurrent DNS lookups for providers that
	// list hostnames, and resolveTimeout each one.
	resolveWorkers = 16
	resolveTimeout = 5 * time.Second
)

// vpnAPI is a provider that publishes its own server list. When it can be
// read, it replaces gluetun's copy of the same provider's list, which is only
// as fresh as gluetun's last update.
type vpnAPI struct {
	provider string // gluetun's name for the provider
	source   string // shown under Data Sources
	url      string
	// read returns the addresses the list names, and the hostnames it names
	// instead of addresses.
	read func(b *categoryBuilder, url string) (addrs, hosts []string, err error)
}

var vpnAPIs = []vpnAPI{
	{"nordvpn", "NordVPN server API", nordVPNServers, readNordVPN},
	{"mullvad", "Mullvad relay API", mullvadRelays, readMullvad},
	{"surfshark", "Surfshark cluster API", surfsharkClusters, readSurfshark},
	{"private internet access", "PIA server list", piaServers, readPIA},
	{"ivpn", "IVPN server API", ivpnServers, readIVPN},
	{"airvpn", "AirVPN status API", airVPNStatus, readAirVPN},
	{"windscribe", "Windscribe server list", windscribeServers, readWindscribe},
	{"privado", "PrivadoVPN server export", privadoServers, readPrivado},
}

func vpnTag(provider string) string {
	return "vpn:" + strings.ReplaceAll(strings.ToLower(strings.TrimSpace(provider)), " ", "-")
}

// ImportVPNServers reads each provider's own server list, then gluetun's
// lists from the GitHub directory listing at gluetunURL for every provider
// whose own list could not be read.
func (b *categoryBuilder) ImportVPNServers(apis []vpnAPI, gluetunURL string) (int, error) {
	now := time.Now().UTC()
	total := 0
	direct := make(map[string]bool)
	for _, api := range apis {
		addrs, err := b.readVPNAPI(api)
		if err != nil {
			logf(b.ctx, "asname: warning: %s: %v; using gluetun's copy\n", api.source, err)
			noteFailed(b.ctx, api.source)
			continue
		}
		total += b.addVPNServers(api.provider, VPNList{Source: api.source, Date: now}, addrs)
		direct[api.provider] = true
	}

	n, err := b.importGluetun(gluetunURL, direct)
	if err != nil {
		if total == 0 {
			return 0, err
		}
		logf(b.ctx, "asname: warning: gluetun server lists: %v\n", err)
		noteFailed(b.ctx, "gluetun server lists")
	}
	total += n
	if total == 0 {
		return 0, fmt.Errorf("no VPN servers read")
	}
	return total, nil
}

func (b *categoryBuilder) readVPNAPI(api vpnAPI) ([]string, error) {
	addrs, hosts, err := api.read(b, api.url)
	if err != nil {
		return nil, err
	}
	if len(hosts) > 0 {
		resolved, failed := b.resolveHosts(hosts)
		// A partial list would replace gluetun's whole one, so most of the
		// names must resolve.
		if failed > len(hosts)/2 {
			return nil, fmt.Errorf("resolved only %d of %d hostnames", len(hosts)-failed, len(hosts))
		}
		addrs = append(addrs, resolved...)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no servers listed")
	}
	return addrs, nil
}

// resolveHosts looks up every hostname, returning the addresses found and how
// many names failed.
func (b *categoryBuilder) resolveHosts(hosts []string) (addrs []string, failed int) {
	found := make([][]string, len(hosts))
	errs := make([]error, len(hosts))
	next := make(chan int)
	var wg sync.WaitGroup
	for range resolveWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				ctx, cancel := context.WithTimeout(b.ctx, resolveTimeout)
				found[i], errs[i] = b.lookupHost(ctx, hosts[i])
				cancel()
			}
		}()
	}
	for i := range hosts {
		next <- i
	}
	close(next)
	wg.Wait()

	for i := range hosts {
		if errs[i] != nil || len(found[i]) == 0 {
			failed++
			continue
		}
		addrs = append(addrs, found[i]...)
	}
	return addrs, failed
}

// addVPNServers tags each address with the provider and records where the
// list came from, returning how many distinct addresses it named.
func (b *categoryBuilder) addVPNServers(provider string, list VPNList, addrs []string) int {
	tag := vpnTag(provider)
	seen := make(map[string]bool)
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if net.ParseIP(addr) == nil || seen[addr] {
			continue
		}
		seen[addr] = true
		b.addPrefix(addr, tag)
	}
	if len(seen) > 0 {
		b.vpnLists[tag] = list
	}
	return len(seen)
}

// importGluetun reads gluetun's per-provider server lists, skipping the
// providers in skip.
func (b *categoryBuilder) importGluetun(listURL string, skip map[string]bool) (int, error) {
	var listing []struct {
		Name        string `json:"name"`
		Type        string `json:"type"`
		DownloadURL string `json:"download_url"`
	}
	if err := fetchJSON(b.ctx, listURL, "", &listing); err != nil {
		return 0, err
	}
	sort.Slice(listing, func(i, j int) bool { return listing[i].Name < listing[j].Name })

	total := 0
	for _, file := range listing {
		provider, ok := strings.CutSuffix(file.Name, ".json")
		if !ok || file.Type != "file" || provider == "manifest" || file.DownloadURL == "" || skip[provider] {
			continue
		}
		n, err := b.ImportGluetunProviderFrom(file.DownloadURL, provider)
		if err != nil {
			logf(b.ctx, "asname: warning: gluetun server list for %s: %v\n", provider, err)
			noteFailed(b.ctx, "gluetun "+provider)
			continue
		}
		total += n
	}
	return total, nil
}

// ImportGluetunProviderFrom reads one gluetun server list for provider.
func (b *categoryBuilder) ImportGluetunProviderFrom(url, provider string) (int, error) {
	var doc struct {
		Timestamp int64 `json:"timestamp"`
		Servers   []struct {
			IPs []string `json:"ips"`
		} `json:"servers"`
	}
	if err := fetchJSON(b.ctx, url, "", &doc); err != nil {
		return 0, err
	}
	list := VPNList{Source: "gluetun server list for " + provider}
	if doc.Timestamp > 0 {
		list.Date = time.Unix(doc.Timestamp, 0).UTC()
	}
	var addrs []string
	for _, server := range doc.Servers {
		addrs = append(addrs, server.IPs...)
	}
	return b.addVPNServers(provider, list, addrs), nil
}

// readNordVPN takes every address of every server: the station address and
// the entry and exit addresses where NordVPN lists them.
func readNordVPN(b *categoryBuilder, url string) (addrs, hosts []string, err error) {
	var doc struct {
		Servers []struct {
			Station     string `json:"station"`
			StationIPv6 string `json:"station_ipv6"`
			IPs         []struct {
				IP struct {
					IP string `json:"ip"`
				} `json:"ip"`
			} `json:"ips"`
		} `json:"servers"`
	}
	if err := fetchJSON(b.ctx, url, "", &doc); err != nil {
		return nil, nil, err
	}
	for _, s := range doc.Servers {
		addrs = append(addrs, s.Station, s.StationIPv6)
		for _, ip := range s.IPs {
			addrs = append(addrs, ip.IP.IP)
		}
	}
	return addrs, nil, nil
}

func readMullvad(b *categoryBuilder, url string) (addrs, hosts []string, err error) {
	var relays []struct {
		IPv4 string `json:"ipv4_addr_in"`
		IPv6 string `json:"ipv6_addr_in"`
	}
	if err := fetchJSON(b.ctx, url, "", &relays); err != nil {
		return nil, nil, err
	}
	for _, r := range relays {
		addrs = append(addrs, r.IPv4, r.IPv6)
	}
	return addrs, nil, nil
}

// readSurfshark lists hostnames only: Surfshark's API encrypts the address.
func readSurfshark(b *categoryBuilder, url string) (addrs, hosts []string, err error) {
	for _, cluster := range []string{"generic", "double", "static", "obfuscated"} {
		var servers []struct {
			Host string `json:"connectionName"`
		}
		if err := fetchJSON(b.ctx, url+cluster, "", &servers); err != nil {
			return nil, nil, err
		}
		for _, s := range servers {
			if s.Host != "" {
				hosts = append(hosts, s.Host)
			}
		}
	}
	return nil, dedupe(hosts), nil
}

// readPIA reads PIA's list, which is JSON followed by a signature; the
// decoder stops after the JSON.
func readPIA(b *categoryBuilder, url string) (addrs, hosts []string, err error) {
	var doc struct {
		Regions []struct {
			Servers map[string][]struct {
				IP string `json:"ip"`
			} `json:"servers"`
		} `json:"regions"`
	}
	if err := fetchJSON(b.ctx, url, "", &doc); err != nil {
		return nil, nil, err
	}
	for _, region := range doc.Regions {
		for _, servers := range region.Servers {
			for _, s := range servers {
				addrs = append(addrs, s.IP)
			}
		}
	}
	return addrs, nil, nil
}

// readIVPN lists hostnames only.
func readIVPN(b *categoryBuilder, url string) (addrs, hosts []string, err error) {
	var doc struct {
		Servers []struct {
			Hostnames struct {
				OpenVPN   string `json:"openvpn"`
				WireGuard string `json:"wireguard"`
			} `json:"hostnames"`
		} `json:"servers"`
	}
	if err := fetchJSON(b.ctx, url, "", &doc); err != nil {
		return nil, nil, err
	}
	for _, s := range doc.Servers {
		for _, host := range []string{s.Hostnames.OpenVPN, s.Hostnames.WireGuard} {
			if host != "" {
				hosts = append(hosts, host)
			}
		}
	}
	return nil, dedupe(hosts), nil
}

// readAirVPN takes every ip_v4_* and ip_v6_* field, which covers the entry
// addresses and any exit addresses the API lists.
func readAirVPN(b *categoryBuilder, url string) (addrs, hosts []string, err error) {
	var doc struct {
		Servers []map[string]any `json:"servers"`
	}
	if err := fetchJSON(b.ctx, url, "", &doc); err != nil {
		return nil, nil, err
	}
	for _, s := range doc.Servers {
		for key, value := range s {
			ip, ok := value.(string)
			if ok && (strings.HasPrefix(key, "ip_v4_") || strings.HasPrefix(key, "ip_v6_")) {
				addrs = append(addrs, ip)
			}
		}
	}
	return addrs, nil, nil
}

// readWindscribe appends a cache breaker to the URL, as Windscribe's own
// clients do.
func readWindscribe(b *categoryBuilder, url string) (addrs, hosts []string, err error) {
	var doc struct {
		Data []struct {
			Groups []struct {
				Nodes []struct {
					IP  string `json:"ip"`
					IP2 string `json:"ip2"`
					IP3 string `json:"ip3"`
				} `json:"nodes"`
			} `json:"groups"`
		} `json:"data"`
	}
	// The trailing number defeats caches upstream. The start of the current
	// UTC day keeps it stable within one update window, so asname's own
	// cache can still serve a retry.
	day := time.Now().UTC().Truncate(24 * time.Hour).Unix()
	if err := fetchJSON(b.ctx, url+strconv.FormatInt(day, 10), "", &doc); err != nil {
		return nil, nil, err
	}
	for _, region := range doc.Data {
		for _, group := range region.Groups {
			for _, n := range group.Nodes {
				addrs = append(addrs, n.IP, n.IP2, n.IP3)
			}
		}
	}
	return addrs, nil, nil
}

func readPrivado(b *categoryBuilder, url string) (addrs, hosts []string, err error) {
	var doc struct {
		Servers []struct {
			IP string `json:"ip"`
		} `json:"servers"`
	}
	if err := fetchJSON(b.ctx, url, "", &doc); err != nil {
		return nil, nil, err
	}
	for _, s := range doc.Servers {
		addrs = append(addrs, s.IP)
	}
	return addrs, nil, nil
}

func dedupe(items []string) []string {
	sort.Strings(items)
	return slices.Compact(items)
}
