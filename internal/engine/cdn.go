package engine

import (
	"context"
	"net"
	"strings"
)

// A hostname behind a CDN resolves to the CDN's edge server nearest whoever
// asked, often a cache inside the asker's own ISP, so a lookup of it
// describes that server, not the site's owner. ServedBy says so when the
// name's CNAME chain or its DNS host gives the CDN away.

// ServedBy is the CDN a hostname is served through.
type ServedBy struct {
	CDN string // "Akamai"
	// Via is how it was found: "cname" (the name is an alias of the CDN's,
	// which is certain) or "dns" (the domain's DNS is hosted by the CDN,
	// which usually answers with its own edge servers).
	Via string
	// Name is the CNAME target or the name server that matched.
	Name string
}

// cdnCNAMEs maps CNAME suffixes to the CDN behind them.
var cdnCNAMEs = []struct{ suffix, cdn string }{
	{"akamaiedge.net", "Akamai"},
	{"akamai.net", "Akamai"},
	{"edgekey.net", "Akamai"},
	{"edgesuite.net", "Akamai"},
	{"akamaized.net", "Akamai"},
	{"akamaihd.net", "Akamai"},
	{"cloudfront.net", "Amazon CloudFront"},
	{"fastly.net", "Fastly"},
	{"fastlylb.net", "Fastly"},
	{"cdn.cloudflare.net", "Cloudflare"},
	{"azureedge.net", "Azure CDN"},
	{"azurefd.net", "Azure Front Door"},
	{"edgecastcdn.net", "Edgio"},
	{"systemcdn.net", "Edgio"},
	{"llnwd.net", "Edgio"},
	{"llnw.net", "Edgio"},
	{"cdn77.org", "CDN77"},
	{"b-cdn.net", "Bunny CDN"},
	{"incapdns.net", "Imperva"},
	{"stackpathdns.com", "StackPath"},
	{"sucuri.net", "Sucuri"},
	{"googlehosted.com", "Google"},
}

// cdnNameServers maps name-server suffixes to CDNs whose DNS answers with
// their own edge servers.
var cdnNameServers = []struct{ suffix, cdn string }{
	{"akam.net", "Akamai"},
	{"akamaiedge.net", "Akamai"},
}

func matchSuffix(name string, table []struct{ suffix, cdn string }) string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, e := range table {
		if name == e.suffix || strings.HasSuffix(name, "."+e.suffix) {
			return e.cdn
		}
	}
	return ""
}

// cdnFromCNAME is the CDN behind a canonical name, or "".
func cdnFromCNAME(cname string) string { return matchSuffix(cname, cdnCNAMEs) }

// cdnFromNS is the CDN hosting a domain's DNS, or "".
func cdnFromNS(ns string) string { return matchSuffix(ns, cdnNameServers) }

// DetectCDN asks DNS whether host is served through a CDN: by its CNAME
// chain first, then by who hosts its DNS (host's own name servers, or its
// nearest parent's).
func DetectCDN(ctx context.Context, host string) *ServedBy {
	host = strings.TrimSuffix(host, ".")
	if cname, err := net.DefaultResolver.LookupCNAME(ctx, host); err == nil {
		if cdn := cdnFromCNAME(cname); cdn != "" {
			return &ServedBy{CDN: cdn, Via: "cname", Name: strings.TrimSuffix(cname, ".")}
		}
	}
	labels := strings.Split(host, ".")
	for i := 0; i < len(labels)-1 && i < 3; i++ {
		zone := strings.Join(labels[i:], ".")
		nss, err := net.DefaultResolver.LookupNS(ctx, zone)
		if err != nil || len(nss) == 0 {
			continue
		}
		for _, ns := range nss {
			if cdn := cdnFromNS(ns.Host); cdn != "" {
				return &ServedBy{CDN: cdn, Via: "dns", Name: strings.TrimSuffix(ns.Host, ".")}
			}
		}
		return nil // the nearest zone with name servers decides
	}
	return nil
}
