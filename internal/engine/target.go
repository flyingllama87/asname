package engine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flyingllama87/asname/internal/sources"
)

const (
	MaxResolveWorkers = 16
	DNSTimeout        = 5 * time.Second
	RDNSTimeout       = 5 * time.Second
)

// Target is one entry the user asked about.
type Target struct {
	Raw  string
	Host string
	IPs  []net.IP
	ASN  uint32
	Err  error
}

func ParseTargets(arg string) ([]Target, error) {
	if ip := net.ParseIP(strings.TrimSpace(arg)); ip != nil {
		return []Target{{Raw: arg, IPs: []net.IP{ip}}}, nil
	}

	info, err := os.Stat(arg)
	switch {
	case err == nil && info.Mode().IsRegular():
		return readTargetFile(arg)
	case err == nil && info.IsDir():
		return nil, fmt.Errorf("%s is a directory, expected an IP address, hostname, URL or a file of entries", arg)
	case looksLikePath(arg):
		return nil, fmt.Errorf("no such file: %s", arg)
	}

	return []Target{NewTarget(arg)}, nil
}

func looksLikePath(s string) bool {
	if strings.HasPrefix(s, "//") {
		return false
	}
	return strings.HasPrefix(s, "/") ||
		strings.HasPrefix(s, "./") ||
		strings.HasPrefix(s, "../") ||
		strings.HasPrefix(s, "~/")
}

func NewTarget(raw string) Target {
	trimmed := strings.TrimSpace(raw)
	if asn, ok := ParseASNTarget(trimmed); ok {
		return Target{Raw: raw, ASN: asn}
	}
	host := NormalizeTarget(raw)
	if host == "" {
		return Target{Raw: raw, Err: fmt.Errorf("not an IP address, hostname, URL or ASN")}
	}
	if ip := net.ParseIP(host); ip != nil {
		return Target{Raw: raw, IPs: []net.IP{ip}}
	}
	if asn, ok := ParseASNTarget(host); ok {
		return Target{Raw: raw, ASN: asn}
	}
	return Target{Raw: raw, Host: host}
}

// ParseASNTarget parses a string like "AS15169", "asn15169", "AS-15169", or pure digits "15169".
func ParseASNTarget(s string) (uint32, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	upper := strings.ToUpper(s)
	if strings.HasPrefix(upper, "ASN:") {
		upper = upper[4:]
	} else if strings.HasPrefix(upper, "ASN") {
		upper = strings.TrimPrefix(upper, "ASN")
	} else if strings.HasPrefix(upper, "AS") {
		upper = strings.TrimPrefix(upper, "AS")
	}
	upper = strings.TrimPrefix(upper, "-")
	if num, err := strconv.ParseUint(upper, 10, 32); err == nil && num > 0 {
		return uint32(num), true
	}
	return 0, false
}

func NormalizeTarget(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	} else {
		s = strings.TrimPrefix(s, "//")
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i >= 0 {
			s = s[1:i]
		}
	} else if i := strings.LastIndex(s, ":"); i >= 0 && strings.Count(s, ":") == 1 {
		s = s[:i]
	}
	return strings.TrimSuffix(strings.TrimSpace(s), ".")
}

func readTargetFile(path string) ([]Target, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var targets []Target
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		entry, ok := EntryFromLine(scanner.Text())
		if !ok {
			continue
		}
		targets = append(targets, NewTarget(entry))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %v", path, err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no entries found in %s", path)
	}
	return targets, nil
}

func EntryFromLine(line string) (string, bool) {
	if i := strings.Index(line, "#"); i >= 0 {
		line = line[:i]
	}
	field, _, ok := sources.SplitFirstField(strings.TrimSpace(line))
	return field, ok
}

func ResolveTargets(ctx context.Context, targets []Target) {
	sem := make(chan struct{}, MaxResolveWorkers)
	var wg sync.WaitGroup
	for i := range targets {
		if targets[i].Err != nil || targets[i].Host == "" || targets[i].ASN > 0 {
			continue
		}
		wg.Add(1)
		go func(t *Target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			lookupCtx, cancel := context.WithTimeout(ctx, DNSTimeout)
			defer cancel()

			t.IPs, t.Err = LookupHostIPs(lookupCtx, t.Host)
		}(&targets[i])
	}
	wg.Wait()
}

func LookupHostIPs(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := DedupeIPs(addrs)
	if len(ips) == 0 {
		return nil, fmt.Errorf("lookup %s: no addresses found", host)
	}
	return ips, nil
}

func LookupHostIPsWithRetry(ctx context.Context, host string) ([]net.IP, error) {
	var addrs []net.IPAddr
	var err error

	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
		}

		lookupCtx, cancel := context.WithTimeout(ctx, DNSTimeout)
		addrs, err = net.DefaultResolver.LookupIPAddr(lookupCtx, host)
		cancel()

		if err == nil {
			break
		}

		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			break
		}
	}

	if err != nil {
		return nil, err
	}

	ips := DedupeIPs(addrs)
	if len(ips) == 0 {
		return nil, fmt.Errorf("lookup %s: no addresses found", host)
	}
	return ips, nil
}

func DedupeIPs(addrs []net.IPAddr) []net.IP {
	seen := make(map[string]bool, len(addrs))
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		key := addr.IP.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		ips = append(ips, addr.IP)
	}
	return ips
}

func ResolveReverseDNS(ctx context.Context, results []LookupResult) {
	sem := make(chan struct{}, MaxResolveWorkers)
	var wg sync.WaitGroup
	for i := range results {
		if results[i].IsASN || results[i].IP == nil {
			continue
		}
		wg.Add(1)
		go func(res *LookupResult) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			rdnsCtx, cancel := context.WithTimeout(ctx, RDNSTimeout)
			defer cancel()

			res.RDNS = "N/A"
			if names, err := LookupReverseDNS(rdnsCtx, res.IP); err == nil && names != "" {
				res.RDNS = names
			}
		}(&results[i])
	}
	wg.Wait()
}

func LookupReverseDNS(ctx context.Context, ip net.IP) (string, error) {
	names, err := net.DefaultResolver.LookupAddr(ctx, ip.String())
	if err != nil {
		return "", err
	}
	if len(names) == 0 {
		return "", nil
	}
	return FormatReverseDNSNames(names), nil
}

func FormatReverseDNSNames(names []string) string {
	normalized := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSuffix(name, ".")
		if name != "" {
			normalized = append(normalized, name)
		}
	}
	sort.Strings(normalized)
	return strings.Join(normalized, ", ")
}
