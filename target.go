package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

// maxResolveWorkers bounds the concurrent DNS queries issued for a run. Files
// of hostnames are the common case for batch lookups and DNS latency, not the
// trie lookups, dominates their runtime.
const maxResolveWorkers = 16

// target is one entry the user asked about: a literal IP address, or a hostname
// that may expand into several addresses. URLs are reduced to whichever of the
// two they contain.
type target struct {
	raw  string   // the entry as written by the user or the input file
	host string   // hostname, empty when the entry was a literal IP
	ips  []net.IP // addresses to look up
	err  error    // why this entry produced no addresses
}

// parseTargets turns the single command-line argument into the entries to look
// up. The argument is interpreted, in order of precedence, as a literal IP
// address, a readable file holding one entry per line, or a hostname/URL.
func parseTargets(arg string) ([]target, error) {
	if ip := net.ParseIP(strings.TrimSpace(arg)); ip != nil {
		return []target{{raw: arg, ips: []net.IP{ip}}}, nil
	}

	info, err := os.Stat(arg)
	switch {
	case err == nil && info.Mode().IsRegular():
		return readTargetFile(arg)
	case err == nil && info.IsDir():
		return nil, fmt.Errorf("%s is a directory, expected an IP address, hostname, URL or a file of entries", arg)
	case looksLikePath(arg):
		// Unambiguously a path, so failing to open it beats handing it to DNS.
		return nil, fmt.Errorf("no such file: %s", arg)
	}

	return []target{newTarget(arg)}, nil
}

// looksLikePath reports whether an argument can only have been meant as a file,
// as opposed to a hostname or a scheme-less URL such as "example.com/status".
func looksLikePath(s string) bool {
	if strings.HasPrefix(s, "//") {
		return false // scheme-relative URL
	}
	return strings.HasPrefix(s, "/") ||
		strings.HasPrefix(s, "./") ||
		strings.HasPrefix(s, "../") ||
		strings.HasPrefix(s, "~/")
}

// newTarget classifies a single entry, stripping any URL decoration first.
func newTarget(raw string) target {
	host := normalizeTarget(raw)
	if host == "" {
		return target{raw: raw, err: fmt.Errorf("not an IP address, hostname or URL")}
	}
	if ip := net.ParseIP(host); ip != nil {
		return target{raw: raw, ips: []net.IP{ip}}
	}
	return target{raw: raw, host: host}
}

// normalizeTarget reduces a URL to its host, so that the user can paste
// whatever they have at hand: "https://user@example.com:8443/path?q=1#frag"
// and "example.com" both come back as "example.com". Input that is already a
// bare IP or hostname passes through untouched.
func normalizeTarget(s string) string {
	s = strings.TrimSpace(s)
	// Scheme, or a scheme-relative "//host/path".
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	} else {
		s = strings.TrimPrefix(s, "//")
	}
	// Path, query and fragment. Cut these before the userinfo so that an "@"
	// inside a path cannot be mistaken for a userinfo delimiter.
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	// Port. A bracketed host is an IPv6 literal; an unbracketed host with more
	// than one colon is a bare IPv6 literal, which has no port to strip.
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i >= 0 {
			s = s[1:i]
		}
	} else if i := strings.LastIndex(s, ":"); i >= 0 && strings.Count(s, ":") == 1 {
		s = s[:i]
	}
	// A fully qualified name keeps its meaning without the root label.
	return strings.TrimSuffix(strings.TrimSpace(s), ".")
}

// readTargetFile reads a list of entries, one per line. Blank lines and "#"
// comments are ignored, and only the first whitespace-delimited field of a line
// is used so that columnar files work as-is.
func readTargetFile(path string) ([]target, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var targets []target
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		entry, ok := entryFromLine(scanner.Text())
		if !ok {
			continue
		}
		targets = append(targets, newTarget(entry))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %v", path, err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no entries found in %s", path)
	}
	return targets, nil
}

// entryFromLine extracts the entry from one line of an input file. ok is false
// for blank and comment-only lines.
func entryFromLine(line string) (string, bool) {
	if i := strings.Index(line, "#"); i >= 0 {
		line = line[:i]
	}
	field, _, ok := splitFirstField(strings.TrimSpace(line))
	return field, ok
}

// resolveTargets fills in the addresses of every hostname entry. Each query
// gets its own timeout so one dead name cannot starve the rest of a file.
func resolveTargets(ctx context.Context, targets []target) {
	sem := make(chan struct{}, maxResolveWorkers)
	var wg sync.WaitGroup
	for i := range targets {
		if targets[i].err != nil || targets[i].host == "" {
			continue
		}
		wg.Add(1)
		go func(t *target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			lookupCtx, cancel := context.WithTimeout(ctx, dnsTimeout)
			defer cancel()

			t.ips, t.err = lookupHostIPs(lookupCtx, t.host)
		}(&targets[i])
	}
	wg.Wait()
}

// lookupHostIPs returns every distinct address a hostname resolves to.
func lookupHostIPs(ctx context.Context, host string) ([]net.IP, error) {
	// net.DNSError already names the host it failed on, so it needs no wrapping.
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := dedupeIPs(addrs)
	if len(ips) == 0 {
		return nil, fmt.Errorf("lookup %s: no addresses found", host)
	}
	return ips, nil
}

// dedupeIPs keeps the resolver's ordering but drops repeated addresses, which
// show up when a name has both an A and an IPv4-mapped AAAA record.
func dedupeIPs(addrs []net.IPAddr) []net.IP {
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
