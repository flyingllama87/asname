package engine

import (
	_ "embed"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Targets are read from anything: a clean list, a bulleted one, a log, an
// alert, a web page. A line that starts with a target keeps the old rule,
// its first field (so "8.8.8.8 GOOGLE" and "13335 Cloudflare" are one
// target each); any other line is searched for IP addresses, URLs, AS
// numbers and domains, defanged ones ("hxxp", "[.]") included. The web UI
// does the same in web/src/targets.js.

// tldsText is IANA's list of top-level domains
// (https://data.iana.org/TLD/tlds-alpha-by-domain.txt), used to tell a
// domain in free text from a file name or a version number.
//
//go:embed tlds.txt
var tldsText string

var tlds = func() map[string]bool {
	m := map[string]bool{}
	for _, l := range strings.Split(tldsText, "\n") {
		l = strings.TrimSpace(l)
		if l != "" && l[0] != '#' {
			m[strings.ToLower(l)] = true
		}
	}
	return m
}()

// fileLikeTLDs are file extensions that are also top-level domains:
// "README.md" or "setup.py" in prose is a file, not a host.
var fileLikeTLDs = map[string]bool{
	"md": true, "sh": true, "py": true, "pl": true, "rs": true, "zip": true, "mov": true,
	"so": true, "ps": true, "ai": true, "cc": true, "java": true, "scot": true,
}

var (
	refangDot  = regexp.MustCompile(`(?i)\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)`)
	refangHxxp = regexp.MustCompile(`(?i)\bhxxp(s?)://`)
	bulletRe   = regexp.MustCompile(`^(?:[-*•>+]\s*|\d+[.)]\s+)`)
	urlRe      = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s<>"'` + "`" + `)\]}|\\^]+`)
	ipv4Re     = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}`)
	ipv6Re     = regexp.MustCompile(`[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*`)
	asnRe      = regexp.MustCompile(`\bASN?[ -]?(\d{1,10})\b`)
	domainRe   = regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}`)
)

// Refang undoes the usual ways of defanging an indicator.
func Refang(s string) string {
	s = refangDot.ReplaceAllString(s, ".")
	s = strings.ReplaceAll(s, "[:]", ":")
	s = strings.ReplaceAll(s, "[://]", "://")
	s = refangHxxp.ReplaceAllString(s, "http$1://")
	return s
}

// EntriesFromLine returns the targets in one line of input, in order.
func EntriesFromLine(line string) []string {
	line = Refang(line)
	if i := commentStart(line); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	stripped := strings.TrimSpace(bulletRe.ReplaceAllString(line, ""))
	if first, rest, ok := cutField(stripped); ok && leadsWithTarget(first, rest != "") {
		return []string{first}
	}
	return extractTargets(line)
}

// EntryFromLine returns the first target in line, for callers that take
// one per line.
func EntryFromLine(line string) (string, bool) {
	e := EntriesFromLine(line)
	if len(e) == 0 {
		return "", false
	}
	return e[0], true
}

// commentStart is where a '#' comment begins: at the start of the line or
// after a space, so a URL's fragment is not one.
func commentStart(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
			return i
		}
	}
	return -1
}

// cutField splits off the first whitespace-separated field, without the
// quotes or brackets around it.
func cutField(s string) (first, rest string, ok bool) {
	f := strings.Fields(s)
	if len(f) == 0 {
		return "", "", false
	}
	first = strings.Trim(f[0], "\"'`()[]<>,;")
	rest = strings.TrimSpace(strings.TrimPrefix(s, f[0]))
	return first, rest, first != ""
}

// leadsWithTarget reports whether a line's first field is a target to take
// as it is. Alone on its line, any host name will do (internal names
// included); followed by more text, only something that cannot be an
// ordinary word: an address, a URL, an AS number or a number, or a name
// with a dot in it.
func leadsWithTarget(first string, more bool) bool {
	if strings.Contains(first, "://") {
		_, err := url.Parse(first)
		return err == nil
	}
	if _, err := netip.ParseAddr(strings.Trim(first, "[]")); err == nil {
		return true
	}
	if ap, err := netip.ParseAddrPort(first); err == nil && ap.IsValid() {
		return true
	}
	if _, ok := ParseASNTarget(first); ok {
		return true
	}
	if !isHostName(first) {
		return false
	}
	if !more {
		return true
	}
	return strings.Contains(strings.TrimSuffix(first, "."), ".") && !looksLikeIPv4(first)
}

func isHostName(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if host, port, ok := strings.Cut(s, ":"); ok {
		if _, err := strconv.Atoi(port); err != nil {
			return false
		}
		s = host
	}
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

func looksLikeIPv4(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c == '.') {
			return false
		}
	}
	return true
}

// ExtractTargets returns every target in text, in order of appearance and
// each once, applying EntriesFromLine to each line.
func ExtractTargets(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		for _, t := range EntriesFromLine(line) {
			if k := strings.ToLower(t); !seen[k] {
				seen[k] = true
				out = append(out, t)
			}
		}
	}
	return out
}

type found struct {
	at     int
	target string
}

// extractTargets searches free text for targets.
func extractTargets(s string) []string {
	var hits []found
	buf := []byte(s)
	blank := func(i, j int) {
		for k := i; k < j; k++ {
			buf[k] = ' '
		}
	}
	for _, m := range urlRe.FindAllStringIndex(s, -1) {
		raw := strings.TrimRight(s[m[0]:m[1]], ".,;:!?")
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			hits = append(hits, found{m[0], u.Hostname()})
		}
		blank(m[0], m[1])
	}
	rest := string(buf)
	for _, m := range ipv4Re.FindAllStringIndex(rest, -1) {
		if m[0] > 0 && (isDigit(rest[m[0]-1]) || rest[m[0]-1] == '.') {
			continue
		}
		if m[1] < len(rest) && (isDigit(rest[m[1]]) || (rest[m[1]] == '.' && m[1]+1 < len(rest) && isDigit(rest[m[1]+1]))) {
			continue
		}
		if a, err := netip.ParseAddr(rest[m[0]:m[1]]); err == nil && a.Is4() {
			hits = append(hits, found{m[0], a.String()})
			blank(m[0], m[1])
		}
	}
	rest = string(buf)
	for _, m := range ipv6Re.FindAllStringIndex(rest, -1) {
		cand := strings.Trim(rest[m[0]:m[1]], ".")
		if a, err := netip.ParseAddr(cand); err == nil && a.Is6() && cand != "::" {
			if m[0] > 0 && isWordByte(rest[m[0]-1]) {
				continue
			}
			hits = append(hits, found{m[0], cand})
			blank(m[0], m[1])
		}
	}
	rest = string(buf)
	for _, m := range asnRe.FindAllStringSubmatchIndex(rest, -1) {
		if n, err := strconv.ParseUint(rest[m[2]:m[3]], 10, 32); err == nil && n > 0 {
			hits = append(hits, found{m[0], "AS" + strconv.FormatUint(n, 10)})
		}
	}
	for _, m := range domainRe.FindAllStringIndex(rest, -1) {
		if m[0] > 0 {
			if r, _ := utf8.DecodeLastRuneInString(rest[:m[0]]); isWordRune(r) || r == '@' || r == '.' || r == '-' {
				continue
			}
		}
		if m[1] < len(rest) {
			if r, _ := utf8.DecodeRuneInString(rest[m[1]:]); isWordRune(r) || r == '-' {
				continue
			}
		}
		host := rest[m[0]:m[1]]
		labels := strings.Split(strings.ToLower(host), ".")
		tld := labels[len(labels)-1]
		if !tlds[tld] || (len(labels) == 2 && fileLikeTLDs[tld]) {
			continue
		}
		hits = append(hits, found{m[0], host})
	}
	if len(hits) == 0 {
		return nil
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].at < hits[j].at })
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.target)
	}
	return out
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
func isWordRune(r rune) bool { return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) }
