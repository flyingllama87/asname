package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// ARIN and LACNIC leave holes in the offline netblock database: ARIN does not
// publish its whois database without a signed agreement, and LACNIC's public
// dump is anonymised. Both will still answer a query about a single address
// over port 43, so an address the offline database cannot name can be looked up
// live instead.
//
// That means going to the network, which the rest of asname never does during a
// lookup, so it is asked about rather than assumed. The answer is remembered for
// an hour so that a session's worth of lookups is one question, not one per
// address.
const (
	whoisConsentFilename = "whois-consent.json"
	whoisConsentTTL      = time.Hour
	whoisTimeout         = 8 * time.Second
	whoisPort            = "43"
	// ianaWhois refers a query to whichever registry holds the address, so the
	// right server is found without asname keeping its own map of the two.
	ianaWhois = "whois.iana.org"
	// maxWhoisQueries caps how many addresses one run will look up online. The
	// registries rate-limit port 43 aggressively, and a large input file would
	// otherwise walk straight into a temporary block.
	maxWhoisQueries = 25
)

// whoisMode is how the fallback was configured for this run.
type whoisMode int

const (
	whoisAsk    whoisMode = iota // ask once, then remember for an hour
	whoisAlways                  // --whois
	whoisNever                   // --no-whois
)

// whoisConsent is the remembered answer, stored beside the databases.
type whoisConsent struct {
	Allow bool      `json:"allow"`
	Asked time.Time `json:"asked"`
}

// whoisAsker decides whether this run may query whois, asking the user at most
// once and only when an address actually needs it.
type whoisAsker struct {
	path     string
	mode     whoisMode
	out      io.Writer // where the question is written, stderr in normal use
	in       io.Reader // where the answer is read from, stdin in normal use
	terminal bool      // whether there is anybody there to answer it

	decided bool
	allow   bool
	queries int
	capped  bool
}

func newWhoisAsker(path string, mode whoisMode) *whoisAsker {
	return &whoisAsker{
		path:     path,
		mode:     mode,
		out:      os.Stderr,
		in:       os.Stdin,
		terminal: isTerminal(os.Stdin),
	}
}

// allowed reports whether a whois query may be made for ip, asking the user on
// the first address that needs one. Later calls reuse that answer.
func (a *whoisAsker) allowed(ip net.IP) bool {
	if a == nil || a.mode == whoisNever {
		return false
	}
	if !a.decide(ip) {
		return false
	}
	if a.queries >= maxWhoisQueries {
		if !a.capped {
			a.capped = true
			fmt.Fprintf(a.out, "asname: stopping whois lookups after %d addresses, to stay under the registries' rate limits\n", maxWhoisQueries)
		}
		return false
	}
	a.queries++
	return true
}

// decide resolves this run's answer once: from the flag, from a remembered
// answer that has not expired, or by asking.
func (a *whoisAsker) decide(ip net.IP) bool {
	if a.decided {
		return a.allow
	}
	a.decided = true

	if a.mode == whoisAlways {
		a.allow = true
		return true
	}

	if consent, ok := loadWhoisConsent(a.path); ok {
		a.allow = consent.Allow
		return a.allow
	}

	// Without a terminal there is nobody to ask, and silently reaching out to
	// the network is exactly what the question exists to prevent.
	if !a.terminal {
		fmt.Fprintln(a.out, "asname: no offline netblock data for some addresses; pass --whois to look them up online")
		a.allow = false
		return false
	}

	a.allow = a.ask(ip)
	if err := saveWhoisConsent(a.path, a.allow); err != nil {
		fmt.Fprintln(a.out, "asname: could not remember that answer:", err)
	}
	return a.allow
}

// ask puts the question to the user and reads their answer.
func (a *whoisAsker) ask(ip net.IP) bool {
	fmt.Fprintf(a.out, "asname: %s has no offline netblock: ARIN and LACNIC do not publish theirs\n", ip)
	fmt.Fprintf(a.out, "asname: in a form that can be indexed offline. Query whois over the network for\n")
	fmt.Fprintf(a.out, "asname: addresses like it? Either answer is remembered for an hour. [y/N] ")

	line, err := bufio.NewReader(a.in).ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(a.out)
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

// loadWhoisConsent returns a remembered answer, and whether one was found that
// has not yet expired.
func loadWhoisConsent(path string) (whoisConsent, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return whoisConsent{}, false
	}
	var consent whoisConsent
	if err := json.Unmarshal(data, &consent); err != nil {
		return whoisConsent{}, false
	}
	// A timestamp in the future means a clock change; treat it as expired
	// rather than letting it hold indefinitely.
	age := time.Since(consent.Asked)
	if age < 0 || age > whoisConsentTTL {
		return whoisConsent{}, false
	}
	return consent, true
}

func saveWhoisConsent(path string, allow bool) error {
	data, err := marshalConsent(whoisConsent{Allow: allow, Asked: time.Now().UTC()})
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func marshalConsent(consent whoisConsent) ([]byte, error) {
	data, err := json.Marshal(consent)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// lookupWhoisNetblock asks IANA which registry holds ip, then asks that
// registry who the address is assigned to.
func lookupWhoisNetblock(ip net.IP) (netblockInfo, error) {
	referral, err := whoisQuery(ianaWhois, ip.String())
	if err != nil {
		return netblockInfo{}, fmt.Errorf("%s: %v", ianaWhois, err)
	}
	server := whoisField(referral, "refer", "whois")
	if server == "" {
		return netblockInfo{}, fmt.Errorf("%s named no registry for %s", ianaWhois, ip)
	}

	body, err := whoisQuery(server, ip.String())
	if err != nil {
		return netblockInfo{}, fmt.Errorf("%s: %v", server, err)
	}

	info := parseWhoisNetblock(body)
	if info.empty() {
		// The registries answer a query they are throttling with a perfectly
		// well-formed document that simply has no data in it. Reporting that
		// as "no netblock" would be indistinguishable from an address nobody
		// holds, so say which it was.
		if isWhoisRateLimited(body) {
			return netblockInfo{}, fmt.Errorf("%s is rate-limiting queries; try again shortly", server)
		}
		return netblockInfo{}, fmt.Errorf("%s returned no netblock for %s", server, ip)
	}
	return info, nil
}

// isWhoisRateLimited reports whether a response is a refusal to answer rather
// than an answer.
func isWhoisRateLimited(body string) bool {
	lower := strings.ToLower(body)
	for _, phrase := range []string{"rate limit", "query limit", "too many requests", "excessive", "try again later"} {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

// whoisQuery runs one query against a registry's whois service.
func whoisQuery(server, query string) (string, error) {
	return whoisQueryOn(server, whoisPort, query)
}

// whoisQueryOn is whoisQuery against a given port. The protocol is a line in
// and a document out, with the server closing the connection to end the
// response.
func whoisQueryOn(server, port, query string) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(server, port), whoisTimeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(whoisTimeout)); err != nil {
		return "", err
	}
	if _, err := io.WriteString(conn, query+"\r\n"); err != nil {
		return "", err
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// parseWhoisNetblock pulls the netblock name and its owner out of a response.
// Each registry has its own vocabulary for the two — ARIN answers with NetName
// and OrgName, LACNIC with owner alone, and the RPSL registries with netname
// and descr — so every spelling is tried in the order that prefers the most
// specific.
func parseWhoisNetblock(body string) netblockInfo {
	info := netblockInfo{
		netname: whoisField(body, "netname"),
		org:     whoisField(body, "orgname", "custname", "owner", "descr", "org-name", "organization"),
	}
	// ARIN's "Organization" repeats the handle after the name, which the
	// dedicated OrgName field does not.
	if i := strings.LastIndex(info.org, " ("); i > 0 && strings.HasSuffix(info.org, ")") {
		info.org = info.org[:i]
	}
	if isPlaceholderRange(info.netname, info.org) {
		return netblockInfo{}
	}
	return info
}

// whoisField returns the first value found for any of names, searched in the
// order given rather than the order they appear in the response.
func whoisField(body string, names ...string) string {
	for _, name := range names {
		if v := firstWhoisField(body, name); v != "" {
			return v
		}
	}
	return ""
}

func firstWhoisField(body, name string) string {
	for line := range strings.SplitSeq(body, "\n") {
		if line == "" || line[0] == '%' || line[0] == '#' {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), name) {
			continue
		}
		if v := cleanValue(value); v != "" {
			return v
		}
	}
	return ""
}
