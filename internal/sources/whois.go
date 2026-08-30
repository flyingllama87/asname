package sources

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

const (
	WhoisConsentFilename = "whois-consent.json"
	WhoisConsentTTL      = time.Hour
	whoisTimeout         = 8 * time.Second
	whoisPort            = "43"
	ianaWhois            = "whois.iana.org"
	MaxWhoisQueries      = 25
)

// WhoisMode is how the fallback was configured for this run.
type WhoisMode int

const (
	WhoisAsk WhoisMode = iota
	WhoisAlways
	WhoisNever
)

type whoisConsent struct {
	Allow bool      `json:"allow"`
	Asked time.Time `json:"asked"`
}

type WhoisAsker struct {
	Path     string
	Mode     WhoisMode
	Out      io.Writer
	In       io.Reader
	Terminal bool

	decided bool
	allow   bool
	queries int
	capped  bool
}

func NewWhoisAsker(path string, mode WhoisMode) *WhoisAsker {
	return &WhoisAsker{
		Path:     path,
		Mode:     mode,
		Out:      os.Stderr,
		In:       os.Stdin,
		Terminal: isTerminal(os.Stdin),
	}
}

func (a *WhoisAsker) Allowed(ip net.IP) bool {
	if a == nil || a.Mode == WhoisNever {
		return false
	}
	if !a.decide(ip) {
		return false
	}
	if a.queries >= MaxWhoisQueries {
		if !a.capped {
			a.capped = true
			fmt.Fprintf(a.Out, "asname: stopping whois lookups after %d addresses, to stay under the registries' rate limits\n", MaxWhoisQueries)
		}
		return false
	}
	a.queries++
	return true
}

func (a *WhoisAsker) decide(ip net.IP) bool {
	if a.decided {
		return a.allow
	}
	a.decided = true

	if a.Mode == WhoisAlways {
		a.allow = true
		return true
	}

	if consent, ok := LoadWhoisConsent(a.Path); ok {
		a.allow = consent.Allow
		return a.allow
	}

	if !a.Terminal {
		fmt.Fprintln(a.Out, "asname: no offline netblock data for some addresses; pass --whois to look them up online")
		a.allow = false
		return false
	}

	a.allow = a.ask(ip)
	if err := SaveWhoisConsent(a.Path, a.allow); err != nil {
		fmt.Fprintln(a.Out, "asname: could not remember that answer:", err)
	}
	return a.allow
}

func (a *WhoisAsker) ask(ip net.IP) bool {
	fmt.Fprintf(a.Out, "asname: %s has no offline netblock: ARIN and LACNIC do not publish theirs\n", ip)
	fmt.Fprintf(a.Out, "asname: in a form that can be indexed offline. Query whois over the network for\n")
	fmt.Fprintf(a.Out, "asname: addresses like it? Either answer is remembered for an hour. [y/N] ")

	line, err := bufio.NewReader(a.In).ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(a.Out)
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

func LoadWhoisConsent(path string) (whoisConsent, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return whoisConsent{}, false
	}
	var consent whoisConsent
	if err := json.Unmarshal(data, &consent); err != nil {
		return whoisConsent{}, false
	}
	age := time.Since(consent.Asked)
	if age < 0 || age > WhoisConsentTTL {
		return whoisConsent{}, false
	}
	return consent, true
}

func SaveWhoisConsent(path string, allow bool) error {
	data, err := MarshalConsent(whoisConsent{Allow: allow, Asked: time.Now().UTC()})
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func MarshalConsent(consent whoisConsent) ([]byte, error) {
	data, err := json.Marshal(consent)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// LookupWhoisNetblock asks IANA which registry holds ip, then asks that registry.
func LookupWhoisNetblock(ip net.IP) (NetblockInfo, error) {
	referral, err := whoisQuery(ianaWhois, ip.String())
	if err != nil {
		return NetblockInfo{}, fmt.Errorf("%s: %v", ianaWhois, err)
	}
	server := WhoisField(referral, "refer", "whois")
	if server == "" {
		return NetblockInfo{}, fmt.Errorf("%s named no registry for %s", ianaWhois, ip)
	}

	body, err := whoisQuery(server, ip.String())
	if err != nil {
		return NetblockInfo{}, fmt.Errorf("%s: %v", server, err)
	}

	info := ParseWhoisNetblock(body)
	if info.Empty() {
		if IsWhoisRateLimited(body) {
			return NetblockInfo{}, fmt.Errorf("%s is rate-limiting queries; try again shortly", server)
		}
		return NetblockInfo{}, fmt.Errorf("%s returned no netblock for %s", server, ip)
	}
	return info, nil
}

func IsWhoisRateLimited(body string) bool {
	lower := strings.ToLower(body)
	for _, phrase := range []string{"rate limit", "query limit", "too many requests", "excessive", "try again later"} {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

func whoisQuery(server, query string) (string, error) {
	return WhoisQueryOn(server, whoisPort, query)
}

func WhoisQueryOn(server, port, query string) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(server, port), whoisTimeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(whoisTimeout)); err != nil {
		return "", err
	}
	if _, err := fmt.Fprintf(conn, "%s\r\n", query); err != nil {
		return "", err
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func ParseWhoisNetblock(body string) NetblockInfo {
	info := NetblockInfo{
		Netname: WhoisField(body, "netname"),
		Org:     WhoisField(body, "orgname", "custname", "owner", "descr", "org-name", "organization"),
	}
	if i := strings.LastIndex(info.Org, " ("); i > 0 && strings.HasSuffix(info.Org, ")") {
		info.Org = info.Org[:i]
	}
	if IsPlaceholderRange(info.Netname, info.Org) {
		return NetblockInfo{}
	}
	return info
}

func WhoisField(body string, names ...string) string {
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
		if v := CleanValue(value); v != "" {
			return v
		}
	}
	return ""
}
