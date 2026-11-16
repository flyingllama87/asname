package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// RDAP (Registration Data Access Protocol, RFC 9082/9083) is the registries'
// JSON-over-HTTPS replacement for port-43 whois: the same field names at
// every registry, always UTF-8. The online netblock lookup asks RDAP first
// and falls back to whois when a registry's RDAP server fails.

const (
	// RDAPBootstrapURL is IANA's directory of which RDAP server holds which
	// address space; ipv4.json and ipv6.json sit under it.
	RDAPBootstrapURL = "https://data.iana.org/rdap/"
	// RDAPBootstrapTTL is how long a downloaded bootstrap file is used
	// before it is fetched again. IANA changes it a few times a year.
	RDAPBootstrapTTL = 7 * 24 * time.Hour

	rdapTimeout  = 8 * time.Second
	rdapMaxBody  = 4 << 20
	rdapRedirect = 5
)

// Online netblock sources, as LookupOnlineNetblock reports them.
const (
	OnlineSourceRDAP  = "rdap"
	OnlineSourceWhois = "whois"
)

// ErrRDAPNotFound means the registry answered but has no network for the
// address.
var ErrRDAPNotFound = errors.New("no RDAP network for the address")

// RDAPClient looks addresses up over RDAP. It is safe for concurrent use; a
// long-running server shares one so the bootstrap file is read once.
type RDAPClient struct {
	// CacheDir holds the downloaded bootstrap files (rdap-ipv4.json,
	// rdap-ipv6.json). Empty keeps them in memory only.
	CacheDir string
	// BootstrapURL is where ipv4.json and ipv6.json are fetched from.
	BootstrapURL string
	// HTTP is the client used for every request. Its redirects must stay
	// on HTTPS; NewRDAPClient's does.
	HTTP *http.Client
	// HTTPv4, when set, retries a request that failed or took more than
	// half the timeout over IPv4 only: from some networks, registries'
	// servers reset or stall IPv6 connections (LACNIC, RIPE, AFRINIC) while
	// answering over IPv4.
	HTTPv4 *http.Client
	// Whois is the fallback when RDAP fails; nil uses LookupWhoisNetblock.
	Whois func(net.IP) (NetblockInfo, error)

	mu   sync.Mutex
	boot map[string]*rdapBootstrap // "ipv4", "ipv6"
	// v4Only holds the hosts whose first attempt failed and IPv4 answered;
	// they are asked over IPv4 straight away from then on.
	v4Only sync.Map
}

type rdapBootstrap struct {
	fetched  time.Time
	services []rdapService
}

type rdapService struct {
	prefixes []netip.Prefix
	base     string
}

// NewRDAPClient returns a client that caches the bootstrap files in
// cacheDir (none when empty).
func NewRDAPClient(cacheDir string) *RDAPClient {
	v4 := http.DefaultTransport.(*http.Transport).Clone()
	dialer := &net.Dialer{Timeout: rdapTimeout}
	v4.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp4", addr)
	}
	return &RDAPClient{
		CacheDir:     cacheDir,
		BootstrapURL: RDAPBootstrapURL,
		HTTP:         &http.Client{Timeout: rdapTimeout, CheckRedirect: httpsRedirectsOnly},
		HTTPv4:       &http.Client{Timeout: rdapTimeout, CheckRedirect: httpsRedirectsOnly, Transport: v4},
	}
}

// httpsRedirectsOnly follows a few redirects, all over HTTPS. Registries
// redirect to each other, and LACNIC and APNIC to national registries
// (registro.br, JPNIC...).
func httpsRedirectsOnly(req *http.Request, via []*http.Request) error {
	if len(via) >= rdapRedirect {
		return fmt.Errorf("stopped after %d redirects", rdapRedirect)
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect to %s", req.URL.Redacted())
	}
	return nil
}

// LookupOnlineNetblock asks RDAP for ip's netblock and, if that fails for
// any reason, port-43 whois. It returns the netblock and which of the two
// answered (OnlineSourceRDAP or OnlineSourceWhois). rdapErr is RDAP's error
// when whois answered instead, so the caller can log it; err is set only
// when neither found anything. A nil client goes straight to whois.
func (c *RDAPClient) LookupOnlineNetblock(ctx context.Context, ip net.IP) (info NetblockInfo, source string, rdapErr, err error) {
	whois := LookupWhoisNetblock
	if c != nil {
		if c.Whois != nil {
			whois = c.Whois
		}
		info, rdapErr = c.LookupNetblock(ctx, ip)
		if rdapErr == nil {
			return info, OnlineSourceRDAP, nil, nil
		}
	}
	info, err = whois(ip)
	if err != nil {
		if rdapErr != nil {
			err = fmt.Errorf("RDAP: %v; whois: %v", rdapErr, err)
		}
		return NetblockInfo{}, "", rdapErr, err
	}
	return info, OnlineSourceWhois, rdapErr, nil
}

// LookupNetblock asks the registry that holds ip for its most specific
// network.
func (c *RDAPClient) LookupNetblock(ctx context.Context, ip net.IP) (NetblockInfo, error) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return NetblockInfo{}, fmt.Errorf("invalid IP address %v", ip)
	}
	addr = addr.Unmap()
	base, err := c.serverFor(ctx, addr)
	if err != nil {
		return NetblockInfo{}, err
	}

	u := strings.TrimSuffix(base, "/") + "/ip/" + addr.String()
	body, status, err := c.get(ctx, u)
	if err != nil {
		return NetblockInfo{}, fmt.Errorf("%s: %v", hostOf(u), err)
	}
	switch {
	case status == http.StatusNotFound:
		return NetblockInfo{}, ErrRDAPNotFound
	case status == http.StatusTooManyRequests:
		return NetblockInfo{}, fmt.Errorf("%s is rate-limiting queries; try again shortly", hostOf(u))
	case status != http.StatusOK:
		return NetblockInfo{}, fmt.Errorf("%s answered HTTP %d", hostOf(u), status)
	}

	info, err := ParseRDAPNetwork(body)
	if err != nil {
		return NetblockInfo{}, fmt.Errorf("%s: %v", hostOf(u), err)
	}
	if info.Empty() {
		return NetblockInfo{}, ErrRDAPNotFound
	}
	return info, nil
}

func hostOf(u string) string {
	u = strings.TrimPrefix(u, "https://")
	host, _, _ := strings.Cut(u, "/")
	return host
}

func (c *RDAPClient) get(ctx context.Context, u string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, rdapTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", "asname")

	// With an IPv4 fallback, the first attempt gets half the time: a
	// broken IPv6 path usually hangs rather than failing fast.
	host := req.URL.Host
	var resp *http.Response
	if _, known := c.v4Only.Load(host); known && c.HTTPv4 != nil {
		resp, err = c.HTTPv4.Do(req)
	} else {
		first := ctx
		if c.HTTPv4 != nil {
			var cancelFirst context.CancelFunc
			first, cancelFirst = context.WithTimeout(ctx, rdapTimeout/2)
			defer cancelFirst()
		}
		resp, err = c.HTTP.Do(req.WithContext(first))
		if err != nil && c.HTTPv4 != nil && ctx.Err() == nil {
			if resp, err = c.HTTPv4.Do(req.WithContext(ctx)); err == nil {
				c.v4Only.Store(host, true)
			}
		}
	}
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, rdapMaxBody+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if len(body) > rdapMaxBody {
		return nil, resp.StatusCode, fmt.Errorf("response larger than %d bytes", rdapMaxBody)
	}
	return body, resp.StatusCode, nil
}

// serverFor returns the RDAP base URL for addr from IANA's bootstrap file:
// the service with the longest prefix that holds addr.
func (c *RDAPClient) serverFor(ctx context.Context, addr netip.Addr) (string, error) {
	family := "ipv4"
	if addr.Is6() {
		family = "ipv6"
	}
	boot, err := c.bootstrap(ctx, family)
	if err != nil {
		return "", err
	}
	best, bestBits := "", -1
	for _, svc := range boot.services {
		for _, p := range svc.prefixes {
			if p.Bits() > bestBits && p.Contains(addr) {
				best, bestBits = svc.base, p.Bits()
			}
		}
	}
	if best == "" {
		return "", fmt.Errorf("no RDAP server is listed for %s", addr)
	}
	return best, nil
}

// bootstrap returns the parsed bootstrap file for family, from memory, the
// cache directory or IANA, in that order. A stale copy is used when IANA
// cannot be reached.
func (c *RDAPClient) bootstrap(ctx context.Context, family string) (*rdapBootstrap, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.boot == nil {
		c.boot = map[string]*rdapBootstrap{}
	}
	if b := c.boot[family]; b != nil && time.Since(b.fetched) < RDAPBootstrapTTL {
		return b, nil
	}

	cachePath := ""
	if c.CacheDir != "" {
		cachePath = filepath.Join(c.CacheDir, "rdap-"+family+".json")
	}
	var stale *rdapBootstrap
	if cachePath != "" {
		if data, err := os.ReadFile(cachePath); err == nil {
			if b, err := parseRDAPBootstrap(data); err == nil {
				b.fetched = modTime(cachePath)
				if time.Since(b.fetched) < RDAPBootstrapTTL {
					c.boot[family] = b
					return b, nil
				}
				stale = b
			}
		}
	}

	u := strings.TrimSuffix(c.BootstrapURL, "/") + "/" + family + ".json"
	data, status, err := c.get(ctx, u)
	if err == nil && status != http.StatusOK {
		err = fmt.Errorf("HTTP %d", status)
	}
	var b *rdapBootstrap
	if err == nil {
		b, err = parseRDAPBootstrap(data)
	}
	if err != nil {
		if stale != nil {
			c.boot[family] = stale
			return stale, nil
		}
		return nil, fmt.Errorf("RDAP bootstrap %s: %v", u, err)
	}
	b.fetched = time.Now()
	c.boot[family] = b
	if cachePath != "" {
		// Best effort: without the cache the next run fetches it again.
		_ = writeFileAtomic(cachePath, data, 0o644)
	}
	return b, nil
}

func modTime(path string) time.Time {
	st, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return st.ModTime()
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// parseRDAPBootstrap reads an IANA bootstrap file (RFC 9224): services is a
// list of [prefixes, base URLs]. Only HTTPS servers are kept.
func parseRDAPBootstrap(data []byte) (*rdapBootstrap, error) {
	var raw struct {
		Services [][][]string `json:"services"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	b := &rdapBootstrap{}
	for _, svc := range raw.Services {
		if len(svc) != 2 {
			continue
		}
		base := ""
		for _, u := range svc[1] {
			if strings.HasPrefix(u, "https://") {
				base = u
				break
			}
		}
		if base == "" {
			continue
		}
		var prefixes []netip.Prefix
		for _, p := range svc[0] {
			if pfx, err := netip.ParsePrefix(p); err == nil {
				prefixes = append(prefixes, pfx.Masked())
			}
		}
		if len(prefixes) > 0 {
			b.services = append(b.services, rdapService{prefixes: prefixes, base: base})
		}
	}
	if len(b.services) == 0 {
		return nil, errors.New("no HTTPS services listed")
	}
	return b, nil
}

type rdapEntity struct {
	Handle     string            `json:"handle"`
	Roles      []string          `json:"roles"`
	VCardArray []json.RawMessage `json:"vcardArray"`
	Entities   []rdapEntity      `json:"entities"`
}

type rdapNetwork struct {
	ObjectClassName string       `json:"objectClassName"`
	Handle          string       `json:"handle"`
	Name            string       `json:"name"`
	Country         string       `json:"country"`
	Entities        []rdapEntity `json:"entities"`
	Events          []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Remarks []struct {
		Title       string   `json:"title"`
		Description []string `json:"description"`
	} `json:"remarks"`
}

// ParseRDAPNetwork maps an RDAP ip network object to a NetblockInfo: name
// is the netname, the registrant's vCard "fn" the organisation (falling back
// to the first description remark, RIPE's and APNIC's descr), country and
// the registration date.
func ParseRDAPNetwork(body []byte) (NetblockInfo, error) {
	var n rdapNetwork
	if err := json.Unmarshal(body, &n); err != nil {
		return NetblockInfo{}, fmt.Errorf("decoding RDAP response: %v", err)
	}
	if n.ObjectClassName != "" && n.ObjectClassName != "ip network" {
		return NetblockInfo{}, fmt.Errorf("RDAP answered with a %q object", n.ObjectClassName)
	}

	info := NetblockInfo{
		Netname: CleanValue(n.Name),
		Org:     registrantName(n.Entities),
	}
	// registro.br names a network by its owner's number ("22817"), which
	// says nothing to a reader.
	if isDigits(info.Netname) {
		info.Netname = ""
	}
	if info.Org == "" {
		for _, r := range n.Remarks {
			if (r.Title == "" || strings.EqualFold(r.Title, "description")) && len(r.Description) > 0 {
				info.Org = CleanValue(r.Description[0])
				break
			}
		}
	}
	if IsPlaceholderRange(info.Netname, info.Org) {
		return NetblockInfo{}, nil
	}
	if len(n.Country) == 2 {
		info.Country = strings.ToUpper(n.Country)
	}
	for _, e := range n.Events {
		if e.Action == "registration" && len(e.Date) >= 10 {
			if _, err := time.Parse("2006-01-02", e.Date[:10]); err == nil {
				info.Created = e.Date[:10]
			}
			break
		}
	}
	return info, nil
}

// registrantName is the "fn" of the registrant, preferring an organisation
// over the maintainer objects RIPE also lists as registrants
// (RIPE-NCC-MNT). It looks one level into nested entities.
func registrantName(entities []rdapEntity) string {
	var fallback string
	for _, list := range [][]rdapEntity{entities, nested(entities)} {
		for _, e := range list {
			if !hasRole(e.Roles, "registrant") {
				continue
			}
			fn, kind := vcardField(e.VCardArray, "fn"), vcardField(e.VCardArray, "kind")
			if fn == "" || strings.HasSuffix(strings.ToUpper(e.Handle), "-MNT") {
				continue
			}
			if kind == "org" {
				return fn
			}
			if fallback == "" {
				fallback = fn
			}
		}
		if fallback != "" {
			return fallback
		}
	}
	return ""
}

func nested(entities []rdapEntity) []rdapEntity {
	var out []rdapEntity
	for _, e := range entities {
		out = append(out, e.Entities...)
	}
	return out
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if strings.EqualFold(r, want) {
			return true
		}
	}
	return false
}

// vcardField returns a text property of a jCard (RFC 7095):
// ["vcard", [[name, params, type, value], ...]].
func vcardField(card []json.RawMessage, name string) string {
	if len(card) < 2 {
		return ""
	}
	var props [][]json.RawMessage
	if err := json.Unmarshal(card[1], &props); err != nil {
		return ""
	}
	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		var key, value string
		if json.Unmarshal(p[0], &key) != nil || !strings.EqualFold(key, name) {
			continue
		}
		if json.Unmarshal(p[3], &value) == nil {
			return CleanValue(value)
		}
	}
	return ""
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
