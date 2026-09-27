package asname

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/flyingllama87/asname/internal/engine"
	"github.com/flyingllama87/asname/internal/sources"
)

// ErrClosed is returned when an operation is performed on a closed Client.
var ErrClosed = errors.New("asname: client is closed")

// Client is a query client holding in-memory databases for high-speed lookups.
type Client struct {
	eng        *engine.Engine
	cfg        sources.Config
	reverseDNS bool

	mu     sync.RWMutex
	closed bool
}

// New creates a new Client configured with the given options.
// If no options are given, DefaultOptions() are used.
func New(opts ...Option) (*Client, error) {
	o := DefaultOptions()
	for _, opt := range opts {
		opt(&o)
	}
	return NewWithOptions(o)
}

// NewWithOptions creates a new Client with explicit Options.
func NewWithOptions(opts Options) (*Client, error) {
	cfg := opts.toSourcesConfig()

	wantCity := false
	switch opts.City {
	case FeatureEnabled:
		wantCity = true
	case FeatureAuto:
		wantCity = sources.CityDBPresent(cfg.CityPath)
	}

	wantNetblock := false
	switch opts.Netblock {
	case FeatureEnabled:
		wantNetblock = true
	case FeatureAuto:
		wantNetblock = sources.NetblockDBPresent(cfg.NetblockPath)
	}

	wantCategory := false
	switch opts.Category {
	case FeatureEnabled:
		wantCategory = true
	case FeatureAuto:
		wantCategory = sources.CategoryDBPresent(cfg.CategoryPath)
	}

	var whoisMode sources.WhoisMode
	switch opts.Whois {
	case WhoisAlways:
		whoisMode = sources.WhoisAlways
	case WhoisAsk:
		whoisMode = sources.WhoisAsk
	default:
		whoisMode = sources.WhoisNever
	}
	showNetblock := wantNetblock || whoisMode == sources.WhoisAlways

	if opts.AutoUpdate > 0 {
		_, err := UpdateStale(context.Background(), UpdateOptions{
			ASN: true, Names: true, Country: true,
			City: wantCity, Netblock: wantNetblock, Category: wantCategory,
			DataDir: opts.DataDir, Paths: opts.Paths,
			ContactEmail: opts.ContactEmail, Log: opts.Log,
		}, opts.AutoUpdate)
		if err != nil {
			return nil, fmt.Errorf("asname: auto-update failed: %w", err)
		}
	}

	eng, err := engine.NewEngine(cfg, wantCity, wantNetblock, showNetblock, wantCategory, whoisMode, opts.Log)
	if err != nil {
		return nil, err
	}
	if opts.OnlinePrefixes {
		eng.SetOnlinePrefixes(sources.WhoisAlways)
	}

	return &Client{
		eng:        eng,
		cfg:        cfg,
		reverseDNS: opts.EnableReverseDNS,
	}, nil
}

// Lookup queries an IP address, hostname, URL, or ASN string (e.g. "8.8.8.8", "dns.google", "https://1.1.1.1", "AS15169").
func (c *Client) Lookup(target string) ([]Result, error) {
	return c.LookupContext(context.Background(), target)
}

// LookupContext is like Lookup but respects ctx for DNS resolution, online prefixes, or whois.
func (c *Client) LookupContext(ctx context.Context, target string) ([]Result, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return nil, ErrClosed
	}

	targets, err := engine.ParseTargets(target)
	if err != nil {
		return nil, err
	}

	engine.ResolveTargets(ctx, targets)

	var allResults []Result
	for _, t := range targets {
		rawResults, err := c.eng.LookupTargetContext(ctx, t)
		if err != nil {
			return nil, err
		}
		if c.reverseDNS {
			engine.ResolveReverseDNS(ctx, rawResults)
		}
		for _, r := range rawResults {
			allResults = append(allResults, resultFromEngine(r))
		}
	}
	return allResults, nil
}

// LookupIP performs a fast in-memory lookup for a single net.IP address.
func (c *Client) LookupIP(ip net.IP) (Result, error) {
	return c.LookupIPContext(context.Background(), ip)
}

// LookupIPContext is like LookupIP but respects ctx for the reverse DNS lookup
// made when WithReverseDNS is enabled.
func (c *Client) LookupIPContext(ctx context.Context, ip net.IP) (Result, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return Result{}, ErrClosed
	}

	raw, err := c.eng.Lookup(ip)
	if err != nil {
		return Result{}, err
	}
	if c.reverseDNS {
		results := []engine.LookupResult{raw}
		engine.ResolveReverseDNS(ctx, results)
		raw = results[0]
	}
	return resultFromEngine(raw), nil
}

// LookupASN looks up details for an Autonomous System by number (e.g. 15169).
func (c *Client) LookupASN(asn uint32) (Result, error) {
	return c.LookupASNContext(context.Background(), asn)
}

// LookupASNContext looks up an Autonomous System by number. With
// WithOnlinePrefixes enabled, ctx bounds the online prefix query made when the
// local prefix database does not cover asn.
func (c *Client) LookupASNContext(ctx context.Context, asn uint32) (Result, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return Result{}, ErrClosed
	}

	raw, err := c.eng.LookupASNContext(ctx, asn)
	if err != nil {
		return Result{}, err
	}
	return resultFromEngine(raw), nil
}

// Search looks for query, ignoring case, in the registered names of
// Autonomous Systems and in the organization names and netnames of registry
// netblocks, so an organization that holds an ASN but no address space is
// still found. opts.Scope limits it to one of the two. With SearchAll and no
// netblock database open (see HasNetblockDB) only the AS names are searched;
// SearchNetblocksOnly returns an error instead.
func (c *Client) Search(query string, opts SearchOptions) (SearchResults, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return SearchResults{}, ErrClosed
	}

	var out SearchResults
	if opts.Scope != SearchNetblocksOnly {
		for _, r := range c.eng.SearchASNs(query, opts.Limit, opts.V4Only, opts.V6Only) {
			out.ASNs = append(out.ASNs, asnResultFromEngine(r))
		}
	}
	if opts.Scope == SearchNetblocksOnly || (opts.Scope == SearchAll && c.eng.HasNetblockDB()) {
		netblocks, err := c.searchNetblocks(query, opts)
		if err != nil {
			return SearchResults{}, err
		}
		out.Netblocks = netblocks
	}
	return out, nil
}

// CountryPrefixes returns the minimal CIDR blocks the country database
// assigns to country, a two-letter ISO code ("AU") or an English name
// ("Australia"), in ascending address order. The database is built from the
// RIR delegation files, so a block belongs to the country its holder
// registered it in, which is not always where its addresses are used.
func (c *Client) CountryPrefixes(country string) (CountryResult, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return CountryResult{}, ErrClosed
	}

	cc, v4, v6, err := c.eng.CountryPrefixes(country)
	if err != nil {
		return CountryResult{}, err
	}
	return CountryResult{Country: cc, Name: sources.CountryNames[cc], IPv4: v4, IPv6: v6}, nil
}

// CityPrefixes returns every place whose city is named city, with the CIDR
// blocks the city database locates there, the place with the most networks
// first. A name several places share returns them all; add ", " and a region,
// country code or country name to pick one, as in "Brisbane, AU". It needs the
// city database, which New loads when it is present or WithCity(true) is set.
func (c *Client) CityPrefixes(city string) ([]CityResult, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return nil, ErrClosed
	}

	places, err := c.eng.CityPrefixes(city)
	if err != nil {
		return nil, err
	}
	out := make([]CityResult, len(places))
	for i, p := range places {
		out[i] = CityResult{City: p.City, Region: p.Region, Country: p.Country, IPv4: p.IPv4, IPv6: p.IPv6}
	}
	return out, nil
}

// SearchNetblocks searches the registry netblock database by organization name or netname.
func (c *Client) SearchNetblocks(query string, opts SearchOptions) ([]NetblockResult, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return nil, ErrClosed
	}
	return c.searchNetblocks(query, opts)
}

func (c *Client) searchNetblocks(query string, opts SearchOptions) ([]NetblockResult, error) {
	raw, err := c.eng.SearchNetblocks(query, sources.NetblockSearchOptions{
		Limit:  opts.Limit,
		V4Only: opts.V4Only,
		V6Only: opts.V6Only,
	})
	if err != nil {
		return nil, err
	}

	results := make([]NetblockResult, len(raw))
	for i, r := range raw {
		results[i] = netblockResultFromEngine(r)
	}
	return results, nil
}

// HasCityDB reports whether the city database is loaded.
func (c *Client) HasCityDB() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.eng != nil && c.eng.HasCityDB()
}

// HasNetblockDB reports whether the netblock database is loaded.
func (c *Client) HasNetblockDB() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.eng != nil && c.eng.HasNetblockDB()
}

// HasCategoryDB reports whether the category database is loaded.
func (c *Client) HasCategoryDB() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.eng != nil && c.eng.HasCategoryDB()
}

// HasPrefixDB reports whether the prefix database is loaded.
func (c *Client) HasPrefixDB() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.eng != nil && c.eng.HasPrefixDB()
}

// Close closes open database handles and releases resources.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.eng != nil {
		c.eng.Close()
	}
	return nil
}

// Global package-level convenience functions using a lazily-initialized shared default client:

var (
	defaultClientMu sync.Mutex
	defaultClient   *Client
)

// DefaultClient returns the shared singleton Client, initializing it with DefaultOptions() on first call.
func DefaultClient() (*Client, error) {
	defaultClientMu.Lock()
	defer defaultClientMu.Unlock()
	if defaultClient != nil {
		return defaultClient, nil
	}
	c, err := New()
	if err != nil {
		return nil, err
	}
	defaultClient = c
	return defaultClient, nil
}

// Lookup queries the target using DefaultClient().
func Lookup(target string) ([]Result, error) {
	c, err := DefaultClient()
	if err != nil {
		return nil, err
	}
	return c.Lookup(target)
}

// LookupContext queries the target using DefaultClient() with context.
func LookupContext(ctx context.Context, target string) ([]Result, error) {
	c, err := DefaultClient()
	if err != nil {
		return nil, err
	}
	return c.LookupContext(ctx, target)
}

// LookupIP queries a single IP address using DefaultClient().
func LookupIP(ip net.IP) (Result, error) {
	c, err := DefaultClient()
	if err != nil {
		return Result{}, err
	}
	return c.LookupIP(ip)
}

// LookupASN queries an Autonomous System number using DefaultClient().
func LookupASN(asn uint32) (Result, error) {
	c, err := DefaultClient()
	if err != nil {
		return Result{}, err
	}
	return c.LookupASN(asn)
}
