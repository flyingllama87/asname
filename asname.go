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
		contact := sources.NewContactAsker(cfg.ContactPath, opts.ContactEmail)
		if err := sources.AutoUpdate(cfg, opts.AutoUpdate, wantCity, wantNetblock, wantCategory, contact); err != nil {
			return nil, fmt.Errorf("asname: auto-update failed: %w", err)
		}
	}

	eng, err := engine.NewEngine(cfg, wantCity, wantNetblock, showNetblock, wantCategory, whoisMode)
	if err != nil {
		return nil, err
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
		rawResults, err := c.eng.LookupTarget(t)
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
		engine.ResolveReverseDNS(context.Background(), results)
		raw = results[0]
	}
	return resultFromEngine(raw), nil
}

// LookupASN looks up details for an Autonomous System by number (e.g. 15169).
func (c *Client) LookupASN(asn uint32) (Result, error) {
	return c.LookupASNContext(context.Background(), asn)
}

// LookupASNContext looks up an Autonomous System by number, respecting ctx for online prefix queries if not cached.
func (c *Client) LookupASNContext(ctx context.Context, asn uint32) (Result, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return Result{}, ErrClosed
	}

	raw, err := c.eng.LookupASN(asn)
	if err != nil {
		return Result{}, err
	}
	return resultFromEngine(raw), nil
}

// SearchNetblocks searches the registry netblock database by organization name or netname.
func (c *Client) SearchNetblocks(query string, opts SearchOptions) ([]NetblockResult, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return nil, ErrClosed
	}

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
