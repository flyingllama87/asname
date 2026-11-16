package sources

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/flyingllama87/asname/pkg/database"
)

// GeofeedSourceName names the networks' own geofeeds among the sources.
const GeofeedSourceName = "Network geofeeds"

const (
	// geofeedWorkers is how many feeds are fetched at once. A host's feeds
	// are fetched one after another, or over geofeedHostConns connections
	// for a host serving many, so no network gets more than that from asname.
	geofeedWorkers = 64
	// geofeedTimeout bounds one feed's download.
	geofeedTimeout = 60 * time.Second
	// maxGeofeedSize bounds one feed; the largest real ones are a few MB.
	maxGeofeedSize = 64 << 20
	// geofeedHostMisses is how many failures in a row give up on a host.
	geofeedHostMisses = 3
	// geofeedHostConns is how many connections a host serving many feeds
	// gets at once.
	geofeedHostConns = 4
)

// geofeedHTTPClient fetches the feeds; tests replace it.
var geofeedHTTPClient = &http.Client{Timeout: geofeedTimeout, CheckRedirect: geofeedRedirect}

func geofeedRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return fmt.Errorf("stopped after %d redirects", len(via))
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect to %s", req.URL.Redacted())
	}
	return nil
}

// span is a run of addresses start..end with a value: a feed's index, or a
// location's.
type span[K any] struct {
	start, end K
	id         uint32
}

// family holds what Flatten and the spans need for one address family.
type family[K any] struct {
	cmp  func(a, b K) int
	inc  func(K) (K, bool)
	dec  func(K) K
	max  K
	from func(netip.Addr) K
	to   func(K) netip.Addr
}

var (
	fam4 = family[uint32]{
		cmp: CompareUint32, inc: IncUint32, dec: func(v uint32) uint32 { return v - 1 }, max: ^uint32(0),
		from: addrUint32,
		to:   addr4,
	}
	fam6 = family[[16]byte]{
		cmp: CompareBytes16, inc: IncBytes16, dec: decBytes16,
		max:  [16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		from: func(a netip.Addr) [16]byte { return a.As16() },
		to:   netip.AddrFrom16,
	}
)

// spans flattens nested intervals, the most specific winning, into disjoint
// runs with a non-zero id.
func (f family[K]) spans(ivs []interval[K]) []span[K] {
	segs := Flatten(ivs, f.cmp, f.inc)
	out := make([]span[K], 0, len(segs))
	for i, s := range segs {
		if s.Netname == 0 {
			continue
		}
		end := f.max
		if i+1 < len(segs) {
			end = f.dec(segs[i+1].Start)
		}
		out = append(out, span[K]{start: s.Start, end: end, id: s.Netname})
	}
	return out
}

// clip keeps the parts of feed (a feed's own entries, disjoint and sorted)
// inside auth (the ranges for which that feed is authoritative, disjoint and
// sorted).
func (f family[K]) clip(feed, auth []span[K]) []span[K] {
	var out []span[K]
	i, j := 0, 0
	for i < len(feed) && j < len(auth) {
		a, b := feed[i], auth[j]
		lo, hi := a.start, a.end
		if f.cmp(b.start, lo) > 0 {
			lo = b.start
		}
		if f.cmp(b.end, hi) < 0 {
			hi = b.end
		}
		if f.cmp(lo, hi) <= 0 {
			out = append(out, span[K]{start: lo, end: hi, id: a.id})
		}
		if f.cmp(a.end, b.end) < 0 {
			i++
		} else {
			j++
		}
	}
	return out
}

func (f family[K]) size(s []span[K]) uint64 {
	var n uint64
	for _, x := range s {
		if v, ok := any(x.start).(uint32); ok {
			n += uint64(any(x.end).(uint32)-v) + 1
		}
	}
	return n
}

// geofeedResult is one fetched and parsed feed.
type geofeedResult struct {
	id      uint32
	entries []geofeedEntry
	bad     int
	err     error
}

// UpdateGeofeedDB fetches the geofeed every registry range names (as the
// netblock update recorded them), keeps each feed's entries for the
// addresses inside the ranges that name it, the most specific range
// deciding, and atomically replaces cfg.GeofeedPath.
func UpdateGeofeedDB(ctx context.Context, cfg Config) (err error) {
	if cfg.GeofeedPath == "" {
		return fmt.Errorf("no geofeed database path")
	}
	ctx, done := beginUpdate(ctx, cfg, KeyGeofeed)
	defer func() { done(err) }()

	refsPath := GeofeedRefsPath(cfg.NetblockPath)
	refs, err := readGeofeedRefs(refsPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("no geofeed references next to the netblock database; rebuild it first with `asname update --netblock-only`")
	}
	if err != nil {
		return err
	}
	logf(ctx, "asname: building IP->geofeed database from the networks' own RFC 8805 geofeeds\n")

	urls := []string{""}
	urlID := map[string]uint32{}
	var ivs4 []interval[uint32]
	var ivs6 []interval[[16]byte]
	for _, r := range refs {
		id, ok := urlID[r.URL]
		if !ok {
			id = uint32(len(urls))
			urls = append(urls, r.URL)
			urlID[r.URL] = id
		}
		if r.Start.Is4() {
			ivs4 = append(ivs4, interval[uint32]{start: fam4.from(r.Start), end: fam4.from(r.End), netname: id})
		} else {
			ivs6 = append(ivs6, interval[[16]byte]{start: fam6.from(r.Start), end: fam6.from(r.End), netname: id})
		}
	}
	refs = nil

	// Where ranges nest, the most specific one naming a feed decides which
	// feed speaks for its addresses (RFC 9092, section 4).
	auth4 := map[uint32][]span[uint32]{}
	for _, s := range fam4.spans(ivs4) {
		auth4[s.id] = append(auth4[s.id], s)
	}
	auth6 := map[uint32][]span[[16]byte]{}
	for _, s := range fam6.spans(ivs6) {
		auth6[s.id] = append(auth6[s.id], s)
	}
	ivs4, ivs6 = nil, nil

	byHost := map[string][]uint32{}
	feeds := 0
	for id := uint32(1); id < uint32(len(urls)); id++ {
		if len(auth4[id]) == 0 && len(auth6[id]) == 0 {
			continue // every range naming it has a more specific one naming another
		}
		u, perr := url.Parse(urls[id])
		if perr != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		byHost[host] = append(byHost[host], id)
		feeds++
	}
	logf(ctx, "asname: %d geofeeds on %d hosts, named by %d registry ranges\n", feeds, len(byHost), len(urlID))

	results := make(chan geofeedResult, geofeedWorkers)
	type hostJob struct {
		gate *hostGate
		ids  []uint32
	}
	hosts := make(chan hostJob)
	var wg sync.WaitGroup
	for range geofeedWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range hosts {
				for _, id := range job.ids {
					if ctx.Err() != nil {
						return
					}
					entries, bad, err := job.gate.fetch(ctx, urls[id])
					results <- geofeedResult{id: id, entries: entries, bad: bad, err: err}
				}
			}
		}()
	}
	go func() {
		defer close(hosts)
		// The hosts with most feeds start first, so they do not finish last.
		order := make([]string, 0, len(byHost))
		for h := range byHost {
			order = append(order, h)
		}
		sort.Slice(order, func(i, j int) bool {
			if len(byHost[order[i]]) != len(byHost[order[j]]) {
				return len(byHost[order[i]]) > len(byHost[order[j]])
			}
			return order[i] < order[j]
		})
		for _, h := range order {
			// A host with many feeds gets a few connections, not one, so
			// it does not hold up the end of the update.
			ids := byHost[h]
			gate := &hostGate{}
			parts := 1
			if len(ids) > 40 {
				parts = geofeedHostConns
			}
			for p := range parts {
				var chunk []uint32
				for i := p; i < len(ids); i += parts {
					chunk = append(chunk, ids[i])
				}
				select {
				case hosts <- hostJob{gate: gate, ids: chunk}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	locs := []string{""}
	locID := map[string]uint32{}
	var out4 []span[uint32]
	var out6 []span[[16]byte]
	var read, failed, entries, outside, bad int
	reasons := map[string]int{}
	for res := range results {
		if res.err != nil {
			failed++
			reasons[geofeedFailure(res.err)]++
			continue
		}
		read++
		bad += res.bad
		// Locations are numbered within the feed first, and only those
		// left after clipping join the database's list.
		var local []string
		localID := map[string]uint32{}
		var feed4 []interval[uint32]
		var feed6 []interval[[16]byte]
		for _, e := range res.entries {
			var id uint32
			if e.Country != "" {
				key := GeofeedLocation{Country: e.Country, Region: e.Region, City: e.City, Feed: urls[res.id]}.encode()
				var ok bool
				if id, ok = localID[key]; !ok {
					local = append(local, key)
					id = uint32(len(local))
					localID[key] = id
				}
			}
			first, last := e.Prefix.Addr(), lastAddr(e.Prefix)
			if first.Is4() {
				feed4 = append(feed4, interval[uint32]{start: fam4.from(first), end: fam4.from(last), netname: id})
			} else {
				feed6 = append(feed6, interval[[16]byte]{start: fam6.from(first), end: fam6.from(last), netname: id})
			}
		}
		global := func(id uint32) uint32 {
			key := local[id-1]
			g, ok := locID[key]
			if !ok {
				g = uint32(len(locs))
				locs = append(locs, key)
				locID[key] = g
			}
			return g
		}
		in4 := fam4.clip(fam4.spans(feed4), auth4[res.id])
		in6 := fam6.clip(fam6.spans(feed6), auth6[res.id])
		entries += len(res.entries)
		if len(res.entries) > 0 && len(in4) == 0 && len(in6) == 0 {
			outside++
		}
		for _, x := range in4 {
			x.id = global(x.id)
			out4 = append(out4, x)
		}
		for _, x := range in6 {
			x.id = global(x.id)
			out6 = append(out6, x)
		}
		if (read+failed)%500 == 0 {
			logf(ctx, "asname: geofeeds: %d of %d fetched (%d failed)\n", read+failed, feeds, failed)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if read == 0 {
		noteFailed(ctx, GeofeedSourceName)
		return fmt.Errorf("none of the %d geofeeds could be fetched", feeds)
	}

	data, prefixes, err := marshalGeofeed(out4, out6, locs)
	if err != nil {
		return err
	}
	if err := WriteFileAtomic(cfg.GeofeedPath, data); err != nil {
		return err
	}
	if failed > 0 {
		var parts []string
		for _, r := range sortedKeysByCount(reasons) {
			parts = append(parts, fmt.Sprintf("%d %s", reasons[r], r))
		}
		logf(ctx, "asname: geofeeds that failed: %s\n", strings.Join(parts, ", "))
	}
	note := fmt.Sprintf("%d of %d feeds read; %d unreachable or invalid", read, feeds, failed)
	if outside > 0 {
		note += fmt.Sprintf("; %d placed no address inside the ranges naming them", outside)
	}
	noteSource(ctx, GeofeedSourceName, prefixes, note)
	logf(ctx, "asname: geofeeds: %s; %d entries (%d malformed lines skipped)\n", note, entries, bad)
	logf(ctx, "asname: wrote %s (%d prefixes, %d IPv4 addresses, %d places, %d bytes)\n",
		cfg.GeofeedPath, prefixes, fam4.size(out4), len(locs)-1, len(data))
	return nil
}

// fetchGeofeed downloads and parses one feed.
func fetchGeofeed(ctx context.Context, feedURL string) ([]geofeedEntry, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", defaultUserAgent())
	req.Header.Set("Accept", "text/csv, text/plain;q=0.9, */*;q=0.5")
	resp, err := geofeedHTTPClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		wait, _ := retryAfter(resp.Header.Get("Retry-After"))
		return nil, 0, &slowDownError{status: resp.Status, wait: wait}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("GET %s: %s", feedURL, resp.Status)
	}
	body := io.LimitReader(resp.Body, maxGeofeedSize+1)
	cr := &countingReader{r: body}
	entries, bad, err := parseGeofeed(cr)
	if err != nil {
		return nil, 0, err
	}
	if cr.n > maxGeofeedSize {
		return nil, 0, errors.New("feed too large")
	}
	// An HTML page or other non-feed parses to nothing but bad lines.
	if len(entries) == 0 && bad > 0 {
		return nil, bad, errors.New("not a geofeed")
	}
	return entries, bad, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// lastAddr is the last address in p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// marshalGeofeed encodes the database: magic, the length of a prefix table,
// the table (each prefix maps to an index into the locations), the number of
// locations, and the locations, NUL-terminated. It returns how many prefixes
// the table holds.
func marshalGeofeed(out4 []span[uint32], out6 []span[[16]byte], locs []string) ([]byte, int, error) {
	trie := database.NewBuilder()
	n := 0
	insert := func(start, end netip.Addr, id uint32) error {
		for _, p := range rangeCIDRs(start, end) {
			ipNet := &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
			if err := trie.InsertMapping(ipNet, id); err != nil {
				return fmt.Errorf("inserting %s: %v", p, err)
			}
			n++
		}
		return nil
	}
	for _, s := range out4 {
		if err := insert(fam4.to(s.start), fam4.to(s.end), s.id); err != nil {
			return nil, 0, err
		}
	}
	for _, s := range out6 {
		if err := insert(fam6.to(s.start), fam6.to(s.end), s.id); err != nil {
			return nil, 0, err
		}
	}
	var trieBytes []byte
	if n > 0 {
		trie.SetFillFactor(OptimizationFillFactor)
		built, err := trie.Build()
		if err != nil {
			return nil, 0, fmt.Errorf("building prefix table: %v", err)
		}
		if trieBytes, err = built.MarshalBinary(); err != nil {
			return nil, 0, err
		}
	}
	data := append([]byte(geofeedMagic), make([]byte, 8)...)
	binary.LittleEndian.PutUint64(data[8:16], uint64(len(trieBytes)))
	data = append(data, trieBytes...)
	data = binary.LittleEndian.AppendUint32(data, uint32(len(locs)-1))
	for _, l := range locs[1:] {
		data = append(data, l...)
		data = append(data, 0)
	}
	return data, n, nil
}

// geofeedFailure sorts a failed fetch into a few kinds for the log.
func geofeedFailure(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "host unreachable"):
		return "skipped (host failing)"
	case strings.Contains(msg, "not a geofeed"):
		return "not a geofeed"
	case strings.Contains(msg, "no such host"):
		return "no DNS"
	case strings.Contains(msg, "deadline") || strings.Contains(msg, "Timeout") || strings.Contains(msg, "timeout"):
		return "timed out"
	case strings.Contains(msg, "certificate") || strings.Contains(msg, "x509") || strings.Contains(msg, "tls"):
		return "TLS error"
	case strings.Contains(msg, "refused"):
		return "connection refused"
	case strings.Contains(msg, "429"):
		return "rate limited (429)"
	case strings.Contains(msg, ": 4") || strings.Contains(msg, ": 5"):
		if i := strings.LastIndex(msg, ": "); i >= 0 && len(msg) >= i+5 {
			return "HTTP " + msg[i+2:i+5]
		}
		return "HTTP error"
	default:
		return "other"
	}
}

func sortedKeysByCount(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}

// slowDownError is a host asking asname to come back later (429 or 503).
type slowDownError struct {
	status string
	wait   time.Duration
}

func (e *slowDownError) Error() string { return e.status }

const (
	// geofeedAttempts is how often one feed is tried when its host asks
	// asname to slow down or drops the connection.
	geofeedAttempts = 3
	// geofeedMaxGap bounds the pause between requests to a slow host, and
	// geofeedMaxWait a single Retry-After.
	geofeedMaxGap  = 5 * time.Second
	geofeedMaxWait = 30 * time.Second
)

// hostGate paces the requests to one host across the connections fetching
// its feeds. It starts unpaced; a 429, 503 or dropped connection widens the
// gap between requests, and a host that keeps failing at that pace is
// given up on.
type hostGate struct {
	mu     sync.Mutex
	next   time.Time
	gap    time.Duration
	misses int
}

// fetch fetches one feed through the gate.
func (g *hostGate) fetch(ctx context.Context, feedURL string) ([]geofeedEntry, int, error) {
	var err error
	for attempt := 1; attempt <= geofeedAttempts; attempt++ {
		if g.down() {
			return nil, 0, errors.New("host unreachable")
		}
		if werr := g.wait(ctx); werr != nil {
			return nil, 0, werr
		}
		var entries []geofeedEntry
		var bad int
		entries, bad, err = fetchGeofeed(ctx, feedURL)
		var slow *slowDownError
		var uerr *url.Error
		switch {
		case err == nil:
			g.reached()
			return entries, bad, nil
		case ctx.Err() != nil:
			return nil, 0, ctx.Err()
		case errors.As(err, &slow):
			g.slowDown(slow.wait)
		case errors.As(err, &uerr):
			// Dropped or refused: perhaps too many at once, perhaps down.
			g.slowDown(0)
		default:
			// A 404 or a bad file: the host is up, the feed is not.
			g.reached()
			return nil, bad, err
		}
	}
	var slow *slowDownError
	if !errors.As(err, &slow) {
		g.missed()
	}
	return nil, 0, err
}

// wait blocks until this request's turn.
func (g *hostGate) wait(ctx context.Context) error {
	g.mu.Lock()
	now := time.Now()
	at := g.next
	if at.Before(now) {
		at = now
	}
	g.next = at.Add(g.gap)
	g.mu.Unlock()
	if d := time.Until(at); d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	return nil
}

func (g *hostGate) slowDown(wait time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gap = min(max(2*g.gap, time.Second), geofeedMaxGap)
	wait = min(max(wait, g.gap), geofeedMaxWait)
	if at := time.Now().Add(wait); at.After(g.next) {
		g.next = at
	}
}

func (g *hostGate) reached() {
	g.mu.Lock()
	g.misses = 0
	g.mu.Unlock()
}

func (g *hostGate) missed() {
	g.mu.Lock()
	g.misses++
	g.mu.Unlock()
}

func (g *hostGate) down() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.misses >= geofeedHostMisses
}
