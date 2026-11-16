package rest

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/flyingllama87/asname/internal/engine"
	"github.com/flyingllama87/asname/internal/format"
)

// exploreOptions reads /v1/explore's query parameters.
func exploreOptions(r *http.Request) (engine.ExploreOptions, error) {
	q := r.URL.Query()
	var o engine.ExploreOptions
	num := func(name string, dst *int, lo, hi int) error {
		v := strings.TrimSpace(q.Get(name))
		if v == "" {
			return nil
		}
		n, err := strconv.Atoi(strings.TrimPrefix(v, "/"))
		if err != nil || n < lo || n > hi {
			return fmt.Errorf("%s must be a number from %d to %d", name, lo, hi)
		}
		*dst = n
		return nil
	}
	if v := strings.TrimSpace(q.Get("len")); v != "" {
		// "8", "/8", "16-24".
		a, b, rng := strings.Cut(strings.ReplaceAll(v, "/", ""), "-")
		lo, err1 := strconv.Atoi(strings.TrimSpace(a))
		hi, err2 := lo, error(nil)
		if rng {
			hi, err2 = strconv.Atoi(strings.TrimSpace(b))
		}
		if err1 != nil || err2 != nil || lo < 0 || hi > 128 || lo > hi {
			return o, fmt.Errorf("len must be a prefix length such as 8 or a range such as 16-24")
		}
		o.MinLen, o.MaxLen = lo, hi
	}
	for _, f := range []struct {
		name   string
		dst    *int
		lo, hi int
	}{{"min_len", &o.MinLen, 0, 128}, {"max_len", &o.MaxLen, 0, 128}, {"min_ipsum", &o.MinIPsum, 0, 255}, {"limit", &o.Limit, 0, 100000}, {"offset", &o.Offset, 0, 1 << 30}} {
		if err := num(f.name, f.dst, f.lo, f.hi); err != nil {
			return o, err
		}
	}
	if q.Get("limit") == "" {
		o.Limit = 500
	}
	switch q.Get("family") {
	case "", "any":
	case "v4", "4", "ipv4":
		o.V4Only = true
	case "v6", "6", "ipv6":
		o.V6Only = true
	default:
		return o, fmt.Errorf("family must be v4 or v6")
	}
	var err error
	if o.Country, err = searchCountry(q.Get("country")); err != nil {
		return o, err
	}
	if o.ASCountry, err = searchCountry(q.Get("as_country")); err != nil {
		return o, err
	}
	if v := strings.TrimSpace(q.Get("asn")); v != "" {
		n, ok := engine.ParseASNTarget(v)
		if !ok {
			return o, fmt.Errorf("asn must be an AS number such as AS13335")
		}
		o.ASN = n
	}
	for _, t := range q["tag"] {
		for _, x := range strings.Split(t, ",") {
			if x = strings.TrimSpace(x); x != "" {
				o.Tags = append(o.Tags, x)
			}
		}
	}
	o.Reputation = q.Get("reputation")
	if !engine.ValidExploreReputation(o.Reputation) {
		return o, fmt.Errorf("reputation must be listed, clean, drop, drop-inside, asn-drop, firehol2 or firehol3")
	}
	if v := q.Get("min_listed_pct"); v != "" {
		if o.MinListedPct, err = strconv.ParseFloat(v, 64); err != nil || o.MinListedPct < 0 {
			return o, fmt.Errorf("min_listed_pct must be a percentage")
		}
	}
	switch o.Sort = q.Get("sort"); o.Sort {
	case "", "address", "size", "listed", "share":
	default:
		return o, fmt.Errorf("sort must be address, size, listed or share")
	}
	return o, nil
}

func (s *Server) handleExplore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed, use GET")
		return
	}
	opts, err := exploreOptions(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	// limit=0 asks only for the count and the breakdown; the engine reads
	// 0 as no limit, which would be a million rows.
	countOnly := opts.Limit == 0
	if countOnly {
		opts.Limit, opts.Offset = 1, 0
	}
	res, err := s.engine().Explore(opts)
	if countOnly {
		res.Prefixes = nil
	}
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	out := format.NewJSONExplore(res, opts.Offset)
	writeJSON(w, http.StatusOK, out)
}
