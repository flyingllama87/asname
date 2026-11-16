package sources

import (
	_ "embed"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"
)

//go:embed inferrules.yaml
var inferRulesYAML []byte

// Where an inferred tag came from.
const (
	InferredFromName = "name" // a word in the AS's registered name
	InferredFromList = "list" // asname's list of networks whose names do not say
)

// InferredTags are the tags asname's own rules give an AS.
type InferredTags struct {
	Tags []string
	// From is InferredFromName or InferredFromList.
	From string
}

// InferRules says what kind of network an AS is from its registered name, or
// from a short list of well-known networks; see inferrules.yaml.
type InferRules struct {
	groups   map[string]*regexp.Regexp
	kinds    []inferRule
	services []inferRule
	asns     map[uint32]curatedASN
}

type inferRule struct {
	Tag      string   `yaml:"tag"`
	Match    []string `yaml:"match"`
	Not      []string `yaml:"not"`
	NotKinds []string `yaml:"not_kinds"`
	NoKind   bool     `yaml:"no_kind"`
}

type curatedASN struct {
	tags   []string
	expect *regexp.Regexp
}

var (
	inferOnce  sync.Once
	inferRules *InferRules
	inferErr   error
)

// DefaultInferRules returns the rules built into asname.
func DefaultInferRules() (*InferRules, error) {
	inferOnce.Do(func() { inferRules, inferErr = ParseInferRules(inferRulesYAML) })
	return inferRules, inferErr
}

// ParseInferRules reads rules in the inferrules.yaml format.
func ParseInferRules(data []byte) (*InferRules, error) {
	var raw struct {
		Words    map[string][]string `yaml:"words"`
		Kinds    []inferRule         `yaml:"kinds"`
		Services []inferRule         `yaml:"services"`
		ASNs     []struct {
			ASN    uint32   `yaml:"asn"`
			Tags   []string `yaml:"tags"`
			Expect string   `yaml:"expect"`
		} `yaml:"asns"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("inference rules: %v", err)
	}
	r := &InferRules{groups: map[string]*regexp.Regexp{}, kinds: raw.Kinds, services: raw.Services, asns: map[uint32]curatedASN{}}
	for name, words := range raw.Words {
		re, err := wordsRegexp(words)
		if err != nil {
			return nil, fmt.Errorf("inference rules: words %q: %v", name, err)
		}
		r.groups[name] = re
	}
	for _, rule := range append(append([]inferRule{}, raw.Kinds...), raw.Services...) {
		if rule.Tag == "" || len(rule.Match) == 0 {
			return nil, fmt.Errorf("inference rules: a rule needs a tag and match")
		}
		for _, g := range append(append([]string{}, rule.Match...), rule.Not...) {
			if r.groups[g] == nil {
				return nil, fmt.Errorf("inference rules: rule %q names unknown words %q", rule.Tag, g)
			}
		}
	}
	for _, a := range raw.ASNs {
		if a.ASN == 0 || len(a.Tags) == 0 || a.Expect == "" {
			return nil, fmt.Errorf("inference rules: AS%d needs tags and expect", a.ASN)
		}
		if _, dup := r.asns[a.ASN]; dup {
			return nil, fmt.Errorf("inference rules: AS%d is listed twice", a.ASN)
		}
		re, err := regexp.Compile("(?i)" + a.Expect)
		if err != nil {
			return nil, fmt.Errorf("inference rules: AS%d expect: %v", a.ASN, err)
		}
		r.asns[a.ASN] = curatedASN{tags: a.Tags, expect: re}
	}
	return r, nil
}

// wordsRegexp matches any of words as a whole word, case-insensitively. A
// trailing * matches any further letters or digits; a space matches any run
// of whitespace, hyphens or underscores.
func wordsRegexp(words []string) (*regexp.Regexp, error) {
	alts := make([]string, 0, len(words))
	for _, w := range words {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		suffix := ""
		if strings.HasSuffix(w, "*") {
			w, suffix = strings.TrimSuffix(w, "*"), `[\p{L}\p{N}]*`
		}
		parts := strings.Fields(w)
		for i, p := range parts {
			parts[i] = regexp.QuoteMeta(p)
		}
		alts = append(alts, strings.Join(parts, `[\s\-_]+`)+suffix)
	}
	if len(alts) == 0 {
		return nil, fmt.Errorf("no words")
	}
	return regexp.Compile(`(?i)(?:^|[^\p{L}\p{N}])(?:` + strings.Join(alts, "|") + `)(?:$|[^\p{L}\p{N}])`)
}

// Infer returns the tags the rules give asn, whose registered name (as the
// AS names list has it, "HANDLE - Organisation, CC") is name. The curated
// list wins over the name rules when the name still matches its entry.
func (r *InferRules) Infer(asn uint32, name string) InferredTags {
	if c, ok := r.asns[asn]; ok && c.expect.MatchString(name) {
		return InferredTags{Tags: sortedTags(c.tags), From: InferredFromList}
	}
	org := asnOrganisation(name)
	if org == "" {
		return InferredTags{}
	}
	var tags []string
	kind := ""
	for _, rule := range r.kinds {
		if r.applies(rule, org) {
			kind = rule.Tag
			tags = append(tags, kind)
			break
		}
	}
	for _, rule := range r.services {
		if rule.NoKind && kind != "" {
			continue
		}
		if kind != "" && contains(rule.NotKinds, kind) {
			continue
		}
		if r.applies(rule, org) && !contains(tags, rule.Tag) {
			tags = append(tags, rule.Tag)
		}
	}
	if len(tags) == 0 {
		return InferredTags{}
	}
	return InferredTags{Tags: sortedTags(tags), From: InferredFromName}
}

func (r *InferRules) applies(rule inferRule, org string) bool {
	for _, g := range rule.Match {
		if !r.groups[g].MatchString(org) {
			return false
		}
	}
	for _, g := range rule.Not {
		if r.groups[g].MatchString(org) {
			return false
		}
	}
	return true
}

// asnOrganisation is the organisation part of an AS names entry: after
// " - " when there is one ("COMCAST-7922 - Comcast Cable Communications,
// LLC, US"), else after the handle ("HETZNER-AS Hetzner Online GmbH, DE"),
// without the trailing country code.
func asnOrganisation(name string) string {
	if i := strings.LastIndex(name, ", "); i >= 0 && len(name)-i == 4 {
		name = name[:i]
	}
	if _, org, ok := strings.Cut(name, " - "); ok {
		return strings.TrimSpace(org)
	}
	if _, org, ok := strings.Cut(name, " "); ok {
		return strings.TrimSpace(org)
	}
	return ""
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func sortedTags(tags []string) []string {
	out := append([]string(nil), tags...)
	sort.Strings(out)
	return out
}
