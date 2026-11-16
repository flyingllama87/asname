package sources

import (
	"bytes"
	"strings"
	"unicode"
	"unicode/utf8"
)

// How a name matched a search, best first. A plain search finds MatchExact
// alone; a fuzzy one also finds MatchCompact and MatchWords.
const (
	MatchNone = iota
	// MatchExact: the name contains the query, ignoring case.
	MatchExact
	// MatchCompact: it does once spaces and punctuation are dropped from
	// both, so "colo crossing" finds COLOCROSSING and "amazon 02" AMAZON-02.
	MatchCompact
	// MatchWords: every word of the query, in any order, starts a word of
	// the name, with company suffixes (Inc, Ltd, GmbH...) left out and
	// common abbreviations (Univ, Dept, Intl...) standing for the words
	// they shorten. Matching only at the start of a word keeps "deutsche"
	// from finding "mitteldeutsche", and a number matches only a whole
	// number, so "level 3" does not find "Level 23".
	MatchWords
)

// MatchName is the name a JSON result gives a Match value.
func MatchName(m int) string {
	switch m {
	case MatchExact:
		return "exact"
	case MatchCompact:
		return "compact"
	case MatchWords:
		return "words"
	}
	return ""
}

// companySuffixes and filler words carry no signal: registrations of the
// same organisation differ in them.
var nameStopWords = map[string]bool{
	"inc": true, "incorporated": true, "llc": true, "ltd": true, "limited": true, "gmbh": true, "mbh": true,
	"srl": true, "sa": true, "sas": true, "sarl": true, "bv": true, "nv": true, "pty": true, "corp": true,
	"corporation": true, "co": true, "company": true, "ag": true, "plc": true, "oy": true, "ab": true,
	"spa": true, "sro": true, "kft": true, "doo": true, "jsc": true, "ooo": true, "llp": true, "lp": true,
	"the": true, "of": true, "and": true, "for": true, "de": true, "der": true, "la": true, "le": true,
}

// nameSynonyms are spellings that stand for each other in registry names.
var nameSynonyms = [][]string{
	{"univ", "university", "universidad", "universidade", "universitat", "universite", "universita"},
	{"dept", "department"},
	{"intl", "international"},
	{"telecom", "telecommunications", "telecommunication", "telekom", "telecomunicacoes", "telecomunicaciones"},
	{"govt", "government"},
	{"natl", "national"},
	{"tech", "technology", "technologies"},
	{"svc", "svcs", "service", "services"},
	{"comm", "comms", "communication", "communications"},
	{"net", "network", "networks"},
	{"assn", "association"},
	{"inst", "institute"},
}

// NameMatcher ranks how well registry names match a search query.
type NameMatcher struct {
	exact   foldMatcher
	fuzzy   bool
	compact []byte     // the query, lower-cased, letters and digits only
	words   [][][]byte // each query word's spellings, lower-cased
	buf     []byte
	starts  []int
}

// NewNameMatcher prepares query. Without fuzzy it finds MatchExact alone,
// as asname always has.
func NewNameMatcher(query string, fuzzy bool) *NameMatcher {
	m := &NameMatcher{exact: newFoldMatcher(query), fuzzy: fuzzy}
	if !fuzzy {
		return m
	}
	m.compact, _ = compactName([]byte(query), nil, nil)
	for _, w := range splitQueryWords(query) {
		if nameStopWords[w] {
			continue
		}
		spellings := [][]byte{[]byte(w)}
		for _, group := range nameSynonyms {
			if containsString(group, w) {
				spellings = spellings[:0]
				for _, s := range group {
					spellings = append(spellings, []byte(s))
				}
				break
			}
		}
		m.words = append(m.words, spellings)
	}
	return m
}

// Rank reports how name matches, or MatchNone. A NameMatcher is not safe
// for concurrent use.
func (m *NameMatcher) Rank(name []byte) int {
	if m.exact.match(name) {
		return MatchExact
	}
	if !m.fuzzy || len(m.compact) == 0 {
		return MatchNone
	}
	ascii := isASCII(name)
	if ascii {
		m.buf = compactLowerASCII(name, m.buf[:0])
	} else {
		m.buf, m.starts = compactName(name, m.buf[:0], m.starts[:0])
	}
	if containsWhole(m.buf, m.compact) {
		return MatchCompact
	}
	if len(m.words) == 0 {
		return MatchNone
	}
	// Every word must appear somewhere before it is worth finding where
	// the name's words start; nearly every name fails here.
	for _, spellings := range m.words {
		found := false
		for _, s := range spellings {
			if bytes.Contains(m.buf, s) {
				found = true
				break
			}
		}
		if !found {
			return MatchNone
		}
	}
	if ascii {
		m.buf, m.starts = compactASCII(name, m.buf[:0], m.starts[:0])
	}
	for _, spellings := range m.words {
		found := false
		for _, s := range spellings {
			if startsWord(m.buf, m.starts, s) {
				found = true
				break
			}
		}
		if !found {
			return MatchNone
		}
	}
	return MatchWords
}

// compactName lower-cases s and keeps only its letters and digits, appending
// to buf; starts gets the index in it of each word's first character. A
// word starts after a space or punctuation, at a lower-to-upper case change
// ("DigitalOcean") and where letters meet digits ("Level3").
func compactName(s []byte, buf []byte, starts []int) ([]byte, []int) {
	if isASCII(s) {
		return compactASCII(s, buf, starts)
	}
	var prev rune = ' '
	for len(s) > 0 {
		r, size := rune(s[0]), 1
		if r >= utf8.RuneSelf {
			r, size = utf8.DecodeRune(s)
		}
		s = s[size:]
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			prev = ' '
			continue
		}
		if prev == ' ' || (unicode.IsLower(prev) && unicode.IsUpper(r)) || unicode.IsDigit(prev) != unicode.IsDigit(r) {
			starts = append(starts, len(buf))
		}
		prev = r
		buf = utf8.AppendRune(buf, unicode.ToLower(r))
	}
	return buf, starts
}

// startsWord reports whether w begins at one of the word starts in c. A
// number must end there too: "3" is not the start of "365".
func startsWord(c []byte, starts []int, w []byte) bool {
	digits := len(w) > 0 && isDigit(w[len(w)-1])
	for _, i := range starts {
		if !bytes.HasPrefix(c[i:], w) {
			continue
		}
		if digits {
			if j := i + len(w); j < len(c) && isDigit(c[j]) {
				continue
			}
		}
		return true
	}
	return false
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

// containsWhole reports whether c contains q without splitting a number: a
// q ending in a digit may not be followed by one ("level3" is not in
// "level365"), nor one starting with a digit preceded by one.
func containsWhole(c, q []byte) bool {
	if len(q) == 0 {
		return false
	}
	headDigit, tailDigit := isDigit(q[0]), isDigit(q[len(q)-1])
	for off := 0; ; {
		i := bytes.Index(c[off:], q)
		if i < 0 {
			return false
		}
		i += off
		end := i + len(q)
		if !(headDigit && i > 0 && isDigit(c[i-1])) && !(tailDigit && end < len(c) && isDigit(c[end])) {
			return true
		}
		off = i + 1
	}
}

// asciiFold maps an ASCII letter or digit to its lower case, and anything
// else to 0.
var asciiFold = func() (t [128]byte) {
	for c := byte('0'); c <= '9'; c++ {
		t[c] = c
	}
	for c := byte('a'); c <= 'z'; c++ {
		t[c] = c
		t[c-'a'+'A'] = c
	}
	return
}()

// compactLowerASCII appends the letters and digits of ASCII s, lower-cased.
func compactLowerASCII(s []byte, buf []byte) []byte {
	for _, c := range s {
		if f := asciiFold[c&0x7f]; f != 0 {
			buf = append(buf, f)
		}
	}
	return buf
}

func isASCII(s []byte) bool {
	for _, c := range s {
		if c >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// compactASCII is compactName for ASCII, which nearly every registry name
// is; it avoids decoding runes for each of the netblock database's millions
// of strings.
func compactASCII(s []byte, buf []byte, starts []int) ([]byte, []int) {
	const (
		other = iota
		lower
		upper
		digit
	)
	prev := other
	for _, c := range s {
		var class int
		switch {
		case 'a' <= c && c <= 'z':
			class = lower
		case 'A' <= c && c <= 'Z':
			class = upper
			c += 'a' - 'A'
		case '0' <= c && c <= '9':
			class = digit
		default:
			prev = other
			continue
		}
		if prev == other || (prev == lower && class == upper) || (prev == digit) != (class == digit) {
			starts = append(starts, len(buf))
		}
		prev = class
		buf = append(buf, c)
	}
	return buf, starts
}

// splitQueryWords splits a query into lower-cased words of letters and
// digits, breaking where compactName starts a word.
func splitQueryWords(q string) []string {
	c, starts := compactName([]byte(q), nil, nil)
	words := make([]string, 0, len(starts))
	for i, s := range starts {
		end := len(c)
		if i+1 < len(starts) {
			end = starts[i+1]
		}
		words = append(words, string(c[s:end]))
	}
	return words
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}
