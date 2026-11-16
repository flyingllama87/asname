package sources

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInferRulesParse(t *testing.T) {
	r, err := DefaultInferRules()
	require.NoError(t, err)
	require.NotEmpty(t, r.kinds)
	require.NotEmpty(t, r.asns)
}

func TestInferFromNames(t *testing.T) {
	r, err := DefaultInferRules()
	require.NoError(t, err)
	cases := map[string][]string{
		// Real AS names list entries, each a case the rules had to get right.
		"KSU-KENNESAW-01 - Kennesaw State University, US":                                     {"education"},
		"AS53164 - UNIVERSIDADE FEDERAL DA BAHIA, BR":                                         {"education"},
		"KFU Kazan Federal University, RU":                                                    {"education"},
		"GECR-IN - Government Engineering College Rajkot, IN":                                 {"education"},
		"CITY-OF-WINNIPEG - City of Winnipeg, CA":                                             {"government"},
		"DEPHUB-AS-ID - Ministry of Transportation Republic of Indonesia, ID":                 {"government"},
		"PNP-AS-AP - Philippine National Police, PH":                                          {"government"},
		"PATELCOCU - Patelco Credit Union, US":                                                {"finance"},
		"SFCU-SITE1 - SchoolsFirst Federal Credit Union, US":                                  {"finance"},
		"BOF-AS Bank Of Finland, FI":                                                          {"finance"},
		"AS22055 - Banco Central do Brasil, BR":                                               {"finance", "government"},
		"NYP-INTERNET - NewYork-Presbyterian Hospital, US":                                    {"healthcare"},
		"Kazteleport-AS JSC Kazteleport - subsidiary of Halyk Bank of Kazakhstan, KZ":         nil,
		"AS270962 - NETICO TELECOMUNICACAO LTDA, BR":                                          {"isp"},
		"VBSPLTD-AS-IN - VEEONE BROADBAND SERVICES PRIVATE LIMITED, IN":                       {"isp"},
		"AS263498 - BERTONCELLO PROVEDOR DE INTERNET LTDA ME, BR":                             {"isp"},
		"AS274082 - ASOCIACION PARAGUAYA DE PROVEEDORES DE INTERNET Y TELECOMUNICACIONES, PY": nil,
		"Grant-Telecom-SPB-AS JSC \"Grant-Telecom\", RU":                                      {"isp"},
		"SVEA Svea Hosting AB, SE":                                                            {"hosting"},
		"WARSAW-DATA-CENTER-AS Warsaw Data Center Sp. z o.o., PL":                             {"hosting"},
		"NORTHWEST-REGIONAL-DATACENTER - Florida State University, US":                        {"education"},
		"ALTEL-AS Mobile Telecom-Service LLP, KZ":                                             {"isp", "mobile"},
		// Handles do not count: these enterprises name their own networks.
		"MUSA-COLO-01 - MURPHY OIL USA, INC, US":      nil,
		"CDK-GLOBAL-HOSTING-FB - CDK Global, LLC, US": nil,
		// Mobile needs a telecom context, and not biology.
		"CCAMPIT-AS - Centre For Cellular And Molecular Platforms, IN": nil,
		"AS61602 - HLP Mobile and Worldwide Tracking Ltda, BR":         nil,
		"ZeniMax-Germany ZeniMax Germany GmbH, DE":                     nil,
	}
	for name, want := range cases {
		got := r.Infer(1, name)
		require.Equal(t, want, got.Tags, name)
		if want != nil {
			require.Equal(t, InferredFromName, got.From, name)
		}
	}
}

func TestInferCuratedListChecksTheName(t *testing.T) {
	r, err := DefaultInferRules()
	require.NoError(t, err)
	got := r.Infer(21928, "T-MOBILE-AS21928 - T-Mobile USA, Inc., US")
	require.Equal(t, InferredTags{Tags: []string{"isp", "mobile"}, From: InferredFromList}, got)

	// The same number under another holder falls back to the name rules.
	got = r.Infer(21928, "EXAMPLE - Example Hosting Ltd, GB")
	require.Equal(t, InferredTags{Tags: []string{"hosting"}, From: InferredFromName}, got)
}

func TestWordsRegexp(t *testing.T) {
	re, err := wordsRegexp([]string{"universi*", "data center", "isp"})
	require.NoError(t, err)
	for _, s := range []string{"Universidad de Chile", "Universität Wien", "XYZ Data-Center", "Example ISP", "data  center"} {
		require.True(t, re.MatchString(s), s)
	}
	for _, s := range []string{"Bisping", "Dispatch", "metadata centers inc"} {
		require.False(t, re.MatchString(s), s)
	}
}

func TestParseInferRulesRejectsMistakes(t *testing.T) {
	_, err := ParseInferRules([]byte("words: {a: [x]}\nkinds: [{tag: t, match: [b]}]\n"))
	require.ErrorContains(t, err, "unknown words")
	_, err = ParseInferRules([]byte("words: {a: [x]}\nasns: [{asn: 1, tags: [isp], expect: A}, {asn: 1, tags: [isp], expect: B}]\n"))
	require.ErrorContains(t, err, "twice")
	_, err = ParseInferRules([]byte("asns: [{asn: 1, tags: [isp]}]\n"))
	require.ErrorContains(t, err, "expect")
}

// inferCompatible lists the reference tags (PeeringDB, bgp.tools) that agree
// with an inferred tag. PeeringDB has no finance or healthcare type; those
// organisations call themselves enterprise or non-profit.
var inferCompatible = map[string][]string{
	"isp":        {"isp", "mobile", "satellite", "transit"},
	"mobile":     {"mobile", "isp"},
	"hosting":    {"hosting", "content", "cdn", "network-services", "vpn"},
	"cdn":        {"cdn", "content", "hosting"},
	"education":  {"education"},
	"government": {"government"},
	"finance":    {"enterprise", "non-profit", "government"},
	"healthcare": {"enterprise", "non-profit", "education", "government"},
}

// TestInferRulesAgainstReference measures every inferred tag against the
// PeeringDB and bgp.tools tags of a real data directory. It runs only when
// ASNAME_INFER_EVAL names one (holding asn_db.txt and category.db):
//
//	ASNAME_INFER_EVAL=~/.asname go test ./internal/sources -run InferRules -v
//
// Agreement understates accuracy for hosting and isp: many data centres call
// themselves transit or ISP in PeeringDB. Disagreements are listed for review.
func TestInferRulesAgainstReference(t *testing.T) {
	dir := os.Getenv("ASNAME_INFER_EVAL")
	if dir == "" {
		t.Skip("set ASNAME_INFER_EVAL to a data directory to measure the rules")
	}
	names, err := LoadNames(filepath.Join(dir, NamesFilename))
	require.NoError(t, err)
	cat, err := OpenCategoryDB(filepath.Join(dir, CategoryFilename))
	require.NoError(t, err)
	r, err := DefaultInferRules()
	require.NoError(t, err)

	type count struct{ agree, disagree, fresh int }
	counts := map[string]*count{}
	var disagreements []string
	tagged := 0
	for asn, name := range names {
		inf := r.Infer(asn, name)
		if len(inf.Tags) == 0 {
			continue
		}
		tagged++
		ref := map[string]bool{}
		for _, tag := range strings.Split(cat.LookupASN(asn), ", ") {
			if tag != "" {
				ref[tag] = true
			}
		}
		for _, tag := range inf.Tags {
			c := counts[tag]
			if c == nil {
				c = &count{}
				counts[tag] = c
			}
			switch {
			case len(ref) == 0:
				c.fresh++
			case anyOf(ref, inferCompatible[tag]):
				c.agree++
			default:
				c.disagree++
				disagreements = append(disagreements, fmt.Sprintf("%s AS%d %s [%s]", tag, asn, name, cat.LookupASN(asn)))
			}
		}
	}
	tags := make([]string, 0, len(counts))
	for tag := range counts {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	t.Logf("%d of %d ASNs get an inferred tag", tagged, len(names))
	for _, tag := range tags {
		c := counts[tag]
		t.Logf("%-11s agrees with the reference %5.1f%% (%d of %d); %d ASNs the reference does not describe",
			tag, 100*float64(c.agree)/float64(max(c.agree+c.disagree, 1)), c.agree, c.agree+c.disagree, c.fresh)
	}
	sort.Strings(disagreements)
	if os.Getenv("ASNAME_INFER_EVAL_VERBOSE") != "" {
		for _, d := range disagreements {
			t.Log(d)
		}
	}
}

func anyOf(set map[string]bool, tags []string) bool {
	for _, t := range tags {
		if set[t] {
			return true
		}
	}
	return false
}
