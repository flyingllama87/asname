package sources

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
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
		// Hotels are not hospitals.
		"PARKLAND - PARKLAND HOSPITALITY LTD, IN":           nil,
		"BURNIECITYCOUNCIL-AS-AP - Burnie City Council, AU": {"government"},
		"WBC-NET WANDSWORTH-BOROUGH-COUNCIL, GB":            {"government"},
		"AS-X - Hornsby Shire Council, AU":                  {"government"},
		"NCHE - American Council on Education, US":          nil,
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

func TestWordGroup(t *testing.T) {
	g, err := newWordGroup([]string{"universi*", "data center", "isp"})
	require.NoError(t, err)
	for _, s := range []string{"Universidad de Chile", "Universität Wien", "XYZ Data-Center", "Example ISP", "data  center"} {
		require.True(t, g.match(newSplitName(s)), s)
	}
	for _, s := range []string{"Bisping", "Dispatch", "metadata centers inc"} {
		require.False(t, g.match(newSplitName(s)), s)
	}
	_, err = newWordGroup([]string{"data cent*"})
	require.Error(t, err, "only single words take *")
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

// TestInferNetnamesAgainstData applies the netname rules to every range of
// a real netblock database (ASNAME_INFER_EVAL, holding netblock.db,
// asname.db, asn_db.txt and category.db) and reports how many ranges each
// tag covers, how many were skipped inside hosting networks, and a sample
// of each to read (ASNAME_INFER_EVAL_VERBOSE=1).
func TestInferNetnamesAgainstData(t *testing.T) {
	dir := os.Getenv("ASNAME_INFER_EVAL")
	if dir == "" {
		t.Skip("set ASNAME_INFER_EVAL to a data directory to measure the rules")
	}
	cat, err := OpenCategoryDB(filepath.Join(dir, CategoryFilename))
	require.NoError(t, err)
	names, err := LoadNames(filepath.Join(dir, NamesFilename))
	require.NoError(t, err)
	r, err := DefaultInferRules()
	require.NoError(t, err)

	b := newCategoryBuilder(context.Background())
	for asn, tags := range cat.asnTags() {
		for _, tag := range tags {
			b.addASN(asn, tag)
		}
	}
	for asn, name := range names {
		if inf := r.Infer(asn, name); len(inf.Tags) > 0 {
			b.inferred[asn] = inf
		}
	}
	stats, err := b.importNetnames(filepath.Join(dir, NetblockFilename), filepath.Join(dir, DBFilename))
	require.NoError(t, err)
	for _, tag := range slices.Sorted(maps.Keys(stats.ranges)) {
		t.Logf("%-16s %8d ranges, %6.1fM IPv4 addresses; %d ranges skipped inside hosting networks",
			tag, stats.ranges[tag], float64(stats.addrs4[tag])/1e6, stats.skipped[tag])
	}
	if os.Getenv("ASNAME_INFER_EVAL_VERBOSE") != "" {
		for _, tag := range slices.Sorted(maps.Keys(stats.samples)) {
			for _, s := range stats.samples[tag] {
				t.Logf("%s %s", tag, s)
			}
		}
	}
}

func TestInferNetname(t *testing.T) {
	r, err := DefaultInferRules()
	require.NoError(t, err)
	cases := map[string][]string{
		// Real netnames.
		"IP2000-ADSL-BAS":              {"range:broadband"},
		"ERTH-SPB-PPPOE-50-NET":        {"range:broadband"},
		"EWETEL-DYN-POOL-0185":         {"range:broadband"},
		"KZ-TNSPLUS-FTTB":              {"range:broadband"},
		"AS8758-DYNAMIC-DSL-DHCP-POOL": {"range:broadband"},
		"RABAT_3G_MarocTelecom":        {"range:mobile"},
		"GGSN-3G-ISAT-ID":              {"range:mobile"},
		"MTS-MOBILE-POOL":              {"range:mobile"},
		"MOSLINE-CGNAT0":               {"range:cgnat"},
		"UK-CGN-20190823":              {"range:cgnat"},
		"NETKZ_ALMATY_VPS":             {"range:hosting"},
		"INFOMANIAK-HOSTING":           {"range:hosting"},
		"ADSL2-POOL":                   {"range:broadband"},
		// A customer's company name is not a mobile pool.
		"MOBILE-FUNCTION-GMBH":         nil,
		"RSPC-UK-Mobile-Phones-Direct": nil,
		// "bypass" means the range avoids the NAT.
		"WLINK_BROADBAND_DYNAMIC_BRAS-JWL-01_DEFAULT-POOL-CGNAT-BYPASS": {"range:broadband"},
		// Words inside other words do not count.
		"DSLAMMGMT": nil,
		"GOOGLE":    nil,
	}
	for name, want := range cases {
		require.Equal(t, want, r.InferNetname(name), name)
	}
}

func TestHostingOnly(t *testing.T) {
	require.True(t, HostingOnly([]string{"hosting", "vpn"}))
	require.True(t, HostingOnly([]string{"content"}))
	require.False(t, HostingOnly([]string{"hosting", "isp"}), "an ISP that also hosts")
	require.False(t, HostingOnly([]string{"enterprise"}))
	require.False(t, HostingOnly(nil))
}

func TestSplitASName(t *testing.T) {
	for name, want := range map[string][3]string{
		"COMCAST-7922 - Comcast Cable Communications, LLC, US": {"COMCAST-7922", "Comcast Cable Communications, LLC", "US"},
		"BURNIECITYCOUNCIL-AS-AP - Burnie City Council, AU":    {"BURNIECITYCOUNCIL-AS-AP", "Burnie City Council", "AU"},
		"HETZNER-AS Hetzner Online GmbH, DE":                   {"HETZNER-AS", "Hetzner Online GmbH", "DE"},
		"LVLT-1 - Level 3 Parent, LLC, US":                     {"LVLT-1", "Level 3 Parent, LLC", "US"},
		"EXAMPLE":                                              {"EXAMPLE", "", ""},
		"BOT-TH-AS - Bank of Thailand, Bangkok, Thailand, TH":  {"BOT-TH-AS", "Bank of Thailand, Bangkok, Thailand", "TH"},
	} {
		h, o, cc := SplitASName(name)
		require.Equal(t, want, [3]string{h, o, cc}, name)
	}
}
