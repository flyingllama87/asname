package format

import (
	"fmt"
	"os"
	"strings"

	"github.com/flyingllama87/asname/internal/engine"
	"golang.org/x/term"

	"github.com/flyingllama87/asname/internal/sources"
)

const (
	ansiReset       = "\033[0m"
	ansiBold        = "\033[1m"
	ansiDim         = "\033[2m"
	ansiCyan        = "\033[36m"
	ansiBoldCyan    = "\033[1;36m"
	ansiYellow      = "\033[33m"
	ansiGreen       = "\033[32m"
	ansiBoldMagenta = "\033[1;35m"
	ansiBoldWhite   = "\033[1;37m"
)

// isTerminal reports whether f is an interactive terminal; output redirected
// to /dev/null, a character device, is not.
func isTerminal(f *os.File) bool {
	return f != nil && term.IsTerminal(int(f.Fd()))
}

func ShouldColorize(f *os.File, forceColor, noColor bool) bool {
	if noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	if forceColor {
		return true
	}
	return isTerminal(f)
}

type prettyStyler struct {
	colored bool
}

func newPrettyStyler(colored bool) prettyStyler {
	return prettyStyler{colored: colored}
}

func (s prettyStyler) border(str string) string {
	if !s.colored {
		return str
	}
	return ansiDim + str + ansiReset
}

func (s prettyStyler) section(str string) string {
	if !s.colored {
		return str
	}
	return ansiBoldCyan + str + ansiReset
}

func (s prettyStyler) label(str string) string {
	if !s.colored {
		return str
	}
	return ansiDim + str + ansiReset
}

func (s prettyStyler) header(str string) string {
	if !s.colored {
		return str
	}
	return ansiBoldWhite + str + ansiReset
}

func (s prettyStyler) value(str string) string {
	if !s.colored {
		return str
	}
	return ansiBoldWhite + str + ansiReset
}

func (s prettyStyler) asn(str string) string {
	if !s.colored {
		return str
	}
	return ansiBoldMagenta + str + ansiReset
}

func (s prettyStyler) location(str string) string {
	if !s.colored {
		return str
	}
	return ansiGreen + str + ansiReset
}

func (s prettyStyler) netblock(str string) string {
	if !s.colored {
		return str
	}
	return ansiCyan + str + ansiReset
}

func (s prettyStyler) category(str string) string {
	if !s.colored {
		return str
	}
	return ansiYellow + str + ansiReset
}

func (s prettyStyler) notice(str string) string {
	if !s.colored {
		return str
	}
	return ansiYellow + str + ansiReset
}

// FormatPrettyLookupOutput formats a LookupResult into a multi-line card layout.
func FormatPrettyLookupOutput(res engine.LookupResult, index, total int, colored bool) string {
	st := newPrettyStyler(colored)
	var b strings.Builder

	borderLine := st.border("────────────────────────────────────────────────────────────")

	if res.IsASN {
		if total > 1 {
			b.WriteString(fmt.Sprintf("%s [%d/%d] %s\n", st.header("Target:"), index+1, total, st.asn(res.ASN)))
		} else {
			b.WriteString(fmt.Sprintf("%s %s\n", st.header("Target:"), st.asn(res.ASN)))
		}
		b.WriteString(borderLine + "\n")

		b.WriteString(fmt.Sprintf("  %s\n", st.section("Autonomous System:")))
		b.WriteString(fmt.Sprintf("    %s %s\n", st.label("ASN:              "), st.asn(res.ASN)))
		if res.Name != "" {
			b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Organization:     "), st.value(res.Name)))
		}
		formattedCountry := FormatCountryPretty(res.Country)
		b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Country:          "), st.location(formattedCountry)))

		if res.Category != "" {
			b.WriteString("\n")
			b.WriteString(fmt.Sprintf("  %s\n", st.section("Network Classification:")))
			b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Category:         "), st.category(res.Category)))
		}

		if len(res.Prefixes) > 0 {
			b.WriteString("\n")
			srcNotice := "Offline Index"
			if res.PrefixSource == "ripe-stat" {
				srcNotice = "Live RIPE Stat"
			}
			b.WriteString(fmt.Sprintf("  %s (%d total: %d IPv4, %d IPv6) [%s]\n",
				st.section("Announced Prefixes:"), len(res.Prefixes), len(res.IPv4Prefixes), len(res.IPv6Prefixes), st.notice(srcNotice)))

			const maxShow = 20
			for i, p := range res.Prefixes {
				if i >= maxShow {
					b.WriteString(fmt.Sprintf("    %s ... and %d more prefixes\n", st.label(""), len(res.Prefixes)-maxShow))
					break
				}
				b.WriteString(fmt.Sprintf("    %s %s\n", st.label("•"), st.value(p)))
			}
		}

		b.WriteString(borderLine + "\n\n")
		return b.String()
	}

	targetName := res.Target
	if targetName == "" {
		if res.Host != "" {
			targetName = res.Host
		} else {
			targetName = res.IP.String()
		}
	}

	if total > 1 {
		b.WriteString(fmt.Sprintf("%s [%d/%d] %s\n", st.header("Target:"), index+1, total, st.value(targetName)))
	} else {
		b.WriteString(fmt.Sprintf("%s %s\n", st.header("Target:"), st.value(targetName)))
	}
	b.WriteString(borderLine + "\n")

	b.WriteString(fmt.Sprintf("  %s\n", st.section("Address Details:")))
	if res.Host != "" {
		b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Host:             "), st.value(res.Host)))
	}

	ipVer := "IPv4"
	if res.IP.To4() == nil {
		ipVer = "IPv6"
	}
	b.WriteString(fmt.Sprintf("    %s %s (%s)\n", st.label("IP Address:       "), st.value(res.IP.String()), ipVer))

	if res.RDNS != "" {
		b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Reverse DNS:      "), st.value(res.RDNS)))
	}
	b.WriteString("\n")

	b.WriteString(fmt.Sprintf("  %s\n", st.section("Autonomous System:")))
	b.WriteString(fmt.Sprintf("    %s %s\n", st.label("ASN:              "), st.asn(res.ASN)))
	if res.Name != "" {
		b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Organization:     "), st.value(res.Name)))
	}
	b.WriteString("\n")

	b.WriteString(fmt.Sprintf("  %s\n", st.section("Location:")))
	formattedCountry := FormatCountryPretty(res.Country)
	b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Country:          "), st.location(formattedCountry)))
	if res.City != "" {
		b.WriteString(fmt.Sprintf("    %s %s\n", st.label("City:             "), st.location(res.City)))
	}

	if res.Netblock != "" {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s\n", st.section("Registry Netblock:")))
		b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Netname / Org:    "), st.netblock(res.Netblock)))
		if res.NetblockLive {
			b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Source:           "), st.notice("Live WHOIS")))
		} else {
			b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Source:           "), st.value("Offline Index")))
		}
	}

	if res.Category != "" {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s\n", st.section("Network Classification:")))
		b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Category:         "), st.category(res.Category)))
	}

	b.WriteString(borderLine + "\n\n")
	return b.String()
}

func FormatCountryPretty(country string) string {
	if country == "" || country == "Unknown" {
		return "Unknown"
	}
	parts := strings.SplitN(country, ", ", 2)
	if len(parts) == 2 {
		return fmt.Sprintf("%s (%s)", parts[1], parts[0])
	}
	return country
}

// FormatPrettyASNSearchOutput renders an AS name search result in card format.
func FormatPrettyASNSearchOutput(res engine.ASNSearchResult, index, total int, colored bool) string {
	st := newPrettyStyler(colored)
	var b strings.Builder

	borderLine := st.border("────────────────────────────────────────────────────────────")
	if total > 1 {
		b.WriteString(fmt.Sprintf("%s [%d/%d] %s\n", st.header("ASN:"), index+1, total, st.asn(res.ASN)))
	} else {
		b.WriteString(fmt.Sprintf("%s %s\n", st.header("ASN:"), st.asn(res.ASN)))
	}
	b.WriteString(borderLine + "\n")

	b.WriteString(fmt.Sprintf("  %s\n", st.section("Autonomous System Details:")))
	b.WriteString(fmt.Sprintf("    %s %s\n", st.label("AS Name:          "), st.value(res.Name)))

	if res.Country != "" && res.Country != "Unknown" {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s\n", st.section("Location:")))
		b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Country:          "), st.location(FormatCountryPretty(res.Country))))
	}

	if len(res.Prefixes) > 0 {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s %d (%d IPv4, %d IPv6)\n",
			st.section("Announced Prefixes:"), len(res.Prefixes), len(res.IPv4Prefixes), len(res.IPv6Prefixes)))
		for _, p := range res.Prefixes {
			b.WriteString(fmt.Sprintf("    %s\n", st.value(p)))
		}
	}

	b.WriteString(borderLine + "\n\n")
	return b.String()
}

// FormatPrettyCountryOutput renders a country's CIDR blocks in card format.
// country is "CC, Country Name" or a bare code.
func FormatPrettyCountryOutput(country string, v4, v6 []string, index, total int, colored bool) string {
	return formatPrettyBlocks("Country:", FormatCountryPretty(country), v4, v6, index, total, colored)
}

// FormatPrettyCityOutput renders a place's blocks from a city listing as a card.
func FormatPrettyCityOutput(p sources.CityPlace, index, total int, colored bool) string {
	label := sources.FormatCity(p.City, p.Region)
	if name := sources.CountryNames[p.Country]; name != "" {
		label += ", " + name + " (" + p.Country + ")"
	} else if p.Country != "" {
		label += ", " + p.Country
	}
	return formatPrettyBlocks("City:", label, p.IPv4, p.IPv6, index, total, colored)
}

func formatPrettyBlocks(title, label string, v4, v6 []string, index, total int, colored bool) string {
	st := newPrettyStyler(colored)
	var b strings.Builder

	borderLine := st.border("────────────────────────────────────────────────────────────")
	if total > 1 {
		b.WriteString(fmt.Sprintf("%s [%d/%d] %s\n", st.header(title), index+1, total, st.location(label)))
	} else {
		b.WriteString(fmt.Sprintf("%s %s\n", st.header(title), st.location(label)))
	}
	b.WriteString(borderLine + "\n")
	for _, family := range []struct {
		name  string
		cidrs []string
	}{{"IPv4 Blocks:", v4}, {"IPv6 Blocks:", v6}} {
		if len(family.cidrs) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf("  %s %d\n", st.section(family.name), len(family.cidrs)))
		for _, c := range family.cidrs {
			b.WriteString(fmt.Sprintf("    %s\n", st.value(c)))
		}
	}
	b.WriteString(borderLine + "\n\n")
	return b.String()
}

// FormatPrettyNetblockOutput renders a netblock search result in card format.
func FormatPrettyNetblockOutput(res engine.NetblockEnrichedResult, index, total int, colored bool) string {
	st := newPrettyStyler(colored)
	var b strings.Builder

	borderLine := st.border("────────────────────────────────────────────────────────────")
	cidrStr := strings.Join(res.CIDRs, ", ")
	if cidrStr == "" {
		cidrStr = fmt.Sprintf("%s - %s", res.RangeStart, res.RangeEnd)
	}

	if total > 1 {
		b.WriteString(fmt.Sprintf("%s [%d/%d] %s\n", st.header("Netblock:"), index+1, total, st.value(cidrStr)))
	} else {
		b.WriteString(fmt.Sprintf("%s %s\n", st.header("Netblock:"), st.value(cidrStr)))
	}
	b.WriteString(borderLine + "\n")

	b.WriteString(fmt.Sprintf("  %s\n", st.section("Registry Netblock Details:")))
	b.WriteString(fmt.Sprintf("    %s %s - %s\n", st.label("Range:            "), st.value(res.RangeStart.String()), st.value(res.RangeEnd.String())))
	if len(res.CIDRs) > 0 {
		b.WriteString(fmt.Sprintf("    %s %s\n", st.label("CIDR(s):          "), st.value(strings.Join(res.CIDRs, ", "))))
	}
	if res.Netname != "" {
		b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Netname:          "), st.netblock(res.Netname)))
	}
	if res.Org != "" {
		b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Organization:     "), st.value(res.Org)))
	}

	if res.ASN != "" && res.ASN != "N/A" {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s\n", st.section("Routing Details:")))
		b.WriteString(fmt.Sprintf("    %s %s\n", st.label("ASN:              "), st.asn(res.ASN)))
		if res.ASName != "" && res.ASName != "Unknown" {
			b.WriteString(fmt.Sprintf("    %s %s\n", st.label("AS Name:          "), st.value(res.ASName)))
		}
	}

	if res.Country != "" && res.Country != "Unknown" {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s\n", st.section("Location:")))
		b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Country:          "), st.location(FormatCountryPretty(res.Country))))
	}

	b.WriteString(borderLine + "\n\n")
	return b.String()
}
