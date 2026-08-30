package format

import (
	"fmt"
	"os"
	"strings"

	"github.com/flyingllama87/asname/internal/engine"
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

func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
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
