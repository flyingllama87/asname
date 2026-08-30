package main

import (
	"fmt"
	"os"
	"strings"
)

// ANSI color escape codes.
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

// shouldColorize determines if color output should be enabled based on flags,
// TTY detection, and the NO_COLOR environment variable.
func shouldColorize(f *os.File, forceColor, noColor bool) bool {
	if noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	if forceColor {
		return true
	}
	return isTerminal(f)
}

// prettyStyler holds styling helpers for colorized or plain output.
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

// formatPrettyLookupOutput formats a lookupResult into a multi-line card layout.
func formatPrettyLookupOutput(res lookupResult, index, total int, colored bool) string {
	st := newPrettyStyler(colored)
	var b strings.Builder

	borderLine := st.border("────────────────────────────────────────────────────────────")

	// Target Header
	targetName := res.target
	if targetName == "" {
		if res.host != "" {
			targetName = res.host
		} else {
			targetName = res.ip.String()
		}
	}

	if total > 1 {
		b.WriteString(fmt.Sprintf("%s [%d/%d] %s\n", st.header("Target:"), index+1, total, st.value(targetName)))
	} else {
		b.WriteString(fmt.Sprintf("%s %s\n", st.header("Target:"), st.value(targetName)))
	}
	b.WriteString(borderLine + "\n")

	// Address Details
	b.WriteString(fmt.Sprintf("  %s\n", st.section("Address Details:")))
	if res.host != "" {
		b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Host:             "), st.value(res.host)))
	}

	ipVer := "IPv4"
	if res.ip.To4() == nil {
		ipVer = "IPv6"
	}
	b.WriteString(fmt.Sprintf("    %s %s (%s)\n", st.label("IP Address:       "), st.value(res.ip.String()), ipVer))

	if res.rdns != "" {
		b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Reverse DNS:      "), st.value(res.rdns)))
	}
	b.WriteString("\n")

	// Autonomous System
	b.WriteString(fmt.Sprintf("  %s\n", st.section("Autonomous System:")))
	b.WriteString(fmt.Sprintf("    %s %s\n", st.label("ASN:              "), st.asn(res.asn)))
	if res.name != "" {
		b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Organization:     "), st.value(res.name)))
	}
	b.WriteString("\n")

	// Location
	b.WriteString(fmt.Sprintf("  %s\n", st.section("Location:")))
	formattedCountry := formatCountryPretty(res.country)
	b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Country:          "), st.location(formattedCountry)))
	if res.city != "" {
		b.WriteString(fmt.Sprintf("    %s %s\n", st.label("City:             "), st.location(res.city)))
	}

	// Registry Netblock
	if res.netblock != "" {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s\n", st.section("Registry Netblock:")))
		b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Netname / Org:    "), st.netblock(res.netblock)))
		if res.netblockLive {
			b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Source:           "), st.notice("Live WHOIS")))
		} else {
			b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Source:           "), st.value("Offline Index")))
		}
	}

	// Network Classification
	if res.category != "" {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s\n", st.section("Network Classification:")))
		b.WriteString(fmt.Sprintf("    %s %s\n", st.label("Category:         "), st.category(res.category)))
	}

	b.WriteString(borderLine + "\n\n")
	return b.String()
}

// formatCountryPretty turns "US, United States" into "United States (US)".
func formatCountryPretty(country string) string {
	if country == "" || country == "Unknown" {
		return "Unknown"
	}
	parts := strings.SplitN(country, ", ", 2)
	if len(parts) == 2 {
		return fmt.Sprintf("%s (%s)", parts[1], parts[0])
	}
	return country
}
