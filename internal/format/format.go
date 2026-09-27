package format

import (
	"fmt"
	"strings"
	"time"

	"github.com/flyingllama87/asname/internal/engine"
)

type OutputFormat int

const (
	FormatDefault OutputFormat = iota
	FormatUniform
	FormatPretty
	FormatJSON
	FormatCSV
)

const (
	UniformHostWidth     = 40
	UniformIPWidth       = 39
	UniformASNWidth      = 12
	UniformNameWidth     = 60
	UniformCountryWidth  = 24
	UniformCityWidth     = 34
	UniformNetblockWidth = 48
	UniformCategoryWidth = 30
)

// FieldSeparator separates the fields of a default or uniform output line.
const FieldSeparator = " | "

type outputField struct {
	label string
	value string
	width int
}

// FormatLookupOutput renders one result line for default and uniform modes.
func FormatLookupOutput(res engine.LookupResult, uniform, showHost bool) string {
	if res.IsASN {
		fields := []outputField{
			{label: "ASN", value: res.ASN, width: UniformASNWidth},
			{label: "Name", value: res.Name, width: UniformNameWidth},
			{label: "Country", value: res.Country, width: UniformCountryWidth},
		}
		if res.Category != "" {
			fields = append(fields, outputField{label: "Category", value: res.Category, width: UniformCategoryWidth})
		}
		if len(res.Prefixes) > 0 {
			fields = append(fields, outputField{
				label: "Prefixes",
				value: fmt.Sprintf("%d announced (%d IPv4, %d IPv6)", len(res.Prefixes), len(res.IPv4Prefixes), len(res.IPv6Prefixes)),
			})
		}
		parts := make([]string, 0, len(fields))
		for i, field := range fields {
			if !uniform || i == len(fields)-1 {
				parts = append(parts, fmt.Sprintf("%s: %s", field.label, field.value))
				continue
			}
			parts = append(parts, fmt.Sprintf("%s: %-*s", field.label, field.width, field.value))
		}
		return strings.Join(parts, FieldSeparator) + "\n"
	}

	fields := make([]outputField, 0, 6)
	if res.Host != "" || (uniform && showHost) {
		host := res.Host
		if host == "" {
			host = "-"
		}
		fields = append(fields, outputField{label: "Host", value: host, width: UniformHostWidth})
	}
	fields = append(fields,
		outputField{label: "IP", value: res.IP.String(), width: UniformIPWidth},
		outputField{label: "ASN", value: res.ASN, width: UniformASNWidth},
		outputField{label: "Name", value: res.Name, width: UniformNameWidth},
		outputField{label: "Country", value: res.Country, width: UniformCountryWidth},
	)
	if res.City != "" {
		fields = append(fields, outputField{label: "City", value: res.City, width: UniformCityWidth})
	}
	if res.Netblock != "" {
		netblock := res.Netblock
		if res.NetblockLive {
			netblock += " [whois]"
		}
		fields = append(fields, outputField{label: "Netblock", value: netblock, width: UniformNetblockWidth})
	}
	if res.Category != "" {
		fields = append(fields, outputField{label: "Category", value: res.Category, width: UniformCategoryWidth})
	}
	if res.RDNS != "" {
		fields = append(fields, outputField{label: "Reverse DNS", value: res.RDNS})
	}

	parts := make([]string, 0, len(fields))
	for i, field := range fields {
		if !uniform || i == len(fields)-1 {
			parts = append(parts, fmt.Sprintf("%s: %s", field.label, field.value))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s: %-*s", field.label, field.width, field.value))
	}
	return strings.Join(parts, FieldSeparator) + "\n"
}

// FormatASNSearchOutput renders one AS name search result line.
func FormatASNSearchOutput(res engine.ASNSearchResult) string {
	parts := []string{
		fmt.Sprintf("ASN: %s", res.ASN),
		fmt.Sprintf("Name: %s", res.Name),
	}
	if res.Country != "" && res.Country != "Unknown" {
		parts = append(parts, fmt.Sprintf("Country: %s", res.Country))
	}
	if len(res.Prefixes) > 0 {
		parts = append(parts, fmt.Sprintf("Prefixes: %s", strings.Join(res.Prefixes, ", ")))
	}
	return strings.Join(parts, FieldSeparator) + "\n"
}

// FormatNetblockOutput renders one netblock search result line.
func FormatNetblockOutput(res engine.NetblockEnrichedResult, uniform bool) string {
	cidrStr := strings.Join(res.CIDRs, ", ")
	if cidrStr == "" {
		cidrStr = fmt.Sprintf("%s - %s", res.RangeStart, res.RangeEnd)
	}

	orgDisp := res.Org
	if orgDisp == "" {
		orgDisp = res.Netname
	} else if res.Netname != "" && !strings.EqualFold(res.Netname, res.Org) {
		orgDisp = fmt.Sprintf("%s (%s)", res.Org, res.Netname)
	}

	parts := []string{
		fmt.Sprintf("Netblock: %s", cidrStr),
		fmt.Sprintf("Org: %s", orgDisp),
	}
	if res.ASN != "" && res.ASN != "N/A" {
		parts = append(parts, fmt.Sprintf("ASN: %s", res.ASN))
	}
	if res.ASName != "" && res.ASName != "Unknown" {
		parts = append(parts, fmt.Sprintf("Name: %s", res.ASName))
	}
	if res.Country != "" && res.Country != "Unknown" {
		parts = append(parts, fmt.Sprintf("Country: %s", res.Country))
	}
	return strings.Join(parts, FieldSeparator) + "\n"
}

// Age renders d coarsely, as "45 minutes", "14 hours" or "30 days".
func Age(d time.Duration) string {
	plural := func(n int, unit string) string {
		if n == 1 {
			return "1 " + unit
		}
		return fmt.Sprintf("%d %ss", n, unit)
	}
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return plural(int(d/time.Minute), "minute")
	case d < 48*time.Hour:
		return plural(int(d/time.Hour), "hour")
	default:
		return plural(int(d/(24*time.Hour)), "day")
	}
}

// Bytes renders n in B, KB, MB or GB, powers of 1000.
func Bytes(n int64) string {
	switch {
	case n < 1000:
		return fmt.Sprintf("%d B", n)
	case n < 1000*1000:
		return fmt.Sprintf("%.1f KB", float64(n)/1e3)
	case n < 1000*1000*1000:
		return fmt.Sprintf("%.1f MB", float64(n)/1e6)
	default:
		return fmt.Sprintf("%.1f GB", float64(n)/1e9)
	}
}
