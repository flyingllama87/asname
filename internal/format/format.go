package format

import (
	"fmt"
	"strings"

	"github.com/flyingllama87/asname/internal/engine"
)

type OutputFormat int

const (
	FormatDefault OutputFormat = iota
	FormatUniform
	FormatPretty
	FormatJSON
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

type outputField struct {
	label string
	value string
	width int
}

// FormatLookupOutput renders one result line for default and uniform modes.
func FormatLookupOutput(res engine.LookupResult, uniform, showHost bool) string {
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
	return strings.Join(parts, " → ") + "\n"
}
