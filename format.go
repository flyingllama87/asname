package main

import (
	"fmt"
	"strings"
)

type outputFormat int

const (
	formatDefault outputFormat = iota
	formatUniform
	formatPretty
	formatJSON
)

type outputField struct {
	label string
	value string
	width int // padding in uniform mode; ignored for the final field
}

// formatLookupOutput renders one result line for default and uniform modes.
func formatLookupOutput(res lookupResult, uniform, showHost bool) string {
	fields := make([]outputField, 0, 6)
	if res.host != "" || (uniform && showHost) {
		host := res.host
		if host == "" {
			host = "-"
		}
		fields = append(fields, outputField{label: "Host", value: host, width: uniformHostWidth})
	}
	fields = append(fields,
		outputField{label: "IP", value: res.ip.String(), width: uniformIPWidth},
		outputField{label: "ASN", value: res.asn, width: uniformASNWidth},
		outputField{label: "Name", value: res.name, width: uniformNameWidth},
		outputField{label: "Country", value: res.country, width: uniformCountryWidth},
	)
	if res.city != "" {
		fields = append(fields, outputField{label: "City", value: res.city, width: uniformCityWidth})
	}
	if res.netblock != "" {
		netblock := res.netblock
		if res.netblockLive {
			netblock += " [whois]"
		}
		fields = append(fields, outputField{label: "Netblock", value: netblock, width: uniformNetblockWidth})
	}
	if res.category != "" {
		fields = append(fields, outputField{label: "Category", value: res.category, width: uniformCategoryWidth})
	}
	if res.rdns != "" {
		fields = append(fields, outputField{label: "Reverse DNS", value: res.rdns})
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
