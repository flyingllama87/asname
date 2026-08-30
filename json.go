package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// jsonLookupResult defines the structured schema for JSON and JSONL output.
type jsonLookupResult struct {
	Target     string          `json:"target,omitempty"`
	Host       *string         `json:"host"`
	IP         string          `json:"ip"`
	Version    int             `json:"version"`
	ASN        *jsonASN        `json:"asn,omitempty"`
	Country    *jsonCountry    `json:"country,omitempty"`
	City       *jsonCity       `json:"city,omitempty"`
	Netblock   *jsonNetblock   `json:"netblock,omitempty"`
	Category   *jsonCategory   `json:"category,omitempty"`
	ReverseDNS *jsonReverseDNS `json:"reverse_dns,omitempty"`
	Error      string          `json:"error,omitempty"`
}

type jsonASN struct {
	Number    uint32 `json:"number"`
	ASNString string `json:"asn_string"`
	Name      string `json:"name,omitempty"`
	Announced bool   `json:"announced"`
}

type jsonCountry struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

type jsonCity struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
}

type jsonNetblock struct {
	Handle       string `json:"handle,omitempty"`
	Organization string `json:"organization,omitempty"`
	Raw          string `json:"raw"`
	Source       string `json:"source"`
	LiveQuery    bool   `json:"live_query"`
}

type jsonCategory struct {
	Tags []string `json:"tags"`
	Raw  string   `json:"raw"`
}

type jsonReverseDNS struct {
	Names []string `json:"names"`
	Raw   string   `json:"raw"`
}

// toJSONResult converts an internal lookupResult into a jsonLookupResult.
func toJSONResult(res lookupResult) jsonLookupResult {
	out := jsonLookupResult{
		Target: res.target,
		IP:     res.ip.String(),
	}

	if res.host != "" {
		h := res.host
		out.Host = &h
	}

	if res.ip.To4() != nil {
		out.Version = 4
	} else {
		out.Version = 6
	}

	// ASN
	if res.asn != "" && res.asn != "N/A" {
		numStr := strings.TrimPrefix(res.asn, "AS")
		num, _ := strconv.ParseUint(numStr, 10, 32)
		out.ASN = &jsonASN{
			Number:    uint32(num),
			ASNString: res.asn,
			Name:      res.name,
			Announced: true,
		}
	} else if res.asn == "N/A" {
		out.ASN = &jsonASN{
			Number:    0,
			ASNString: "N/A",
			Name:      "Unknown",
			Announced: false,
		}
	}

	// Country
	if res.country != "" && res.country != "Unknown" {
		parts := strings.SplitN(res.country, ", ", 2)
		if len(parts) == 2 {
			out.Country = &jsonCountry{Code: parts[0], Name: parts[1]}
		} else {
			out.Country = &jsonCountry{Code: parts[0], Name: parts[0]}
		}
	}

	// City
	if res.city != "" && res.city != "Unknown" {
		out.City = &jsonCity{
			Name:    res.city,
			Present: true,
		}
	}

	// Netblock
	if res.netblock != "" && res.netblock != "Unknown" {
		src := "offline"
		if res.netblockLive {
			src = "whois"
		}
		handle, org := parseNetblockField(res.netblock)
		out.Netblock = &jsonNetblock{
			Handle:       handle,
			Organization: org,
			Raw:          res.netblock,
			Source:       src,
			LiveQuery:    res.netblockLive,
		}
	}

	// Category
	if res.category != "" && res.category != "Unknown" {
		rawTags := strings.Split(res.category, ", ")
		tags := make([]string, 0, len(rawTags))
		for _, t := range rawTags {
			t = strings.TrimSpace(t)
			if t != "" {
				tags = append(tags, t)
			}
		}
		out.Category = &jsonCategory{
			Tags: tags,
			Raw:  res.category,
		}
	}

	// Reverse DNS
	if res.rdns != "" && res.rdns != "N/A" {
		rawNames := strings.Split(res.rdns, ", ")
		names := make([]string, 0, len(rawNames))
		for _, n := range rawNames {
			n = strings.TrimSpace(n)
			if n != "" {
				names = append(names, n)
			}
		}
		out.ReverseDNS = &jsonReverseDNS{
			Names: names,
			Raw:   res.rdns,
		}
	}

	return out
}

// parseNetblockField extracts the handle and organization from strings like "GOGL (Google LLC)".
func parseNetblockField(s string) (handle string, org string) {
	if i := strings.Index(s, " ("); i >= 0 && strings.HasSuffix(s, ")") {
		return s[:i], strings.TrimSuffix(s[i+2:], ")")
	}
	return s, ""
}

// formatJSONLookupOutput formats a lookupResult as a single-line JSON string.
func formatJSONLookupOutput(res lookupResult) (string, error) {
	jr := toJSONResult(res)
	b, err := json.Marshal(jr)
	if err != nil {
		return "", fmt.Errorf("marshaling json: %w", err)
	}
	return string(b) + "\n", nil
}
