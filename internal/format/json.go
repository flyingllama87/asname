package format

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/flyingllama87/asname/internal/engine"
)

type JSONLookupResult struct {
	Target     string          `json:"target,omitempty"`
	Host       *string         `json:"host"`
	IP         string          `json:"ip"`
	Version    int             `json:"version"`
	ASN        *JSONASN        `json:"asn,omitempty"`
	Country    *JSONCountry    `json:"country,omitempty"`
	City       *JSONCity       `json:"city,omitempty"`
	Netblock   *JSONNetblock   `json:"netblock,omitempty"`
	Category   *JSONCategory   `json:"category,omitempty"`
	ReverseDNS *JSONReverseDNS `json:"reverse_dns,omitempty"`
	Error      string          `json:"error,omitempty"`
}

type JSONASN struct {
	Number    uint32 `json:"number"`
	ASNString string `json:"asn_string"`
	Name      string `json:"name,omitempty"`
	Announced bool   `json:"announced"`
}

type JSONCountry struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

type JSONCity struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
}

type JSONNetblock struct {
	Handle       string `json:"handle,omitempty"`
	Organization string `json:"organization,omitempty"`
	Raw          string `json:"raw"`
	Source       string `json:"source"`
	LiveQuery    bool   `json:"live_query"`
}

type JSONCategory struct {
	Tags []string `json:"tags"`
	Raw  string   `json:"raw"`
}

type JSONReverseDNS struct {
	Names []string `json:"names"`
	Raw   string   `json:"raw"`
}

func ToJSONResult(res engine.LookupResult) JSONLookupResult {
	out := JSONLookupResult{
		Target: res.Target,
		IP:     res.IP.String(),
	}

	if res.Host != "" {
		h := res.Host
		out.Host = &h
	}

	if res.IP.To4() != nil {
		out.Version = 4
	} else {
		out.Version = 6
	}

	if res.ASN != "" && res.ASN != "N/A" {
		numStr := strings.TrimPrefix(res.ASN, "AS")
		num, _ := strconv.ParseUint(numStr, 10, 32)
		out.ASN = &JSONASN{
			Number:    uint32(num),
			ASNString: res.ASN,
			Name:      res.Name,
			Announced: true,
		}
	} else if res.ASN == "N/A" {
		out.ASN = &JSONASN{
			Number:    0,
			ASNString: "N/A",
			Name:      "Unknown",
			Announced: false,
		}
	}

	if res.Country != "" && res.Country != "Unknown" {
		parts := strings.SplitN(res.Country, ", ", 2)
		if len(parts) == 2 {
			out.Country = &JSONCountry{Code: parts[0], Name: parts[1]}
		} else {
			out.Country = &JSONCountry{Code: parts[0], Name: parts[0]}
		}
	}

	if res.City != "" && res.City != "Unknown" {
		out.City = &JSONCity{
			Name:    res.City,
			Present: true,
		}
	}

	if res.Netblock != "" && res.Netblock != "Unknown" {
		src := "offline"
		if res.NetblockLive {
			src = "whois"
		}
		handle, org := ParseNetblockField(res.Netblock)
		out.Netblock = &JSONNetblock{
			Handle:       handle,
			Organization: org,
			Raw:          res.Netblock,
			Source:       src,
			LiveQuery:    res.NetblockLive,
		}
	}

	if res.Category != "" && res.Category != "Unknown" {
		rawTags := strings.Split(res.Category, ", ")
		tags := make([]string, 0, len(rawTags))
		for _, t := range rawTags {
			t = strings.TrimSpace(t)
			if t != "" {
				tags = append(tags, t)
			}
		}
		out.Category = &JSONCategory{
			Tags: tags,
			Raw:  res.Category,
		}
	}

	if res.RDNS != "" && res.RDNS != "N/A" {
		rawNames := strings.Split(res.RDNS, ", ")
		names := make([]string, 0, len(rawNames))
		for _, n := range rawNames {
			n = strings.TrimSpace(n)
			if n != "" {
				names = append(names, n)
			}
		}
		out.ReverseDNS = &JSONReverseDNS{
			Names: names,
			Raw:   res.RDNS,
		}
	}

	return out
}

func ParseNetblockField(s string) (handle string, org string) {
	if i := strings.Index(s, " ("); i >= 0 && strings.HasSuffix(s, ")") {
		return s[:i], strings.TrimSuffix(s[i+2:], ")")
	}
	return s, ""
}

func FormatJSONLookupOutput(res engine.LookupResult) (string, error) {
	jr := ToJSONResult(res)
	b, err := json.Marshal(jr)
	if err != nil {
		return "", fmt.Errorf("marshaling json: %w", err)
	}
	return string(b) + "\n", nil
}

func FormatJSONError(target, errStr string) (string, error) {
	jr := JSONLookupResult{
		Target: target,
		Error:  errStr,
	}
	b, err := json.Marshal(jr)
	if err != nil {
		return "", err
	}
	return string(b) + "\n", nil
}
