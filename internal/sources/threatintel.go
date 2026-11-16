package sources

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// AbuseCHKeyEnvVar holds an abuse.ch Auth-Key (free with an abuse.ch
// account), which ThreatFox's API requires.
const AbuseCHKeyEnvVar = "ASNAME_ABUSECH_AUTH_KEY"

// threatFoxAPI is ThreatFox's API endpoint; tests point it elsewhere.
var threatFoxAPI = "https://threatfox-api.abuse.ch/api/v1/"

// AbuseCHKey reads the abuse.ch Auth-Key from the environment.
func AbuseCHKey() (string, bool) {
	k := strings.TrimSpace(os.Getenv(AbuseCHKeyEnvVar))
	return k, k != ""
}

// familyTag makes a malware or framework name safe inside a tag: no commas
// (they separate tags) or colons (they separate a tag from its detail).
func familyTag(prefix, family string) string {
	family = strings.Map(func(c rune) rune {
		if c == ',' || c == ':' {
			return -1
		}
		return c
	}, strings.TrimSpace(family))
	if family == "" {
		family = "unknown"
	}
	return prefix + ":" + family
}

// c2IntelNames spells C2IntelFeeds' framework names the way ThreatFox and
// the vendors do, so one framework is not listed twice.
var c2IntelNames = map[string]string{
	"cobaltstrike": "Cobalt Strike",
	"bruteratel":   "Brute Ratel C4",
	"posh":         "PoshC2",
}

// ImportC2IntelFrom reads a C2IntelFeeds IP list: "ip,ioc", where ioc reads
// "Possible Cobaltstrike C2 IP". Each address is tagged c2intel:<framework>.
func (b *reputationBuilder) ImportC2IntelFrom(url string) (int, error) {
	count := 0
	err := b.eachLine(url, func(line string) {
		ip, ioc, _ := strings.Cut(line, ",")
		p, ok := parsePrefix(ip)
		if !ok {
			return
		}
		family := strings.TrimPrefix(strings.TrimSpace(ioc), "Possible ")
		family = strings.TrimSuffix(strings.TrimSuffix(family, " IP"), " C2")
		if canon, ok := c2IntelNames[strings.ToLower(family)]; ok {
			family = canon
		}
		b.addPrefix(p, familyTag("c2intel", family))
		b.listed[p] = true
		count++
	})
	return count, err
}

// ImportThreatFoxFrom asks ThreatFox's API for the last week's indicators
// and keeps the IP ones (ip:port), tagging each threatfox:<malware family>.
// key is sent as the Auth-Key header only; it is never logged or returned.
func (b *reputationBuilder) ImportThreatFoxFrom(api, key string) (int, error) {
	body, _ := json.Marshal(map[string]any{"query": "get_iocs", "days": 7})
	req, err := http.NewRequestWithContext(b.ctx, http.MethodPost, api, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Auth-Key", key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", orDefaultAgent(""))
	resp, err := (&http.Client{Timeout: 2 * time.Minute}).Do(req)
	if err != nil {
		return 0, fmt.Errorf("ThreatFox API: %v", strings.ReplaceAll(err.Error(), key, "***"))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("ThreatFox API: HTTP %d (is %s right?)", resp.StatusCode, AbuseCHKeyEnvVar)
	}
	var doc struct {
		Status string          `json:"query_status"`
		Data   json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<20)).Decode(&doc); err != nil {
		return 0, fmt.Errorf("ThreatFox API: %v", err)
	}
	if doc.Status != "ok" {
		return 0, fmt.Errorf("ThreatFox API: %s", doc.Status)
	}
	var iocs []struct {
		IOC     string `json:"ioc"`
		Type    string `json:"ioc_type"`
		Malware string `json:"malware_printable"`
	}
	if err := json.Unmarshal(doc.Data, &iocs); err != nil {
		return 0, fmt.Errorf("ThreatFox API: %v", err)
	}
	count := 0
	for _, i := range iocs {
		if i.Type != "ip:port" {
			continue // domains, URLs and hashes: asname looks up addresses only
		}
		host := i.IOC
		if j := strings.LastIndex(host, ":"); j > 0 {
			host = strings.Trim(host[:j], "[]")
		}
		p, ok := parsePrefix(host)
		if !ok {
			continue
		}
		b.addPrefix(p, familyTag("threatfox", i.Malware))
		b.listed[p] = true
		count++
	}
	return count, nil
}
