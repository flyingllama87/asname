# asname Cheatsheet & Practical Guide

A quick-reference guide for everyday workflows, pipeline integration, REST daemon usage, database management, and development tasks.

---

## 1. Quick Lookups (CLI)

### Single Target
```bash
# Basic IP lookup
asname 8.8.8.8

# Autonomous System lookup (owner, country, classification, announced prefixes)
asname AS15169
asname asn13335

# Hostname resolution (resolves all A/AAAA records)
asname dns.google

# Browser URL (auto-strips scheme, port, query params, credentials)
asname "https://user:secret@dns.google:8443/resolve?name=example.com#frag"
```

### Batch File Lookups
```bash
# Read a mixed list of IPs, ASNs, hostnames, and URLs (comments/blanks ignored)
asname hosts.txt
```

### Output Formats
```bash
# Multi-line card layout with generous whitespace and colors
asname -p 8.8.8.8
asname --pretty AS15169

# Force colors when piping pretty output to pagers
asname -p --color 8.8.8.8 | less -R

# Aligned columnar output
asname -u 8.8.8.8

# JSON Lines (one JSON object per line)
asname -j 8.8.8.8
asname --json AS15169
asname --json dns.google
```

### Organization Search (`search` / `--org`)
```bash
# Search AS names and 8M+ registry netblock records by organization name or netname
asname search "Cloudflare"

# Only AS names, or only netblocks
asname search --asns-only "Valve"
asname search --netblocks-only "Valve"

# Search using --org / -O flag with custom result limit
asname -O "Google" --limit 10

# IPv4 only or IPv6 only (netblocks and ASN prefixes)
asname search --v4-only "Fastly"
asname search --v6-only "Amazon"

# Formats: pretty cards or JSON Lines
asname search -p --limit 5 "Cloudflare"
asname search -j "Valve" | jq -r 'select(.type == "netblock") | .cidrs[] + " " + .org'
```

### Country Listing (`country`)
```bash
# Every CIDR registered to a country, one per line (code or English name)
asname country AU
asname country --v4-only "New Zealand" > nz.txt

# Formats: pretty card with counts, or JSON Lines
asname country -p AU
asname country -j AU NZ
```

### City Listing (`city`)
```bash
# Every CIDR the city database locates in a city (needs `asname update --city-only`)
asname city "Brisbane, AU"
asname city --v4-only "Brisbane, Queensland" > bne.txt

# A shared name lists every place and names them on stderr
asname city Brisbane

# Formats: pretty card per place, or JSON Lines
asname city -p "Brisbane, AU"
asname city -j "Brisbane, AU" | jq -r .cidr
```

### Enriching with Optional Databases
```bash
# Reverse DNS PTR records
asname -r 8.8.8.8

# City-level geolocation (downloads ~125MB DB-IP Lite on first use)
asname -c 8.8.8.8

# Registry Netblock / Owner name (downloads ~300MB RIR whois dumps on first use)
asname -n 183.177.54.135

# Network Classification (cloud provider, CDN, ISP, hosting, Tor exit)
asname -C 13.32.0.1

# Combine all enrichments in pretty mode
asname -p -r -c -n -C 8.8.8.8
```

---

## 2. Unix Pipeline & Streaming Recipes (`--stream` / `-s`)

Stream targets line-by-line in real-time with fastest-first concurrent DNS resolution.

```bash
# Stream from stdin into pretty cards
cat targets.txt | asname --stream -p

# Real-time web server access log inspection
tail -f /var/log/nginx/access.log | awk '{print $1}' | asname -s -j | jq -c '{ip, asn: .asn.asn_string, country: .country.code}'

# Live network packet capture analysis (tshark)
tshark -T fields -e ip.src | asname -s -j | jq -r '[.ip, .asn.name, .country.name] | @tsv'

# Quick extraction of unannounced / bogon IPs from a list
cat suspicious_ips.txt | asname -s -j | jq -r 'select(.asn.announced == false) | .ip'
```

---

## 3. REST API Daemon (`--rest`)

Run `asname` as a lightweight, in-memory REST API daemon on port `8086`.

### Starting the Server
```bash
# Start on localhost:8086 with all databases enabled
asname --rest --city --netblock -r

# Start on custom host/port with CORS enabled for web dashboards
asname --rest --listen 0.0.0.0:9000 --cors
```

### Querying the REST API

```bash
# Health check & database availability status
curl -s http://127.0.0.1:8086/health

# Query with dirty/raw URLs, IPs, or ASNs (URL-query param)
curl -s "http://127.0.0.1:8086/v1/lookup?q=https://phishing.site:8443/login?user=admin"
curl -s "http://127.0.0.1:8086/v1/lookup?q=AS15169"

# Direct path lookup (IP, hostname, or ASN)
curl -s "http://127.0.0.1:8086/v1/lookup/8.8.8.8"
curl -s "http://127.0.0.1:8086/v1/lookup/AS13335"
curl -s "http://127.0.0.1:8086/v1/lookup/dns.google?reverse_dns=true"

# Search AS names ("asns") and netblocks ("results"); add scope=asns or scope=netblocks for one
curl -s "http://127.0.0.1:8086/v1/search?q=Cloudflare&limit=10"

# Safe Base64URL target lookup (useful for security scripts)
# "https://evil.example.com" -> aHR0cHM6Ly9ldmlsLmV4YW1wbGUuY29t
curl -s "http://127.0.0.1:8086/v1/lookup/b64/aHR0cHM6Ly9ldmlsLmV4YW1wbGUuY29t"

# Bulk batch lookup (JSON payload)
curl -s -X POST http://127.0.0.1:8086/v1/bulk \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["8.8.8.8", "AS15169", "dns.google"],
    "reverse_dns": true
  }'

# Bulk batch lookup (Plaintext lines)
curl -s -X POST http://127.0.0.1:8086/v1/bulk \
  -H "Content-Type: text/plain" \
  --data-binary $'8.8.8.8\n1.1.1.1\nhttps://github.com'
```

---

## 4. Database Management & Updates

`asname` auto-refreshes databases older than 30 days. You can also trigger manual updates:

```bash
# Update core databases (ASN, AS Names, Country)
asname update

# Update specific databases only
asname update --db-only         # IP->ASN RIB trie & ASN->Prefixes database
asname update --names-only      # ASN->Name text file
asname update --country-only    # IP->Country delegation stats
asname update --city-only       # MaxMind DB-IP Lite city database
asname update --netblock-only   # RIR inetnum whois dump index
asname update --category-only   # Provider prefixes & ASN category tags

# Build netblock database with full ARIN coverage, using your ARIN Bulk Whois API key.
# Without the key, ARIN ranges are named from ARIN's open delegated statistics instead,
# which covers 87% of ARIN IPv4 address space.
export ASNAME_ARIN_APIKEY="your-api-key"
asname update --netblock-only
```

The IP to ASN database and announced prefix index are built from the first RIB archive that answers: RouteViews route-views2 (~75 MB), then RIPE RIS rrc04 (~70 MB), then RIPE RIS rrc00 (~400 MB). Override the list with a single dump of your own:

```bash
# Build the ASN database and prefix table from a specific MRT dump (.bz2 or .gz)
asname update --db-only --rib-url https://data.ris.ripe.net/rrc12/2026.09/bview.20260911.0000.gz
```

Downloaded source files are kept in `~/.asname/cache/` for 24 hours. An update that fails partway through reuses what it already fetched on the next attempt, and an interrupted download resumes where it stopped. Delete the directory to force a fresh download.

---

## 5. Using as a Go Library (`github.com/flyingllama87/asname`)

```go
import "github.com/flyingllama87/asname"

// 1. Create client
client, err := asname.New()
defer client.Close()

// 2. Fast in-memory IP lookup
res, err := client.LookupIP(net.ParseIP("8.8.8.8"))
// res.ASN, res.ASNNumber(), res.Name, res.Country, res.City, res.Netblock, res.Category

// 3. String lookup (IP, hostname, URL, or ASN)
results, err := client.Lookup("dns.google")

// 4. Autonomous System lookup
asnRes, err := client.LookupASN(15169)

// 5. Organization search: matches.ASNs and matches.Netblocks
//    (Scope: asname.SearchASNsOnly or asname.SearchNetblocksOnly for one kind)
matches, err := client.Search("Valve", asname.SearchOptions{Limit: 10})

// 6. Every CIDR registered to a country: au.IPv4, au.IPv6
au, err := client.CountryPrefixes("AU")

// 7. Every CIDR the city database locates in a city, one result per place
places, err := client.CityPrefixes("Brisbane, AU")

// 8. Refresh databases missing or older than 30 days; returns the paths rewritten
refreshed, err := asname.UpdateStale(ctx, asname.UpdateOptions{}, 720*time.Hour)
```

Unknown fields are empty strings (not `Unknown`/`N/A`), the `ASNAME_*` variables apply, and output goes only to `asname.WithLog(w)`.

---

## 6. Development & Build Commands (`Makefile`)

```bash
# Compile binary to build/asname
make build

# Run all unit and integration tests with race detector
make test

# Install static binary to /usr/local/bin
sudo make install

# Clean up build artifacts
make clean

# Create release tarball for current platform
make release

# Build release tarballs for all supported platforms
make release-all
```

---

## 7. Environment Variables

| Variable | Description | Default |
|---|---|---|
| `ASNAME_DIR` | Directory holding all local databases | `~/.asname` |
| `ASNAME_PREFIXES` | Custom path to ASN announced prefixes database | `~/.asname/prefixes.db` |
| `ASNAME_LISTEN` | REST API server bind host and port | `127.0.0.1:8086` |
| `ASNAME_WHOIS` | Enable online whois lookups without asking | `false` |
| `ASNAME_CONTACT_EMAIL` | Contact email for `bgp.tools` category queries | `""` |
| `ASNAME_ARIN_APIKEY` | ARIN bulk whois download key, for complete ARIN netblock coverage | `""` |
| `NO_COLOR` | Disables ANSI color output if set | `""` |
