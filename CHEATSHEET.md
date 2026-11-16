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

### Flags
```bash
# Flags work before or after the arguments
asname city Brisbane -p
asname 8.8.8.8 -r

# --v4-only / --v6-only apply to lookups, country and city.
# search is IPv4 only unless --v6 (both) or --v6-only
asname --v4-only dns.google
asname AS13335 --v6-only
```

### Batch File Lookups
```bash
# Read a mixed list of IPs, ASNs, hostnames, and URLs (comments/blanks ignored)
asname hosts.txt
```

### Output Formats
```bash
# Multi-line card layout with generous whitespace and colors (the default)
asname 8.8.8.8
asname AS15169

# One line per result
asname -o 8.8.8.8
asname --oneline dns.google

# Force colors when piping pretty output to pagers
asname --color 8.8.8.8 | less -R

# Aligned columnar output
asname -u 8.8.8.8

# JSON Lines (one JSON object per line)
asname -j 8.8.8.8
asname --json AS15169
asname --json dns.google

# CSV with a header row (lookups, --stream, search, country and city)
asname --csv hosts.txt > hosts.csv
```

### Organization Search (`search` / `--org`)
```bash
# Search AS names and 8M+ registry netblock records by organization name or netname
asname search "Cloudflare"

# Only AS names, or only netblocks
asname search --asns-only "Valve"
asname search --netblocks-only "Valve"

# Fuzzy: also match ignoring spaces/punctuation, and word by word in any order
# (suffixes like Inc/Ltd dropped, Univ/Intl/Dept expanded); exact matches first
asname search --fuzzy "colo crossing"
asname search --fuzzy "univ of mississippi"

# Search using --org / -O flag with custom result limit
asname -O "Google" --limit 10

# IPv4 is the default. --v6 adds IPv6; --v6-only keeps IPv6 alone
asname search "Fastly"
asname search --v6 "Amazon"
asname search --v6-only "Amazon"

# CIDRs only, one per line
asname search --ips-only "Fastly"

# Read queries from stdin, one per line, when no argument (or -) is given
cat orgs.txt | asname search
# ...with --csv or --json, each row starts with the query it matched
cat orgs.txt | asname search --csv > results.csv

# Formats: pretty cards (default), one line each, or JSON Lines
asname search --limit 5 "Cloudflare"
asname search -o "Cloudflare"
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
asname country --csv AU NZ > anz.csv
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

# Registry Netblock / Owner name (downloads ~350MB RIR whois dumps on first use)
asname -n 183.177.54.135

# Network Classification (cloud provider, CDN, ISP, hosting, Tor exit)
asname -C 13.32.0.1

# Reputation: Spamhaus DROP/ASN-DROP, IPsum, FireHOL hits for the IP and its ASN (builds ~10MB DB on first use)
asname -R 77.91.71.90
asname AS211486

# Combine all enrichments
asname -r -c -n -C 8.8.8.8
```

---

## 2. Unix Pipeline & Streaming Recipes (`--stream` / `-s`)

Stream targets line-by-line in real-time with fastest-first concurrent DNS resolution.

```bash
# Stream from stdin into pretty cards (the default), or one line each
cat targets.txt | asname --stream
cat targets.txt | asname --stream -o

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

# Serve the web UI too (build it with `make web`), and allow database updates from it
asname --rest --allow-updates --web-dir web/dist     # http://127.0.0.1:8086/
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

# Search AS names ("asns") and netblocks ("results"); add scope=asns or scope=netblocks for one,
# fuzzy=true to also match ignoring spaces/punctuation and word by word
curl -s "http://127.0.0.1:8086/v1/search?q=Cloudflare&limit=10"
curl -s "http://127.0.0.1:8086/v1/search?q=colo%20crossing&fuzzy=true"

# Each lookup result also as `asname -p` prints it (the web UI's Copy summary)
curl -s "http://127.0.0.1:8086/v1/lookup?q=8.8.8.8&text=true" | jq -r '.results[].text'

# The server logs each request with its query (bulk: its targets) and every update's
# progress as [update] lines; under systemd: journalctl -u asname -f

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

# Databases on disk and loaded, their age, and the last or running update
curl -s http://127.0.0.1:8086/v1/status

# Ask the registry (RDAP, else whois) / RIPEstat for what the offline databases lack (off by default in REST mode;
# online=true asks for both; refused with 403 if the server runs with --no-whois / --no-online-prefixes)
curl -s "http://127.0.0.1:8086/v1/lookup?q=200.160.2.3&whois=true"
curl -s "http://127.0.0.1:8086/v1/lookup?q=AS13335&online_prefixes=true"
```

### Updating Databases over the API (`--allow-updates`)

```bash
# Rebuild chosen databases (asn, names, country, city, netblock, category, reputation)
curl -s -X POST http://127.0.0.1:8086/v1/update \
  -H "Content-Type: application/json" -d '{"databases": ["reputation"]}'

# Everything on disk ({}), only stale ones, or only what the last update left out
curl -s -X POST http://127.0.0.1:8086/v1/update -H "Content-Type: application/json" -d '{"stale_only": true}'
curl -s -X POST http://127.0.0.1:8086/v1/update -H "Content-Type: application/json" -d '{"incremental": true}'

# Watch the log, or cancel
curl -s http://127.0.0.1:8086/v1/update
curl -s -X DELETE http://127.0.0.1:8086/v1/update -H "Content-Type: application/json"

# Settings kept in the data directory (the CLI follows them too):
# refresh age in hours (0 = never) and IPv6 routes from the next ASN update
curl -s -X PUT http://127.0.0.1:8086/v1/settings -H "Content-Type: application/json" -d '{"max_age_hours": 168}'
curl -s -X PUT http://127.0.0.1:8086/v1/settings -H "Content-Type: application/json" -d '{"ipv6_routes": true}'

# Updates are refused from other sites and from hostnames that aren't this machine,
# and the server swaps in the new databases when one finishes, without a restart.
# Stale databases are also refreshed every 6 hours while the server runs.
```

### Web UI & systemd Service

```bash
# Build and install the binary and the web UI (needs Node.js for `make web`)
make build web
sudo make install install-web           # /usr/local/bin, /usr/local/share/asname/web

# System service: own sandboxed user, databases in /var/lib/asname, on 127.0.0.1:8086
sudo make install-service
journalctl -u asname -f
sudo make uninstall-service

# Or a user service sharing ~/.asname with the CLI
make install-user-service
journalctl --user -u asname -f
make uninstall-user-service

# Another address, or a refresh age fixed at install (otherwise the web UI sets it)
sudo make install-service LISTEN=127.0.0.1:9000
sudo make install-service MAX_AGE=168h

# Work on the UI with hot reload against a running `asname --rest`
cd web && npm run dev                    # ASNAME_API=http://127.0.0.1:9000 to point elsewhere
```

---

## 4. Database Management & Updates

`asname` auto-refreshes databases older than 30 days. You can also trigger manual updates.

```bash
# Change the refresh age for one run, or for every run in this shell (0 = never)
asname --max-age 168h 8.8.8.8
export ASNAME_MAX_AGE=168h

# Or set it on the web UI's Databases tab, which saves it in ~/.asname/settings.json
# for the CLI and the service alike; --max-age / ASNAME_MAX_AGE still win over it
```

### Opt into everything

The core databases (ASN, AS names, country, prefixes) are always built. City, netblock, category and reputation are opt-in: each is built the first time you ask for it, and refreshed by every update after that. IPv6 routes are a separate opt-in (below).

```bash
# Latest code (see section 6)
git pull --rebase
make build && sudo make install

# Build or refresh every database: the --*-only flags combine, and each builds its
# database if absent (city ~125MB, netblock ~370MB; reputation is built last,
# from the fresh ASN data). Once built, a plain `asname update` keeps them all fresh.
asname update --db-only --names-only --country-only \
  --city-only --netblock-only --category-only --reputation-only

# Retry anything the update reports as incomplete, then check
asname update -i
asname version
```

### Manual updates

```bash
# When each database was last updated, and which are due for a refresh
asname version
asname version -j | jq '.databases[] | {name, updated, stale}'

# Refresh every database already on disk (core databases are built if missing)
asname update

# Update specific databases only
asname update --db-only         # IP->ASN RIB trie & ASN->Prefixes database
asname update --names-only      # ASN->Name text file
asname update --country-only    # IP->Country delegation stats
asname update --city-only       # MaxMind DB-IP Lite city database
asname update --netblock-only   # RIR inetnum whois dump index
asname update --category-only   # Provider prefixes & ASN category tags
asname update --reputation-only # Spamhaus, IPsum & FireHOL blocklists

# Retry only the databases the last update failed or left a source out of
asname update --incremental

# Include IPv6 routes in the ASN and prefix databases (off by default; remembered)
asname update --ipv6
asname update --no-ipv6         # back to IPv4 only

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
// res.ASN, res.ASNNumber(), res.Name, res.Country, res.City, res.Netblock, res.NetblockCountry, res.NetblockCreated, res.Category, res.Reputation, res.ASNReputation

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

# Build the web UI into web/dist, and install it to /usr/local/share/asname/web
make web
sudo make install-web

# Install the REST server and web UI as a systemd service (or a user service)
sudo make install-service
make install-user-service
```

---

## 7. Environment Variables

| Variable | Description | Default |
|---|---|---|
| `ASNAME_DIR` | Directory holding all local databases | `~/.asname` |
| `ASNAME_REPUTATION` | Custom path to the blocklist reputation database | `~/.asname/reputation.db` |
| `ASNAME_PREFIXES` | Custom path to ASN announced prefixes database | `~/.asname/prefixes.db` |
| `ASNAME_LISTEN` | REST API server bind host and port | `127.0.0.1:8086` |
| `ASNAME_WEB_DIR` | Serve the web UI from this directory on the REST API server | `""` |
| `ASNAME_ALLOW_UPDATES` | Let the REST API server update its databases (`/v1/update`) | `false` |
| `ASNAME_MAX_AGE` | Refresh databases older than this (`168h`, `0` = never); overrides the age saved in the web UI | `720h` |
| `ASNAME_WHOIS` | Enable online registry lookups (RDAP, else whois) without asking | `false` |
| `ASNAME_ONLINE_PREFIXES` | Look up prefixes the offline database lacks on RIPEstat without asking | `false` |
| `ASNAME_IPV6` | Import IPv6 routes on `asname update` (remembered for later updates) | `false` |
| `ASNAME_CONTACT_EMAIL` | Contact email for `bgp.tools` category queries | `""` |
| `ASNAME_ARIN_APIKEY` | ARIN bulk whois download key, for complete ARIN netblock coverage | `""` |
| `NO_COLOR` | Disables ANSI color output if set | `""` |
