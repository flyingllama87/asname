# asname

`asname` is a fast, offline command-line utility written in Go for resolving IP addresses, hostnames and URLs to their Autonomous System Number (ASN), the AS owner's name, and the geographical country.

Lookups are answered from local LC-trie databases, so there is no per-query network call and no API key or rate limit to worry about.

## Features

- **Blazing Fast**: Uses offline LC-trie databases for instantaneous IP lookups.
- **Takes Whatever You Have**: An IP address, a hostname, a URL you pasted from a browser, or a file or stream of anything: a list (bulleted or not), a log, an alert, a web page. IPs, URLs, domains and ASNs are picked out of it, defanged ones (`hxxp`, `[.]`) included.
- **ASN & Prefix Lookups**: Query any ASN (`AS15169`) to see its owner, country, classification, and all announced IPv4/IPv6 prefixes.
- **Organization Search**: Search AS names and millions of registry netblocks by organization name or netname (`asname search <query>`) to find matching ASNs with their announced prefixes, IP ranges and CIDRs, optionally in one country (`--in AU`). Search for an AS number (`asname search AS47692`) to list every registry netblock inside its routes, customers' included.
- **Explore the Routing Table**: Filter every announced prefix by size, registry country, origin AS, kind of network and blocklist hits (`asname explore --len 8`, `asname explore --in AU --reputation drop`), with a breakdown by country, kind and AS.
- **Country Listings**: List every IP block registered to a country as CIDRs (`asname country AU`), ready for a firewall or allowlist.
- **City Listings**: List every IP block the city database locates in a city (`asname city "Brisbane, AU"`).
- **Pretty Cards, One-Liners, JSONL & CSV**: Results print as clean multi-line cards by default, or one line each (`--oneline`), streamable JSON objects (`--json`), or CSV for spreadsheets (`--csv`).
- **Real-Time Streaming**: Feed targets directly through standard input pipes (`--stream`).
- **REST API Server**: Run as an instant in-memory HTTP daemon (`--rest`) on port `8086`.
- **Web UI**: An optional browser front end that takes whatever you paste (a list, a log, an alert, a web page, defanged indicators included) and picks out the IPs, URLs, domains and ASNs, served by the REST server itself (`--web-dir`), for lookups, searches and database updates, and a Makefile target that installs it all as a systemd service.
- **Names the Actual Owner**: An optional database built from the RIRs' bulk whois dumps resolves an address to the netblock it was assigned in, so a suballocation reports the customer holding it rather than the datacentre announcing it, along with the country the block itself is registered in and when it was registered.
- **Says Who Is Dodgy**: An optional reputation database flags addresses and ASNs named by Spamhaus DROP and ASN-DROP, IPsum and FireHOL, and shows what share of an ASN's address space is listed.
- **Says Where the Network Says It Is**: An optional database of the networks' own RFC 8805 geofeeds, found through their registry records, shown beside the geolocation estimate so a disagreement stands out.
- **Says What It Is**: Another optional database classifies an address as cloud, CDN, hosting, residential ISP, mobile or Tor exit, from the providers' own published ranges and operator-declared network types, and flags space rented out by IP leasing brokers or held by an anonymised company.
- **Auto-Updating**: Automatically fetches the latest RouteViews or RIPE RIS RIB dumps, RIPE ASN names, and RIR Delegation Statistics to build and maintain its own fresh databases when they get older than 30 days.
- **Fully Standalone**: A single static binary — no Cgo, and no `geoiplookup` or other system tool to install alongside it.

## Installation

```bash
go install github.com/flyingllama87/asname/cmd/asname@latest
```

Or build and install from a clone using the provided Makefile, which stamps the
version into the binary and links it statically:

```bash
make build
sudo make install
```

This compiles the tool and places the `asname` binary into `/usr/local/bin/`.
Run `make test` to run the test suite.

The web UI is built separately, and needs Node.js and npm; see
[Web UI](#web-ui) and [Running as a service](#running-as-a-service).

```bash
make web
sudo make install-web
```

## Go Package & Library Usage

`asname` is designed as a first-class Go package and can be imported directly into your own Go applications:

```bash
go get github.com/flyingllama87/asname
```

### Basic Example

```go
package main

import (
	"fmt"
	"log"
	"net"

	"github.com/flyingllama87/asname"
)

func main() {
	// Initialize client using $ASNAME_DIR, else ~/.asname
	client, err := asname.New()
	if err != nil {
		log.Fatalf("failed to initialize asname: %v", err)
	}
	defer client.Close()

	// 1. Direct fast in-memory lookup for a net.IP (< 1µs)
	res, err := client.LookupIP(net.ParseIP("8.8.8.8"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("IP: %s | ASN: %s (%d) | Name: %s | Country: %s\n",
		res.IP, res.ASN, res.ASNNumber(), res.Name, res.Country)

	// 2. Query any string target (IP, hostname, URL, or ASN like "AS15169")
	results, err := client.Lookup("dns.google")
	if err != nil {
		log.Fatal(err)
	}
	for _, r := range results {
		fmt.Printf("Resolved IP: %s -> %s\n", r.IP, r.Name)
	}

	// 3. Query an Autonomous System by number
	asnRes, err := client.LookupASN(15169)
	if err == nil {
		fmt.Printf("ASN 15169 Name: %s, Announced Prefixes: %d\n", asnRes.Name, len(asnRes.Prefixes))
	}
}
```

### Client Configuration Options

```go
client, err := asname.New(
	asname.WithDataDir("/custom/path"),           // Custom database directory
	asname.WithCity(true),                        // Enable DB-IP Lite city lookup
	asname.WithNetblock(true),                    // Enable registry netblock owner lookup
	asname.WithCategory(true),                    // Enable network classification
	asname.WithReputation(true),                  // Enable public blocklist reputation
	asname.WithReverseDNS(true),                  // Enable PTR reverse DNS lookups
	asname.WithAutoUpdate(720 * time.Hour),       // Refresh databases older than 30 days
	asname.WithLog(os.Stderr),                    // Show warnings and update progress (silent by default)
	asname.WithOnlinePrefixes(true),              // Let LookupASN fetch prefixes the local DB lacks (off by default)
)
```

The client reads the same environment variables as the CLI: `ASNAME_DIR` for the data directory, and `ASNAME_DB`, `ASNAME_NAMES`, `ASNAME_COUNTRY`, `ASNAME_CITY`, `ASNAME_NETBLOCK`, `ASNAME_GEOFEED`, `ASNAME_CATEGORY`, `ASNAME_REPUTATION` and `ASNAME_PREFIXES` for individual files. An explicit `WithDataDir` beats `ASNAME_DIR`, a per-file variable beats the directory, and `WithCustomPaths` beats both.

A field the databases cannot answer is empty in a `Result`; the CLI's `Unknown` and `N/A` are display text only. `Result.String()` puts them back for printing.

The library never writes to stderr and never prompts. Messages go to `WithLog` or nowhere. It also stays offline unless you opt in: registry lookups (RDAP, falling back to whois) with `WithWhois`, and online ASN prefix lookups with `WithOnlinePrefixes`.

### Updating Databases

```go
// Download the core databases (ASN, names, country) unconditionally.
err := asname.Update(ctx, asname.UpdateOptions{Log: os.Stderr})

// Refresh only what is missing or older than 30 days, and see what changed.
refreshed, err := asname.UpdateStale(ctx, asname.UpdateOptions{City: true, Netblock: true}, 720*time.Hour)

// Rebuild only what the last update failed or left a source out of.
refreshed, err := asname.UpdateIncomplete(ctx, asname.UpdateOptions{All: true})

// Which databases are incomplete, and the sources each is missing.
missing := asname.Incomplete("")
```

A throttled or failing download (HTTP 429 or 5xx) is retried with backoff, honouring `Retry-After`. A database that still cannot be rebuilt keeps its existing file, and the other databases are still updated; the returned error names each failure. The country database is only rewritten when every registry answered, because one missing registry would leave a whole region without countries. Cancelling `ctx` abandons the download in progress. The partial file is kept and resumed next time, and no further database is started. A category update identifies itself to bgp.tools with `UpdateOptions.ContactEmail`, then `$ASNAME_CONTACT_EMAIL`. With neither, it skips the bgp.tools tags rather than asking.

## Usage

Simply pass an IP address to resolve its information. Lookup and search results print as multi-line cards by default (see [Pretty mode](#pretty-mode)); add `--oneline` (or `-o`) to print each result on one line instead, as the examples below do for brevity:

```bash
$ asname -o 8.8.8.8
IP: 8.8.8.8 | ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States
```

The argument can equally be a hostname. Every address the name resolves to is looked up, one line each:

```bash
$ asname -o dns.google
Host: dns.google | IP: 8.8.8.8 | ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States
Host: dns.google | IP: 8.8.4.4 | ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States
```

Or a URL, so you can paste one straight from a browser. The scheme, credentials, port, path, query and fragment are stripped and whatever host remains is looked up:

```bash
$ asname -o 'https://dns.google:443/resolve?name=example.com'
Host: dns.google | IP: 8.8.8.8 | ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States
```

Or a file listing any mix of the above, one entry per line. Blank lines and `#` comments are ignored, and only the first field of a line is read, so columnar files work as they are:

```bash
$ cat hosts.txt
# resolvers to check
8.8.8.8
1.1.1.1          # cloudflare
https://github.com/anthropics

$ asname -o hosts.txt
IP: 8.8.8.8 | ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States
IP: 1.1.1.1 | ASN: AS13335 | Name: CLOUDFLARENET - Cloudflare, Inc., US | Country: AU, Australia
Host: github.com | IP: 4.237.22.38 | ASN: AS8075 | Name: MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US | Country: US, United States
```

Entries that cannot be resolved are reported on stderr and the rest of the file is still printed; `asname` then exits non-zero. Names are resolved concurrently, so a long file is not paced by DNS latency.

An argument that parses as an IP address is always treated as one; an ASN formatted as `AS<number>` (or `asn<number>`) resolves the Autonomous System directly; otherwise an existing file is read as a list, and anything else is treated as a hostname or URL.

Add `--reverse-dns` (or `-r`) to also send a reverse DNS query and include PTR names in the output:

```bash
$ asname -o --reverse-dns 8.8.8.8
IP: 8.8.8.8 | ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States | Reverse DNS: dns.google
```

`--v4-only` and `--v6-only` keep one address family for lookups and for the blocks `country` and `city` list. `search` is IPv4 only unless you pass `--v6` (both families) or `--v6-only`.

Flags can go before or after the arguments, so `asname 8.8.8.8 -r`, `asname city Brisbane -p` and `asname -p city Brisbane` all work. The output, address family and data file flags (`-p`, `-o`, `-j`, `--csv`, `--color`, `--v4-only`, `--dir`, `--city-db`...) work with every command; the rest belong to lookups (`-r`, `--rest`...) or to `search` (`--limit`, `--asns-only`...) alone.

### ASN lookups

Pass an Autonomous System Number directly (`AS15169`, `asn13335`, or just `AS` followed by the number) to look up the organization, country, network classification, and all announced BGP IP prefixes:

```bash
$ asname -o AS15169
ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States | Category: cdn, content, hosting, vpn | Prefixes: 1415 announced (1239 IPv4, 176 IPv6)
Announced Prefixes:
  8.8.4.0/24
  8.8.8.0/24
  34.0.0.0/20
  ...
```

Without `--oneline`, the default card summarizes the prefix breakdown and a sample list:

```bash
$ asname AS15169
Target: AS15169
────────────────────────────────────────────────────────────
  Autonomous System:
    ASN:               AS15169
    Organization:      GOOGLE - Google LLC, US
    Country:           United States (US)

  Network Classification:
    Category:          cdn, content, hosting, vpn

  Announced Prefixes: (1415 total: 1239 IPv4, 176 IPv6)
    • 8.8.4.0/24
    • 8.8.8.0/24
    • 34.0.0.0/20
    • 34.0.0.0/15
    • 34.0.16.0/20
     ... and 1410 more prefixes
────────────────────────────────────────────────────────────
```

Add `--json` (or `-j`) to emit structured JSON Lines containing prefix counts and the full array of announced CIDRs.

Prefixes are answered instantly and offline via `~/.asname/prefixes.db`, which is built automatically from BGP RIB dumps during `asname update`. It holds IPv4 prefixes only unless you opt into IPv6 routes; see [IPv6 routes](#ipv6-routes).

An ASN the prefix database has nothing for, because it announces nothing or the database has not been built, can be looked up on the [RIPEstat](https://stat.ripe.net/) API instead. That is a network query, so like [the registry lookup](#filling-the-gaps-with-rdap-and-whois) it is asked about first, and the answer is remembered for an hour in `~/.asname/online-prefixes-consent.json`. Prefixes that came from RIPEstat are labelled as such in the card and `--json` output.

- `--online-prefixes` (or `ASNAME_ONLINE_PREFIXES=1`) queries without asking.
- `--no-online-prefixes` never queries and never asks.
- Without a terminal to ask on, and in `--stream` and `--rest` modes, nothing is queried unless `--online-prefixes` is given; a lookup that could have used it prints a one-line reminder on stderr.


### City lookups

City-level geolocation is optional and off by default, because the database is
large. Enable it once with `--city` (or `-c`), which downloads it:

```bash
$ asname -o --city 8.8.8.8
IP: 8.8.8.8 | ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States | City: Mountain View, California, United States
```

After that the flag is not needed — the city is included whenever the database
is present, and refreshed along with everything else:

```bash
$ asname -o 1.1.1.1
IP: 1.1.1.1 | ASN: AS13335 | Name: CLOUDFLARENET - Cloudflare, Inc., US | Country: AU, Australia | City: Sydney, New South Wales
```

Use `--no-city` to suppress it for one run, or delete `~/.asname/city.mmdb` to
opt back out for good. `asname update` refreshes the city database only once you
already have it, so it is never fetched unasked.

**Treat the city as a hint, not a fact.** DB-IP rate the free Lite database at
an accuracy index of 77, against 96 for their commercial one. VPNs, mobile
carriers, CGNAT and anycast routinely place an address hundreds of kilometres
from where it really is — `dns.google`'s IPv6 anycast address reports as
Montreal, for instance. The ASN and AS name come from BGP and are solid; the
city is a best guess.

#### MaxMind beside DB-IP

With a MaxMind account the city update also downloads MaxMind's city database
(GeoLite2 City, free with an account, or a paid GeoIP2 City edition) into
`maxmind-city.mmdb`, and every lookup gives both estimates: `MaxMind:` beside
`City:` in the output, `city_maxmind` beside `city` in JSON, and a row each in
the web UI. Two independent estimates that agree are worth more than either
alone, and when they disagree the web UI says the location is unclear.

Put the account in asname's settings file, `~/.config/asname/env`, so the
command, its REST server and the user service all see it:

```bash
mkdir -p ~/.config/asname
cat > ~/.config/asname/env <<'END'
ASNAME_MAXMIND_ACCOUNT_ID=123456
ASNAME_MAXMIND_LICENSE_KEY=...
# ASNAME_MAXMIND_EDITION=GeoIP2-City    # optional; GeoLite2-City by default
END
chmod 600 ~/.config/asname/env
asname update --city-only
```

The account ID and key are sent only to MaxMind (as HTTP basic auth, which is
not passed on when MaxMind redirects the download) and never appear in
asname's logs or errors. Keys issued since 2024 need the account ID; a key
alone is refused, and asname says so. If MaxMind cannot be reached the DB-IP
database is still updated and the update is reported incomplete.

An [abuse.ch](https://auth.abuse.ch/) Auth-Key (free with an account) adds
ThreatFox to the reputation database. Add it to the same file, or pass it for
one update from a secret store:

```bash
echo 'ASNAME_ABUSECH_AUTH_KEY=...' >> ~/.config/asname/env
asname update --reputation-only
```

The key is sent only to ThreatFox's API, as its `Auth-Key` header, and never
appears in asname's logs or errors.

#### The settings file

`~/.config/asname/env` (or `$XDG_CONFIG_HOME/asname/env`, or the file
`ASNAME_ENV_FILE` names) holds `ASNAME_*=value` lines that would otherwise
have to be exported everywhere: the MaxMind account, `ASNAME_ARIN_APIKEY`,
`ASNAME_CONTACT_EMAIL`. A variable set in the environment wins over the
file. asname warns when the file can be read by other users. The system
service reads `/etc/asname/env` instead.

### Network geofeeds

Many networks publish where their own addresses are, as an RFC 8805 *geofeed*:
a CSV file their registry records point to (a `geofeed:` attribute, or a
`remarks: Geofeed <url>` line, RFC 9092). asname can fetch them:

```bash
asname update --geofeed-only     # once; later updates keep it fresh
asname -o 94.249.188.188
IP: 94.249.188.188 | ASN: AS215365 | Name: Threatoff Tom Gewiese, DE | Country: DE, Germany | City: Kirchberg, Bavaria, Germany | MaxMind: Germany | Geofeed: Helsinki, Finland | Netblock: Threatoff | Block country: FI, Finland | Category: hosting
```

The netblock database finds the feeds, so it is needed first; RIPE, APNIC and
AFRINIC registrations name some 6,000. ARIN's are found only with an ARIN bulk
whois key. Fetching them is about 6,000 small downloads from the networks' own
hosts, each host one connection at a time (a few for hosts serving many feeds),
HTTPS only, in about five minutes. A host that answers 429 or 503, or drops
the connection, is slowed down and retried; one that still cannot be reached
three times in a row has its remaining feeds skipped. Expect a fifth of the feeds to be
gone or broken at any time; the update log counts them by reason. Each feed,
and each failure, is kept in the download cache for 24 hours, so a retry or
rebuild the same day asks no host again.

**A feed only counts inside the ranges that name it.** Where registry ranges
nest, the most specific one naming a feed decides which feed speaks for its
addresses (RFC 9092, section 4), and anything a feed says about other
addresses is dropped, so one network's feed cannot place another's space.
Lines that do not parse are skipped. A region code from another country than
the line's own discards the line's region and city, keeping only the country.

**It is the holder's claim.** Measured on 3,000 random addresses from ranges
that name a feed, the feed's country matched MaxMind GeoLite2's 90% of the
time and DB-IP's 90%, as often as those two match each other (88%). In 5% it
contradicted both, and most of those came from one feed placing German
proxy space in Vilnius, Helsinki, Rome or London. So the web UI shows the
geofeed beside the estimates, says when they disagree, and warns when a
geofeed is contradicted by every estimate: typical of proxy and VPN space
advertising a location it is not in (mobile and satellite users do roam,
though). Use `--no-geofeed` to leave it out of
one run, or delete `geofeed.db` to opt out.

### Registry netblocks

The ASN tells you who announces an address, which is often not who is using it.
A suballocation inside a datacentre's range is announced by the datacentre, so
the AS name is theirs and the customer's name appears nowhere.

The RIRs record that assignment as an `inetnum` object in their whois databases,
and they publish those databases in bulk. `asname` can build a local index of
them, enabled once with `--netblock` (or `-n`):

```bash
$ asname -o --netblock 183.177.54.135
IP: 183.177.54.135 | ASN: AS15830 | Name: Equinix Equinix (EMEA) Acquisition Enterprises B.V., NL | Country: AU, Australia | Netblock: SISS-SY4 (Secure Internet Storage Solutions)
```

Like the city, the flag is only needed once: from then on the netblock is
included whenever the database is present. `--no-netblock` suppresses it for one
run, and deleting `~/.asname/netblock.db` opts back out for good.

Ranges nest, and the most specific one wins — an eight-address assignment inside
a /22 allocation reports the assignment, not the allocation.

**Coverage is not uniform, because the registries do not all publish the same
thing:**

| Registry | Region | Status |
|---|---|---|
| APNIC | Asia-Pacific | Published openly |
| RIPE NCC | Europe, Middle East | Published openly |
| AFRINIC | Africa | Published openly |
| LACNIC | Latin America | **Anonymised.** The public dump carries only status, city and country — no owner — so it is not used at all |
| ARIN | North America | Organisation names only, derived from the openly published [delegated statistics](https://ftp.arin.net/pub/stats/arin/). The complete data requires a signed agreement. See below |

What is left over can be filled a query at a time over whois instead, see
[Filling the gaps with RDAP and whois](#filling-the-gaps-with-rdap-and-whois).

#### Block country, age and leased space

For RIPE, APNIC and AFRINIC ranges the index also keeps three things the range says about itself.

**Country.** The `Country` field comes from the RIR delegation statistics, which record the country of whoever holds the larger allocation a range was carved from. A sub-allocated or leased block often names a different country of its own. When it does, the pretty card shows both, and the other formats add a block country field (`Block country` in the line output, `netblock.country` in JSON, `netblock_country` in CSV):

```
  Location:
    Country:           United States (US) [netblock registration]
    Allocated in:      Russia (RU) [RIR allocation]
```

**Age.** The date the range was registered, shown as `Registered: 2026-04-15 (7 months ago)` in the card, `netblock.created` in JSON and `netblock_created` in CSV. Space that was re-registered recently is common for short-lived scanning and proxy operations.

**Leased and anonymised space.** Two flags are added to the category tags (see [Network categories](#network-categories)), so they appear wherever the category does:

| Tag | Meaning | How it is detected |
|---|---|---|
| `leased:<broker>` | The range is rented out by an IP leasing broker (`ipxo`, `interlir`, `prefixbroker`, `ipbroker`, `lir-services`, `ipv4mall`) | The range or its organisation is maintained by the broker's RIPE maintainer, or its geofeed is hosted by the broker |
| `anonymised-holder` | The holder's name is withheld behind a placeholder such as `Company 64d3452aYKe9ygar` | The organisation name matches that placeholder pattern |

Leased space held by an anonymous company is typical of VPN, proxy and scanning operations, though not proof of one. A database built by asname 0.13 or earlier lacks these fields; `asname update --netblock-only` rebuilds it.

ARIN does not publish its database openly. Access needs the [Bulk Whois Terms of
Use](https://www.arin.net/reference/research/bulkwhois/) signed and the request
approved, after which ARIN issue an API key. Their terms restrict redistribution,
so `asname` can only build this part of the database from a key you obtained
yourself:

```bash
export ASNAME_ARIN_APIKEY=...
asname update --netblock-only
```

Without a key, asname falls back to ARIN's [delegated extended statistics](https://ftp.arin.net/pub/stats/arin/),
which are published openly and need no agreement. That file lists every ARIN range
but names none of them: each record carries only an opaque identifier shared by
every resource one organisation holds. Joining a range's identifier to the ASNs
registered under the same identifier yields an AS number, and the AS name database
supplies the name.

This names 72% of ARIN's IPv4 ranges, covering 87% of the addresses in them,
and 89% of its IPv6 ranges.
The remainder are held by organisations that hold no ASN of their own and stay
unnamed. Two limits apply to what it does name. The name is the organisation
holding the allocation, so an address inside a block reassigned to a downstream
customer reports the organisation ARIN allocated it to, not that customer;
reassignment records are carried only in bulk Whois. The name also comes from the
AS name database rather than from ARIN, so it is the operator name seen in routing,
which for an organisation holding several ASNs may differ in wording from its
registered name.

### Filling the gaps with RDAP and whois

LACNIC publishes no usable dump and ARIN's open data names only part of its
space, but every registry will answer a question about a single address. So
when an address has no offline netblock, asname can ask the registry directly:

```bash
$ asname 8.8.8.8
asname: 8.8.8.8 has no offline netblock: not every registry publishes owner data
asname: in a form that can be indexed offline. Ask the registry over the network for
asname: addresses like it? Either answer is remembered for an hour. [y/N] y
IP: 8.8.8.8 | ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States | Netblock: GOGL (Google LLC) [rdap]
```

Every other lookup asname does is offline, so this one is asked about rather
than assumed. **Either answer is remembered for an hour**, in
`~/.asname/whois-consent.json`, so a session's work is one question rather than
one per address. After the hour it asks again.

Answers that came from the network are marked `[rdap]` or `[whois]` (`Live RDAP`
or `Live WHOIS` in `--pretty`, `"source": "rdap"` or `"whois"` in `--json`),
because unlike the rest of the output they are not reproducible offline and
reveal to the registry which addresses you are looking at.

- `--whois` queries without asking, and does not record an answer — use this in
  scripts. (The name predates RDAP; it covers both.)
- `--no-whois` never queries and never asks.
- With no terminal to ask (a pipe, a cron job), asname does not query and prints
  a one-line reminder that `--whois` exists.

**RDAP first, whois if that fails.** RDAP (the Registration Data Access
Protocol, RFC 9082/9083) is the registries' replacement for port-43 whois: JSON
over HTTPS with the same fields at every registry, always UTF-8. asname finds the
registry for an address in IANA's RDAP bootstrap files
(`https://data.iana.org/rdap/ipv4.json` and `ipv6.json`, kept for a week in
`~/.asname/rdap-ipv4.json` and `rdap-ipv6.json`), asks it for the most specific
network holding the address, and follows its redirects (LACNIC hands Brazilian
space to registro.br, for instance) as long as they stay on HTTPS. The netname,
the registrant organisation, the block's own country and its registration date
all come back, so a live answer fills the same fields as the offline index.

If the RDAP server fails, times out, rate-limits (HTTP 429) or has no network
for the address, asname falls back to whois: `whois.iana.org` first to find the
registry, then the registry itself on port 43. Whois answers carry only the
netname and organisation, and LACNIC's mangles accented names ("N�cleo"
for "Núcleo"); RDAP has neither problem. When RDAP failed but whois answered,
the reason is printed on stderr.

Some networks reach the registries' RDAP servers over IPv6 only to have the
connection stall or reset (seen with LACNIC, RIPE and AFRINIC). A request that
fails, or takes more than half its 8-second allowance, is tried again over IPv4,
and that registry is asked over IPv4 straight away for the rest of the run.

asname only goes online when the offline database has nothing *and* the
address is one some registry has actually delegated, which keeps it away from
reserved and unallocated space.

Registries rate-limit these queries hard, so one run stops after 25 online
lookups and says so. A throttled whois server answers with a well-formed but
empty document; that is reported as a failure rather than silently shown as an
unknown netblock.

**AS names, too.** The offline AS names list (RIPE NCC's `asn.txt`) can lag a
newly registered ASN by a day or more. When it has no name for an ASN, the same
opt-in asks that ASN's registry over RDAP (`<server>/autnum/<n>`, found through
IANA's `asn.json` bootstrap file) and shows the name like the list would,
`GOOGLE - Google LLC`, marked `[rdap]` (`"name_source": "rdap"` in `--json`). It
uses the same consent answer and the same 25-query allowance; a name found once
is reused for the rest of the run (or, for the REST server, until it restarts).
There is no whois fallback for AS names.

`--whois` also works with no netblock database at all, if you would rather ask
the registries every time than keep 370 MB on disk.

Each registry also publishes placeholder objects covering the ranges it does
*not* hold, so that a whois query for someone else's address points you at the
right registry instead of returning nothing. Those are dropped while building,
since a placeholder naming APNIC is worse than no answer at all.

Building the database downloads roughly 350 MB of registry dumps, takes about
two minutes and needs ~1.7 GB of memory while it runs. The result is around
370 MB on disk holding some 7.4 million ranges. It is read from disk by binary
search rather than loaded into memory, so a lookup stays instant and costs a few
kilobytes of RAM.

### Searching by organization name

`asname search` (or `--org` / `-O`) finds an organization two ways: in the
registered names of every Autonomous System, and, when you have the netblock
database (`asname -n` or `asname update --netblock-only`), in the organization
name or netname of all 8+ million registry records. Matching ASNs are listed
first, so an organization that holds an ASN but no address space of its own
is still found. Without the netblock database only the AS names are searched.

```bash
$ asname -o search "Cloudflare"
ASN: AS13335 | Name: CLOUDFLARENET - Cloudflare, Inc., US | Country: US, United States | Prefixes: 1.0.0.0/24, 1.1.1.0/24, ...
ASN: AS14789 | Name: CLOUDFLARENET - Cloudflare, Inc., US | Country: US, United States | Prefixes: ...
...
Netblock: 1.0.0.0/24 | Org: APNIC and Cloudflare DNS Resolver project (APNIC-LABS) | ASN: AS13335 | Name: CLOUDFLARENET - Cloudflare, Inc., US
Netblock: 1.1.1.0/24 | Org: APNIC and Cloudflare DNS Resolver project (APNIC-LABS) | ASN: AS13335 | Name: CLOUDFLARENET - Cloudflare, Inc., US
Netblock: 27.111.242.236/30 | Org: Equinix Customer - CLOUDFLARE US, INC (CLOUDFLARE_US_INC) | ASN: AS15830 | Name: Equinix Equinix (EMEA) Acquisition Enterprises B.V., NL
...
```

Each ASN lists the prefixes it announces, from the local prefix database, and
each netblock is enriched with the announcing ASN, operator name, and country.
An AS name match is made against the name without its trailing country code,
so searching `us` does not return every AS in the United States.

You can restrict the search to one kind, customize the result limit and keep
only IPv4 or IPv6 netblocks and ASN prefixes. Search is IPv4 only unless you
opt into IPv6:

```bash
# Only AS names, or only registry netblocks
asname search --asns-only "Valve"
asname search --netblocks-only "Valve"

# Limit results (default unlimited; caps the ASNs and the netblocks separately)
asname search --limit 10 "Google"

# IPv4 is the default. --v6 adds IPv6; --v6-only keeps IPv6 alone
asname search "Fastly"
asname search --v6 "Amazon"
asname search --v6-only "Amazon"

# CIDRs only, one per line (IPv4 unless --v6 or --v6-only)
asname search --ips-only "Fastly"

# Read queries from stdin, one per line, when no argument (or -) is given
cat orgs.txt | asname search
# ...with --csv or --json, each row starts with the query it matched
cat orgs.txt | asname search --csv > results.csv

# Output formats: pretty cards (the default), one line each (--oneline), JSON Lines (--json) or CSV (--csv)
asname search --limit 5 "Cloudflare"
asname search --json "Valve" | jq -r 'select(.type == "netblock") | .cidrs[] + " " + .org'
asname search --json --asns-only "Valve" | jq -r '.ipv4_prefixes[]?'
```

#### One country

`--in` keeps ASNs registered in a country and netblocks the country database
places there. It applies before `--limit`, so it never hides matches:

```bash
asname search --in AU telstra
asname search --in "New Zealand" --ips-only spark
```

#### Every netblock inside an AS

A name search finds blocks whose netname or organisation contains the name, so
a customer's assignment named something else is missed: Nessus GmbH's
`185.49.52.26/32` is registered as `KNOX`, with no organisation. Search for the
AS number instead and you get every registry netblock inside its announced
prefixes, its own allocations and its customers' assignments, each clipped to
the part the most specific record covers:

```bash
asname search AS47692 --netblocks-only
```

#### Fuzzy search

A plain search matches letter for letter, so `colo crossing` misses
`AS-COLOCROSSING` and `univ of mississippi` misses "Mississippi State
University". `--fuzzy` also finds names that match:

- **compact**: ignoring spaces and punctuation on both sides: `colo crossing`
  finds COLOCROSSING, `amazon 02` finds AMAZON-02, `digital ocean` finds
  DigitalOcean;
- **words**: every word of the query, in any order, starting a word of the
  name, with company suffixes (Inc, LLC, Ltd, GmbH, SRL...) left out and common
  abbreviations (Univ, Dept, Intl, Telecom, Govt...) standing for the words they
  shorten: `univ of mississippi` finds five Mississippi universities, `Telstra
  Corporation Ltd` finds Telstra Limited. Matching only at the start of a word
  keeps `deutsche` from finding "mitteldeutsche", and numbers match whole, so
  `level 3` does not find "Level 23".

Exact matches come first, then compact, then words, and the limit applies after
that ranking; `--json` and `--csv` say how each result matched. A fuzzy search
over the netblock database takes a second or two rather than half a second.
Like every search it reads only the local databases and never goes online.

```bash
asname search --fuzzy "colo crossing"
asname search --fuzzy --json "univ of mississippi" | jq -r '[.match, .asn // .netname, .name // .org] | @tsv'
```

### Exploring the routing table

`asname explore` lists the announced prefixes, each with its origin AS,
registry country, kind of network and blocklist hits, filtered by any mix of:

| Flag | Keeps |
| --- | --- |
| `--len 8`, `--len 16-24` | prefixes of that length, or in that range |
| `--in AU` | prefixes the country database places in a country (the holder's registration, not where users are) |
| `--as-in AU` | prefixes whose origin AS is registered there |
| `--asn AS13335` | one origin AS |
| `--tag hosting,vpn` | any of these kinds of network; a tag counts when both ends of the prefix carry it, or its AS does, so one Tor exit does not label its /24 |
| `--reputation listed\|clean\|drop\|drop-inside\|asn-drop\|firehol2\|firehol3` | `drop` is a prefix wholly on Spamhaus DROP; `drop-inside` one containing a DROP block |
| `--min-ipsum N` | an address on N or more IPsum feeds |
| `--min-listed-pct P` | P% or more of its IPv4 addresses on IPsum or FireHOL |

`--sort size|listed|share` orders it (address order by default), `--limit`
caps it (500; 0 for all), `--ips-only` prints the prefixes alone, `--count`
prints how many match and what they break down into, and `--json` everything.
The index is built from the local databases on first use, a couple of seconds,
and needs the prefix database; the category and reputation databases add tags
and blocklist hits when present.

```bash
asname explore --len 8 --count
asname explore --in AU --reputation drop
asname explore --tag hosting --min-ipsum 3 --sort listed --ips-only
```

### Listing a country's IP blocks

`asname country` prints every block the country database assigns to a
country as minimal CIDRs, one per line, IPv4 first. It takes a two-letter code
or an English name, and several at once:

```bash
$ asname country AU
1.0.0.0/24
1.0.4.0/22
1.1.1.0/24
...

asname country --v4-only "New Zealand" > nz.txt
asname country AU NZ
asname country --json AU        # {"country":"AU","cidr":"1.0.0.0/24","is_v6":false} per line
asname country --pretty AU      # a card with IPv4 and IPv6 block counts
```

Adjacent blocks are merged, so the list is already as short as it can be
without taking in addresses registered to another country.

The country database is built from the RIRs' delegation statistics, so a
block is listed under the country its holder registered it in, as the
Country field of a lookup is. That is not always where the addresses are used.

### Listing a city's IP blocks

`asname city` prints every block the city database locates in a city, as
minimal CIDRs, one per line, IPv4 first. It needs the city database (~125MB;
`asname update --city-only`). A name several places share lists them all and
names each on stderr; add a region, country code or country name after a comma
to pick one. Region names are the database's full names (`Queensland`, not
`QLD`), and city names are English (`Munich`, not `München`).

```bash
$ asname city Brisbane
asname: "Brisbane" matches 2 places, so all are listed; add a region or country to pick one:
asname:   Brisbane, Queensland, AU (13826 blocks)
asname:   Brisbane, California, US (49 blocks)
1.44.93.0/24
...

asname city "Brisbane, AU" > brisbane.txt
asname city --v4-only "Brisbane, Queensland"
asname city --json "Brisbane, AU"    # {"city":"Brisbane","region":"Queensland","country":"AU","cidr":"1.44.93.0/24","is_v6":false} per line
asname city --pretty Munich         # a card with IPv4 and IPv6 block counts
```

The city database is DB-IP Lite geolocation: estimates, mostly at /24
granularity, of where addresses are used. Expect some of a city's blocks to be
missing or placed in a neighbouring city. A listing reads the whole database,
so it takes a couple of seconds.

### Network categories

Who owns an address and what it is *for* are different questions. `--category`
(or `-C`) answers the second: cloud, CDN, hosting, residential ISP, mobile,
university, Tor exit, a named VPN provider's server and so on.

```bash
$ asname -o -C 13.32.0.1
IP: 13.32.0.1 | ASN: AS16509 | Name: AMAZON-02 - Amazon.com, Inc., US | Country: US, United States | Category: cdn, cloud:aws

$ asname -o 139.130.4.5
IP: 139.130.4.5 | ASN: AS1221 | Name: ASN-TELSTRA Telstra Limited, AU | Country: AU, Australia | Category: isp, mobile

$ asname -o 104.156.233.174
IP: 104.156.233.174 | ASN: AS20473 | Name: AS-VULTR - The Constant Company, LLC, US | Country: US, United States | Category: cloud:vultr, vpn:vpn-unlimited
```

Like the other optional databases, the flag is needed once; after that its
presence on disk is enough. `--no-category` suppresses it for a run. The
database is about 3 MB, or about 26 MB with the netblock database present (for
the netname and owner tags below), and builds in a minute or two.

**The two halves of it are not equally trustworthy, and the difference matters.**

*Prefixes* come from the providers themselves. AWS, Azure, Google, Oracle, Fastly,
Cloudflare, DigitalOcean, Linode and Vultr all publish the exact ranges they
use, and AWS goes further and names the service, which is how `13.32.0.1` is
reported as a CDN while `52.95.110.1` is just a machine. The Tor Project
publishes its exit list the same way. When one of these names an address, that
is the provider speaking about its own network and it settles the question.
An address inside one of these ranges that is also a Tor exit or VPN server
reports both, for example `cloud:vultr, vpn:vpn-unlimited`.

Azure's ranges come from Microsoft's weekly [Service Tags](https://www.microsoft.com/en-us/download/details.aspx?id=56519)
file (the public cloud's `AzureCloud` ranges, with Front Door's edge also
tagged `cdn`).

*Known services* come from the [MISP warninglists](https://github.com/MISP/misp-warninglists),
lists of addresses that look suspicious but are not, kept by the MISP
threat-sharing project. asname reads their IP lists only:

| Tag | Meaning |
|---|---|
| `scanner:<name>` | A known internet scanner's published range (Censys, Shodan, Rapid7, Shadowserver and about 90 more): background noise, not a targeted attack. |
| `crawler:<name>` | Googlebot's or OpenAI's GPTBot's published crawler ranges. |
| `service:<name>` | A service's own addresses: Zscaler (a corporate user behind its proxy), Microsoft 365, GitHub, Salesforce, Telegram, Apple, a Cisco Umbrella block page, big mail providers' sending and receiving servers. |
| `public-dns` | A DNS resolver that answers anyone. |
| `sinkhole` | A known sinkhole for seized malicious domains: a device talking to it is probably infected. |
| `parking` | A domain-parking service. |
| `cloud:<name>` | Clouds and CDNs with no first-hand list: IBM, Alibaba, Huawei, Tencent, Hetzner, OVH, Leaseweb, Scaleway, Akamai, Gcore, Bunny, CDN77, Imperva and others, plus Azure's China, Germany and US Government clouds. |

These tags add to the network's own tags rather than replace them: an open
resolver on a home connection still shows `isp`. With `-v` the card names the
warninglist behind each.

*iCloud Private Relay* egress ranges come from [Apple](https://mask-api.icloud.com/egress-ip-ranges.csv),
tagged `relay:icloud`. Apple publishes each range with the region its users
are in, and keeps them there, so the card shows that location as `Relay users`
(JSON `relay`): roughly where the person is, unlike a VPN's.

*Bogons* come from [Team Cymru's full bogon lists](https://www.team-cymru.com/bogon-reference),
tagged `bogon`: space no registry has handed out. Unannounced, traffic from it
is spoofed; announced, it is squatted or hijacked.

*Special-purpose blocks* need no download: asname carries IANA's
special-purpose address registries ([IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/),
[IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/), RFC 6890)
and names the block an address is in, with its RFC and whether it is reachable
on the internet: `Special-purpose: Shared Address Space (carrier-grade NAT),
100.64.0.0/10 (RFC 6598), not reachable on the internet` (JSON `special`).
This works without any database.

*VPN servers* come from the providers' own server lists where they publish
one without a login: NordVPN, Mullvad, Surfshark, Private Internet Access,
IVPN, AirVPN, Windscribe and PrivadoVPN. Surfshark and IVPN list hostnames
rather than addresses, so those are resolved at build time. The other
providers, among them ProtonVPN, ExpressVPN, CyberGhost, IPVanish and PureVPN,
come from the server lists that [gluetun](https://github.com/qdm12/gluetun-servers)
maintains for its VPN client, which are only as fresh as gluetun's last update.
A provider whose own list cannot be read, or whose hostnames mostly fail to
resolve, falls back to gluetun's copy, so a network that filters VPN domains
still gets a complete, if older, set. Each server address is tagged with its
provider, as `vpn:nordvpn`, `vpn:private-internet-access` and so on, and
With `-v` the card shows under Data Sources which list it came from and its date.

Two limits apply. The lists hold the addresses a client *connects to*, plus
exit addresses where NordVPN and AirVPN list them; most providers send traffic
out of the same address, but some, ProtonVPN among them, can exit from a
different one, which these lists do not record. And they cover only those
providers.

*ASNs* come from bgp.tools' operator tags and PeeringDB's self-reported network
type. These describe **the operator, not the address**: the tag means the AS is
associated with that thing somewhere, not that every address in it is. So
`asname -C 8.8.8.8` reports `cdn, hosting, vpn` — all true of Google, none of
them specifically true of that resolver. Read AS-level answers as "this is the
sort of network it is", not as a fact about the address.

The netblock database, when present, adds two more tags from the registry records themselves: `leased:<broker>` for space an IP leasing broker rents out, and `anonymised-holder` where the holder's name is withheld. See [Block country, age and leased space](#block-country-age-and-leased-space).

Because of that, a prefix match wins outright and the AS tags are not consulted;
otherwise every EC2 address would inherit `vpn` from Amazon's AS, on the grounds
that somebody, somewhere, runs a VPN on EC2.

Three of bgp.tools' tags are left out entirely for the same reason. `tor` sits
on a quarter of the eyeball ISPs in their data, because subscribers run relays.
`anycast` sits on Telstra, Google and Amazon, because everyone large anycasts
something. `biznet` means the network sells business connectivity, which
describes an ISP rather than the business at the far end.

*Inferred tags* are asname's own, and are shown apart from the rest: as
`inferred: finance` after the category, an `Inferred:` line in `--pretty`
saying what each was inferred from, `"inferred": [{"tag": "finance", "from":
"name"}]` in the JSON `category`, a
`category_inferred` CSV column, and outlined tags in the web UI. `from` is
`name` or `list` for the AS, and `netname` or `netblock` for the address's
own range. About three ASNs
in four are not described by PeeringDB or bgp.tools at all, yet most say what
they are in their registered name: "Kennesaw State University", "Patelco
Credit Union", "Netico Telecomunicação", "Svea Hosting". The rules in
[`internal/sources/inferrules.yaml`](internal/sources/inferrules.yaml) turn
such words into `education`, `government`, `finance`, `healthcare`, `isp`,
`mobile` and `hosting`, in several languages, and a short list adds well-known
networks whose names do not say (T-Mobile, Reliance Jio, OVH, Leaseweb...).
They run every time the category database is built, so an update recreates
the same tags from the current AS names list.

```bash
$ asname AS15916
ASN: AS15916 | Name: ABN AMRO Bank N.V., NL | Country: NL, Netherlands | Category: inferred: finance
```

They are written for accuracy over coverage. They read the organisation part
of the name, never the handle, because enterprises call their own data-centre
networks `-COLO` or `-HOSTING` without being hosting companies. An AS gets at
most one kind of organisation, in priority order, so "Universidade Federal" is
education and "SchoolsFirst Federal Credit Union" finance. Words that misled
when measured are left out: "federal", "state of", bare "5G". Each listed
network carries the name it is expected to have, and is skipped if the AS
number changes hands. Measured against every AS that PeeringDB or bgp.tools also
describe (November 2026), the tags agree with them for education 99%,
government 95%, ISP 94%, mobile 93% and finance 88%. Most of the remaining
"disagreements" are the reference being loose, for example data centres that
call themselves `transit` and telcos that call themselves `content`. The rules
tag about 20,000 ASNs, some 13,000 of which neither source describes. To
measure them against your own data:

```bash
ASNAME_INFER_EVAL=~/.asname go test ./internal/sources -run InferRulesAgainstReference -v
# add ASNAME_INFER_EVAL_VERBOSE=1 to list every disagreement
```

**Netnames say even more, about the address itself.** Registries name each
range, and access networks name theirs for what they are: `IP2000-ADSL-BAS`,
`ERTH-SPB-PPPOE-50-NET`, `RABAT_3G_MarocTelecom`, `MOSLINE-CGNAT0`. With the
netblock database present, the category build reads every range's netname and
tags it `range:broadband` (DSL, PPPoE, fibre, cable or dynamic pools),
`range:mobile` (LTE, 3G, GPRS, GGSN, APN), `range:cgnat` (carrier-grade NAT,
where one address is shared by many subscribers and identifying one needs the
port and time) or `range:hosting` (VPS, hosting or data-centre ranges inside
networks that are otherwise not hosts). Unlike the AS tags these are about the
address's own range:

```bash
$ asname 2.6.213.10
IP: 2.6.213.10 | ASN: AS3215 | Name: AS3215 Orange S.A., FR | ... | Netblock: IP2000-ADSL-BAS (BSBOR651 Bordeaux Bloc 2) | Category: isp, mobile; inferred: range:broadband
```

A netname is split into words and matched whole, so "DSLAM" is not "DSL",
and only words that name a kind of connection count. "mobile" needs a pool
word beside it, because `MOBILE-FUNCTION-GMBH` is a customer, and `epc` and
`pgw` were dropped after matching a company and someone's initials. Inside
networks that only host servers, netnames are not trusted at all: Leaseweb
names ranges `US_broadband_Internet` and OVH has `DHCP-for-VPC`. On the
November 2026 data this tags about 352,000 broadband ranges (107 million IPv4
addresses), 4,700 mobile (24 million), 1,200 CGNAT and 14,000 hosting ranges.
To measure them, with samples to read:

```bash
ASNAME_INFER_EVAL=~/.asname ASNAME_INFER_EVAL_VERBOSE=1 go test ./internal/sources -run InferNetnamesAgainstData -v
```

What a netname says is what the connection is, not who is on it: a DSL range
may be one small office's line, and a pool named "dynamic" years ago may
since have been reassigned.

**So does the organisation a block is registered to.** An ISP's address space
is often registered, block by block, to its customers: `14.200.154.201` is
carried by TPG Telecom, but its block is registered to Lismore City Council,
and that council is who is behind the address. The same name rules that read
AS names are applied to every netblock's registered owner. Where the owner's
kind is something the network's own tags do not already say, the range is
tagged with it, marked as inferred from the block's owner (`"from":
"netblock"` in JSON):

```bash
$ asname 14.200.154.201
IP: 14.200.154.201 | ASN: AS7545 | Name: TPG-INTERNET-AP - TPG Telecom Limited, AU | ... | Netblock: LISMORECITYCOUNCIL (LISMORE CITY COUNCIL) | Category: isp, transit; inferred: government
```

That covers about 46,000 government blocks (Italian comuni, Dutch gemeenten,
UK councils, police stations), 23,000 banks and insurers, 20,000 colleges and
universities, 12,000 hospitals and clinics, 30,000 hosting customers and
91,000 downstream ISPs (an "ISP" registered inside a network that only hosts
servers is taken to be a leased range and skipped). Read by hand, the
samples were overwhelmingly right; what slipped through were names that read
like something they are not, such as a church's "Life Ministry Centre", and
"hospitality" no longer counts as a hospital.

The web UI leads with this. Each card answers **Who is it?** from the most
specific record there is, and shows the block's registered owner beside the
network that carries it, each with the tags that describe it, so a council's
block inside TPG reads as the council's, not as a TPG home user. A block whose
"owner" is really the operator's own description of a pool ("BSBOR651
Bordeaux Bloc 2", "Dynamic pool") is shown as the network's.

They are still guesses from a name. A bank's AS can carry its IT
subsidiary, and a telecom equipment maker can read like a telecom. So they never
replace a source's tag (where PeeringDB or bgp.tools already says the same,
the inferred copy is dropped), and the web UI's explanations say "inferred from
its name" when they rely on one.

**What is still missing is proxy detection, and VPNs beyond those lists.** A
provider gluetun does not cover, a provider's exit addresses where they differ
from its servers, and residential proxy networks, which route traffic through
home connections, all look like ordinary hosting or ISP addresses from routing
data alone. Finding them takes active measurement, connecting to the service
and watching where it comes out, which is why that data is sold rather than
published.

#### The bgp.tools contact address

bgp.tools asks that clients identify themselves rather than arrive with a
default user agent, so the first build asks for an address:

```
asname: some of the categories (hosting, ISP, VPN, CDN) come from bgp.tools,
asname: which asks that clients identify themselves with a contact address so
asname: they can get in touch if a client misbehaves. It is sent to bgp.tools
asname: alone, in the User-Agent header, and to none of the other sources.
asname: Contact email (blank to skip bgp.tools):
```

It is stored in `~/.asname/contact.json` and asked once. **It is sent to
bgp.tools and nowhere else** — every other source is fetched with the plain user
agent, since none of them asked, and handing a personal address to a dozen
unrelated hosts is not a fair trade for a tag. Leaving it blank is remembered
too, and simply builds without their tags.

Set `ASNAME_CONTACT_EMAIL` or pass `--contact-email` to skip the question, which
is what you want in a script; neither is written to disk. With no terminal to
ask on, the build says so and leaves bgp.tools out.

Their data carries no explicit licence and they ask for 24-hour caching on it,
which a monthly rebuild comfortably satisfies. If you are going to redistribute
anything built from it, talk to `admin@bgp.tools` first. PeeringDB rate-limits
anonymous API access, so rebuilding repeatedly in quick succession will get a
`429`; the build warns and carries on with the other sources, which leaves the
database thinner than it should be — check the per-source counts if you care.

Add `--uniform` (or `-u`) to print aligned fields:

```bash
$ asname -o -u -r 8.8.8.8
IP: 8.8.8.8                                | ASN: AS15169      | Name: GOOGLE - Google LLC, US                                      | Country: US, United States         | Reverse DNS: dns.google
```

### Reputation (blocklists)

`--reputation` (or `-R`) reports which free public blocklists name an address, and what they say about the ASN announcing it. It is off until you ask for it once; after that the database's presence on disk is enough, for lookups and for `search`. `--no-reputation` suppresses it for a run.

Reputation is shown in the default card, JSON and CSV output, not in `--oneline` output:

```bash
$ asname -R 77.91.71.90
...
  Reputation:
    Address:           firehol-level2, firehol-level3, ipsum:7
    ASN:               11 listed IPs (1.43% of 768 announced IPv4), max 7 lists
...

$ asname 8.8.8.8
...
  Reputation:
    Address:           not listed
    ASN:               233 listed IPs (0.0103% of 2252800 announced IPv4), max 2 lists
...
```

The address-level tags are:

| Tag | Meaning |
|---|---|
| `spamhaus-drop:SBLnnnnnn` | The address is inside a [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) block: hijacked or criminal-operated space. Block it outright. |
| `ipsum:N` | [IPsum](https://github.com/stamparm/ipsum) lists the address on N of the 30+ public feeds it aggregates. IPsum's author suggests 3 or more as a blocking threshold. |
| `firehol-level2` | [FireHOL level 2](https://iplists.firehol.org/?ipset=firehol_level2): reported attacking within the last 48 hours. |
| `firehol-level3` | [FireHOL level 3](https://iplists.firehol.org/?ipset=firehol_level3): reported attacking within the last 30 days. |
| `c2intel:<framework>` | [C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds): a command-and-control server of an attack framework (mostly Cobalt Strike), verified in the last 30 days. |
| `threatfox:<family>` | [abuse.ch ThreatFox](https://threatfox.abuse.ch/): reported in the last week as that malware family's infrastructure. Needs a free abuse.ch Auth-Key in `ASNAME_ABUSECH_AUTH_KEY`; only its IP indicators are used. |
| `feodo:<family>` | [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/): a botnet command-and-control server for that malware family (QakBot, Emotet...). Block it; an internal host talking to it is probably infected. |

The ASN-level summary is the useful signal for spotting a dodgy ASN:

- **Spamhaus ASN-DROP**: Spamhaus considers the whole ASN to be operated by or for criminals. This is the strongest single signal.
- **Spamhaus DROP prefixes**: how many DROP blocks the ASN announces.
- **Listed IPs**: distinct addresses inside the ASN's routes that IPsum or FireHOL name, with the share of its announced IPv4 space when the prefix database has its routes. Every large network has some listed addresses, so judge by the share, not the count: Google's 233 are 0.01% of its space, while AS211486's 11 are 1.43% of three /24s.
- **max N lists**: the highest IPsum count among those addresses.

In the default card output the AS card for an ASN lookup or `search` result shows the ASN summary. `--json` carries the same data under `reputation`, including `listed_share_pct`, and `--csv` adds `reputation` and `asn_reputation` columns.

The database is about 10 MB and builds in under ten seconds. Like the other databases it is refreshed when older than `--max-age`. `asname update --reputation-only` refreshes it on demand. Per-ASN counts are attributed using the ASN database at build time, so `asname update` builds it last.

FireHOL level 1 is not used: it includes the full bogon list, so private and unallocated space would be reported as listed, and it otherwise repeats Spamhaus DROP. AbuseIPDB, IBM X-Force and similar services need an API key per lookup and do not fit an offline database.

### Pretty mode

Lookup and search results are displayed as a structured, multi-line card layout with plenty of whitespace and terminal color highlights. This is the default; `--pretty` (or `-p`) asks for it explicitly, and `--oneline` (or `-o`) prints one line per result instead. For `country` and `city`, whose default is a plain CIDR list, `--pretty` gives a card with block counts:

```bash
$ asname 94.249.188.188
Target: 94.249.188.188
────────────────────────────────────────────────────────────
  Address Details:
    IP Address:        94.249.188.188 (IPv4)

  Autonomous System:
    ASN:               AS215365
    Organization:      Threatoff Tom Gewiese, DE

  Location:
    Country:           Finland (FI) [netblock registration]
    Allocated in:      Germany (DE) [RIR allocation]
    Geofeed:           Helsinki, Finland [the network's own geofeed]
    City:              Germany [MaxMind GeoLite2 geolocation]
    City:              Kirchberg, Bavaria, Germany [DB-IP geolocation]

  Registry Netblock:
    Netname / Org:     Threatoff
    Registered:        2026-09-03 (2 months ago)
    Source:            Offline Index

  Network Classification:
    Category:          hosting

  Reputation:
    Address:           not listed
    ASN:               58 listed IPs (0.87% of 6656 announced IPv4), max 2 lists
────────────────────────────────────────────────────────────
```

Location shows every answer asname has, each labelled: the registration country, the network's own geofeed when you have opted in to geofeeds, and the city from each city database present (MaxMind and DB-IP). They answer different questions and can disagree; above, the operator's feed says Finland while both estimates say Germany.

The address's blocklists read out in words: `IPsum: on 2 feeds`, `FireHOL level 2: attacks in the last 48 h`, `Spamhaus DROP (SBL123)`.

An IPv6 address inside a NAT64 prefix is looked up as the IPv4 address it carries, with a `NAT64:` line saying so. On an IPv6-only network (a phone hotspot, most mobile carriers) the resolver makes up such addresses for sites with no IPv6, and a registry lookup of one names the carrier, not the site.

`--verbose` (or `-v`) ends each card with Data Sources, the database or live query behind each field shown:

```bash
$ asname -v 8.8.8.8
  ...
  Data Sources:
    ASN:               BGP RIB dump (RouteViews or RIPE RIS), offline
    Organization:      RIPE NCC AS names list (asn.txt), offline
    Country:           RIR delegation stats (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC), offline
    City:              MaxMind GeoLite2 geolocation, offline
    City:              DB-IP geolocation, offline
    Netblock:          RIR WHOIS dumps, offline
    Category:          Cloud provider ranges (incl. Azure Service Tags), Tor exits, VPN server lists, iCloud Private Relay, MISP warninglists, Team Cymru bogons, bgp.tools tags, PeeringDB, offline
    Reputation:        Spamhaus DROP and ASN-DROP, IPsum, FireHOL level 2 and 3, abuse.ch Feodo Tracker and ThreatFox, C2IntelFeeds, offline
```

Colors are enabled automatically on interactive terminals and suppressed when piped, unless forced with `--color`. Use `--no-color` (or set the `NO_COLOR` environment variable) to disable colors explicitly.

### JSON lines mode

Add `--json` (or `-j`) to emit results in JSON Lines (`JSONL`) format, one JSON object per resolved IP:

```bash
$ asname --json 8.8.8.8
{"target":"8.8.8.8","host":null,"ip":"8.8.8.8","version":4,"asn":{"number":15169,"asn_string":"AS15169","name":"GOOGLE - Google LLC, US","announced":true},"country":{"code":"US","name":"United States"},"city":{"name":"Mountain View, California, United States","present":true},"category":{"tags":["cdn","content","hosting","vpn"],"raw":"cdn, content, hosting, vpn"}}
```

### CSV mode

Add `--csv` to emit a header row and then one CSV row per result, ready for a spreadsheet or `csvkit`. It works for lookups, `--stream`, `search`, `country` and `city`, and carries the same fields as `--json`. A field with several values (an ASN's prefixes, a netblock's CIDRs, category tags) separates them with spaces, and an unknown value is left empty:

```bash
$ asname --csv --v4-only dns.google
target,host,ip,version,asn,as_name,country_code,country_name,city,netblock,netblock_source,netblock_country,netblock_created,category,reputation,asn_reputation,reverse_dns,prefixes,error
dns.google,dns.google,8.8.4.4,4,AS15169,"GOOGLE - Google LLC, US",US,United States,"Mountain View, California, United States",Google LLC,offline,,,cdn hosting vpn,,"915 listed IPs (0.0420% of 2179584 announced IPv4), max 7 lists",,,
dns.google,dns.google,8.8.8.8,4,AS15169,"GOOGLE - Google LLC, US",US,United States,"Mountain View, California, United States",Google LLC,offline,,,cdn hosting vpn,,"915 listed IPs (0.0420% of 2179584 announced IPv4), max 7 lists",,,

$ asname country --csv NZ | head -3
country,cidr,version
NZ,14.1.32.0/19,4
NZ,14.102.98.0/23,4
```

The columns are:

| Command | Columns |
|---|---|
| lookup, `--stream` | `target,host,ip,version,asn,as_name,country_code,country_name,city,netblock,netblock_source,netblock_country,netblock_created,category,reputation,asn_reputation,reverse_dns,prefixes,error` |
| `search` | `type,asn,as_name,country,netname,org,range_start,range_end,version,cidrs,ipv4_prefixes,ipv6_prefixes,asn_reputation`, where `type` is `asn` or `netblock` |
| `country` | `country,cidr,version` |
| `city` | `city,region,country,cidr,version` |

In `--stream` mode a target that cannot be looked up is a row with only `target` and `error` filled, as in JSON mode.

### Streaming mode

Use `--stream` (or `-s`, or `-`) to read targets continuously from standard input in real time. Queries are resolved concurrently with a single retry on transient DNS failures and output is flushed immediately:

```bash
# Pipe network logs into asname with JSONL and filter with jq
tail -f /var/log/nginx/access.log | awk '{print $1}' | asname --stream --json | jq -c '{ip, asn: .asn.asn_string, country: .country.code}'

# Stream from network capture tools
tshark -T fields -e ip.src | asname --stream --json
```

### REST API server

Run `asname --rest` to host a fast HTTP REST API daemon in the foreground on port `8086` (or configure via `--listen` / `ASNAME_LISTEN`):

```bash
$ asname --rest --city --netblock -r
asname REST API listening on http://127.0.0.1:8086
Databases: ASN (yes), Names (yes), Country (true), City (true), Netblock (true), Category (true), Reputation (true)
Ready to handle requests. Press Ctrl+C to shut down.
```

The REST API supports querying URLs, hostnames, and IP addresses with zero manual sanitization:

```bash
# Health check
curl -s http://127.0.0.1:8086/health

# Query with URL / hostname / IP / ASN via query parameter
curl -s "http://127.0.0.1:8086/v1/lookup?q=https://dns.google/resolve&reverse_dns=true"
curl -s "http://127.0.0.1:8086/v1/lookup?q=AS15169"

# Direct path lookup (IP, hostname, or ASN)
curl -s "http://127.0.0.1:8086/v1/lookup/1.1.1.1"
curl -s "http://127.0.0.1:8086/v1/lookup/AS13335"

# Search netblocks by organization name or netname
# AS name matches come in "asns", netblocks in "results"; scope=asns or
# scope=netblocks searches only one; fuzzy=true as --fuzzy does
curl -s "http://127.0.0.1:8086/v1/search?q=Cloudflare&limit=10"
curl -s "http://127.0.0.1:8086/v1/search?q=colo%20crossing&fuzzy=true"
# country=AU (a code or a name) as --in does; an AS number lists its netblocks
curl -s "http://127.0.0.1:8086/v1/search?q=telstra&country=AU"
curl -s "http://127.0.0.1:8086/v1/search?q=AS47692&scope=netblocks"

# Explore the routing table: len, family, country, as_country, asn, tag,
# reputation, min_ipsum, min_listed_pct, sort, limit, offset as the flags of
# `asname explore`; limit=0 for the counts and breakdown alone
curl -s "http://127.0.0.1:8086/v1/explore?len=8"
curl -s "http://127.0.0.1:8086/v1/explore?country=AU&reputation=drop"

# Each result also as `asname -p` prints it, in "text"
curl -s "http://127.0.0.1:8086/v1/lookup?q=8.8.8.8&text=true" | jq -r '.results[].text'

# Base64URL-encoded target lookup
curl -s "http://127.0.0.1:8086/v1/lookup/b64/aHR0cHM6Ly9leGFtcGxlLmNvbQ"

# Bulk batch lookup (JSON or plain text)
curl -s -X POST http://127.0.0.1:8086/v1/bulk \
  -H "Content-Type: application/json" \
  -d '{"targets": ["8.8.8.8", "AS15169", "dns.google"], "reverse_dns": true}'

# Which databases are on disk and loaded, how old they are, and the last update
curl -s http://127.0.0.1:8086/v1/status
```

#### Online lookups

A lookup can ask the registry (RDAP, or whois) for a netblock the offline database cannot name (ARIN
and LACNIC space; see [Filling the gaps with RDAP and whois](#filling-the-gaps-with-rdap-and-whois)),
and RIPEstat for the prefixes of an ASN the offline prefix database lacks. In
REST mode nothing is asked unless the request says so, with `whois=true`,
`online_prefixes=true`, or `online=true` for both (in a bulk JSON body,
`"whois": true` and so on). `--whois` and `--online-prefixes` make them the
default, which a request can turn off with `=false`; `--no-whois` and
`--no-online-prefixes` turn them off for the server, and a request asking for one
then answers `403`. Each request may make up to 25 registry queries.

```bash
# LACNIC space: no netblock offline, NIC.br's registration over RDAP ("source": "rdap")
curl -s "http://127.0.0.1:8086/v1/lookup?q=200.160.2.3&whois=true"

# Prefixes from RIPEstat when the prefix database has none
curl -s "http://127.0.0.1:8086/v1/lookup?q=AS13335&online_prefixes=true"
```

#### Updating databases through the API

Started with `--allow-updates` (`ASNAME_ALLOW_UPDATES`), the server can also
rebuild its databases, which is what the web UI's Databases tab uses. It also
checks every 6 hours for databases older than the refresh age (see
[Refresh age](#refresh-age)) and refreshes them, as a lookup on the command line
would. An update runs in the background; the server keeps answering from the
current files and switches to the new ones when the update finishes, without a
restart. Without `--allow-updates`, a server refreshes stale databases only when
it starts.

```bash
$ asname --rest --allow-updates

# Rebuild the reputation and category databases (any absent one is built)
curl -s -X POST http://127.0.0.1:8086/v1/update \
  -H "Content-Type: application/json" \
  -d '{"databases": ["reputation", "category"]}'

# Refresh every database on disk, as `asname update` does
curl -s -X POST http://127.0.0.1:8086/v1/update -H "Content-Type: application/json" -d '{}'

# Only what is older than --max-age, or only what the last update left out
curl -s -X POST http://127.0.0.1:8086/v1/update -H "Content-Type: application/json" -d '{"stale_only": true}'
curl -s -X POST http://127.0.0.1:8086/v1/update -H "Content-Type: application/json" -d '{"incremental": true}'

# Progress (the log of the running or last update), and cancelling it
curl -s http://127.0.0.1:8086/v1/update
curl -s -X DELETE http://127.0.0.1:8086/v1/update -H "Content-Type: application/json"
```

The databases are named `asn` (which includes the ASN prefixes), `names`,
`country`, `city`, `netblock`, `category` and `reputation`. Only one update runs
at a time; asking for another answers `409`.

The same server can change two settings kept in the data directory, which the
`asname` command sharing it follows too: the refresh age, and whether ASN
updates import IPv6 routes (as `asname update --ipv6` and `--no-ipv6` do, from
the next update of the ASN database).

```bash
# Refresh databases older than a week; 0 is never
curl -s -X PUT http://127.0.0.1:8086/v1/settings \
  -H "Content-Type: application/json" -d '{"max_age_hours": 168}'

# Import IPv6 routes from the next ASN update
curl -s -X PUT http://127.0.0.1:8086/v1/settings \
  -H "Content-Type: application/json" -d '{"ipv6_routes": true}'
```

A refresh age given to the server on its command line (`--max-age`,
`ASNAME_MAX_AGE` or `--no-update`) cannot be changed this way; asking answers
`409`.

Updates download hundreds of megabytes and rewrite the data directory, so the
server accepts them, and setting changes, only from a page on its own origin: the request must be JSON,
must not come from another site (`Origin`, `Sec-Fetch-Site`), and must be
addressed to an IP address, `localhost` or this machine's own name. That stops a
web page you visit from starting one, even through a domain re-pointed at your
machine. The API has no login, so keep `--allow-updates` servers on
`127.0.0.1`, or behind something that authenticates, rather than open to a
network.

#### What the server logs

The server writes one line per request to standard output (the journal, under
systemd), with the query string, so the log shows what was looked up and
searched for; a bulk lookup adds its targets. The web UI's polling of
`/v1/status` and `/v1/update`, `/health` and the UI's own files are left out
when they succeed. Every line of a database update's progress is logged too, as
`[update]`, between an "update started" and an "update finished" line, so the
journal keeps the history of every update; the Databases tab shows only the last
one.

```text
[REST] GET /v1/lookup?q=92.113.115.76&text=true 200 410µs (127.0.0.1:57750)
[REST] POST /v1/bulk?text=true 200 2.1ms (127.0.0.1:57760) targets=8.8.8.8,1.1.1.1
[REST] api update started: reputation
[update] asname: downloading https://www.spamhaus.org/drop/drop_v4.json
[REST] api update finished (err=<nil>, reloaded=true)
```

### Web UI

`asname` ships an optional web UI, built with IBM's
[Carbon Design System](https://carbondesignsystem.com/), that the REST server
serves itself with `--web-dir`:

```bash
make web        # npm ci && npm run build, into web/dist
asname --rest --allow-updates --web-dir web/dist
# open http://127.0.0.1:8086/
```

It has four tabs, and **Help** (how to read the answers) and **API** (every
endpoint, with a curl example to copy) buttons in the header:

- **Lookup**: IPs, hostnames, URLs or ASNs, one per line, each shown as a card
  with the fields `asname -p` shows: ASN, country, city, netblock, category,
  reputation, reverse DNS and announced prefixes, with where each came from. A
  field the databases have no answer for says so rather than being left out.
  Each card opens with **What this means**: where the address most likely is,
  reconciling its registration, allocation and geolocation, and plain-language
  findings, worst first (blocklists, Spamhaus DROP in its network, Tor or VPN,
  leased or anonymised space, a recently registered block, the kind of
  network). Every field has an (i) explaining it and each tag shown, written for
  someone new to triage. **Copy summary** copies the `asname -p` card with those
  findings, for a ticket. Click an ASN to look it up. An **Online lookups**
  switch asks the registries (RDAP, or whois) and RIPEstat for what the offline databases lack (try
  `200.160.2.3`).
- **Search**: AS names and registry netblocks by organisation or network name,
  with a **Fuzzy match** switch (see [Fuzzy search](#fuzzy-search)), a
  **Country** filter (Worldwide by default) and tips; an AS number lists every
  netblock inside it. Click a column heading to sort. **Copy** gives the ASNs,
  the prefixes (the ASNs' announced prefixes and the netblocks' CIDRs,
  deduplicated and sorted, for a block list), both tables as aligned text, CSV,
  or the JSON.
- **Explore**: the routing table, filtered as `asname explore` does, with the
  matches broken down by country, kind of network and origin AS (click one to
  filter on it), paged, and the same copy buttons. An ASN's card links to its
  netblocks and to Explore.
- **Databases**: what is on disk and loaded, how old each database is, and
  buttons to update the ones you choose, refresh everything, refresh only what
  is stale, or retry what the last update left out, with the update's log as it
  runs; and the refresh age and IPv6 routes settings. Without `--allow-updates`
  it shows the status only. **Data sources** lists every public source each
  database is built from (cloud ranges, Tor exits, each VPN provider's list,
  PeeringDB, bgp.tools, the blocklists, the registries' dumps...), with a link,
  what it provides, and whether the last update used it, how many entries it
  gave, or failed. For the category database it also lists the VPN server list
  behind every `vpn:<provider>` tag and how old that list is, flagging any over
  six months old.

A banner on every tab says when a database is missing, older than the refresh
age, or left incomplete by its last update, or when an update is running.

The UI talks to the asname that served it. Settings can point it at another
server instead, which must then run with `--cors`, and which only accepts
updates from its own page. Lookups and searches are linkable
(`#/lookup?q=8.8.8.8`, `#/search?q=cloudflare&country=US`,
`#/explore?len=8`), and there is a light and a dark
theme. See [web/README.md](web/README.md) to work on it.

### Running as a service

The Makefile installs the REST server and the web UI as a systemd service on
`127.0.0.1:8086`. Build and install the binary and the UI first:

```bash
make build web
sudo make install install-web
```

Then either a system service, which runs as its own unprivileged user
(`DynamicUser`) with its databases in `/var/lib/asname`, sandboxed so it can
write nothing else:

```bash
sudo make install-service      # enables and starts asname.service
journalctl -u asname -f        # the first start downloads the core databases
sudo make uninstall-service    # keeps /var/lib/private/asname
```

or a user service that runs as you and shares `~/.asname` with the `asname`
command, so nothing is downloaded twice:

```bash
make install-user-service      # systemctl --user enable --now asname
loginctl enable-linger         # optional: keep it running after you log out
make uninstall-user-service
```

Both run `asname --rest --allow-updates --web-dir /usr/local/share/asname/web`.
`LISTEN`, `BINDIR` and `WEBDIR` change the address and paths, e.g.
`sudo make install-service LISTEN=127.0.0.1:9000`. The refresh age is left to the
web UI unless `MAX_AGE` fixes it, e.g. `sudo make install-service MAX_AGE=168h`
for a week. Re-running an install target after `make install` or
`make install-web` picks up the new files; restart the service to use them.

### Refresh age

Databases are refreshed when older than 30 days. To change that, either:

- pass `--max-age` (or set `ASNAME_MAX_AGE`), such as `--max-age 168h` for a
  week or `--max-age 0` for never, which applies to that run; or
- choose it on the web UI's Databases tab (or with `PUT /v1/settings`), which
  saves it in the data directory as `settings.json`, where the `asname` command
  and any server sharing the directory follow it.

`--max-age` and `ASNAME_MAX_AGE` win over the saved age, and `--no-update` turns
refreshing off.

### Manual Updates

You can manually trigger an update of the local databases using:

```bash
asname update
```

You can also update specific databases using the `--db-only`, `--names-only`, `--country-only`, `--city-only`, `--netblock-only`, `--category-only` or `--reputation-only` flags.

#### Incremental updates

Some databases are built from several sources and are still written when one of them cannot be read: the netblock database without a registry whose dump was cut off, the category database without the Tor exit list, or with gluetun's copy of a VPN provider's server list instead of the provider's own. Each update records what it could not read in `~/.asname/update-record.json`, and when anything was left out it ends with a line such as:

```
asname: incomplete: netblock (missing RIPE), category (missing Tor, NordVPN server API)
asname: run `asname update --incremental` to retry only these
```

`asname version` lists what each database's last update left out, under that database's line.

A netblock update that cannot read a whole registry keeps the existing database rather than replace it with one blind to that region, unless the existing database was itself built without one. The update reports the failure, and `--incremental` retries it.

`asname update --incremental` (or `-i`) rebuilds only the databases whose last update failed or left a source out, plus any missing core database. Every source that did download, from the registry dumps to each cloud provider's ranges, VPN server list, bgp.tools tag and blocklist, is reused from the cache for 24 hours, and an interrupted download resumes where it stopped. A retry within that window therefore contacts only the providers that failed. After 24 hours the retry downloads that database's sources again in full. Combine it with the `--*-only` flags to limit the retry to those databases. When nothing is incomplete it says so and downloads nothing.

`asname version` shows when each database was last updated, its size, and whether it is due for a refresh. The update time is when `asname` last wrote the file, which is also what `--max-age` is measured against; the city database also records when DB-IP built its data. A database whose last update could not read one of its sources says so on the next line, for example `incomplete: missing PeeringDB`, followed by a reminder to run `asname update --incremental`. Add `-j` for JSON, where the same appears as `missing` and `last_error`, along with `sources` (every public source the database is built from, its URL, what it provides and how it fared in the last update: `recorded`, `entries`, `failed`, `note`) and, for the category database, `vpn_lists` (the list behind each `vpn:<provider>` tag and its date). Updates record each source's result from 0.17 on; for a database last updated before that, only failures are known. `GET /v1/status` returns the same under `store.databases`.

```bash
$ asname version
asname v0.14.0

Databases in ~/.asname (auto-refreshed when older than 30 days):
  ASN           asname.db      updated 2026-11-16 16:07 (40 minutes ago)  11.3 MB
  AS names      asn_db.txt     updated 2026-11-16 16:07 (40 minutes ago)  7.2 MB
  Country       country.db     updated 2026-11-16 16:07 (39 minutes ago)  8.3 MB
  ASN prefixes  prefixes.db    updated 2026-11-16 16:07 (40 minutes ago)  6.7 MB
  City          city.mmdb      updated 2026-11-16 16:08 (39 minutes ago)  126.9 MB  data built 2026-11-01
  Netblock      netblock.db    updated 2026-11-16 16:39 (7 minutes ago)  372.1 MB
  Category      category.db    updated 2026-11-16 16:33 (14 minutes ago)  2.6 MB
  Reputation    reputation.db  updated 2026-11-16 16:13 (34 minutes ago)  10.5 MB

IPv6 routes: off (`asname update --ipv6` to import them)
```

### RIB Sources and Fallback

The IP to ASN database is built from an MRT RIB dump. `asname` tries the following archives in order and stops at the first that yields a database, so an outage at one archive does not stop an update:

| Order | Archive | Download | Compression |
| --- | --- | --- | --- |
| 1 | [RouteViews route-views2](http://archive.routeviews.org/bgpdata/) | ~75 MB | bzip2 |
| 2 | [RIPE RIS rrc04](https://data.ris.ripe.net/rrc04/) (CIXP Geneva) | ~70 MB | gzip |
| 3 | [RIPE RIS rrc00](https://data.ris.ripe.net/rrc00/) (multi-hop, most complete) | ~400 MB | gzip |

RouteViews and RIPE RIS are run by different organisations on separate infrastructure, so the fallback is a genuine second opinion rather than a second address for the same server.

To use a specific dump instead of the list above, pass its URL:

```bash
asname update --db-only --rib-url https://data.ris.ripe.net/rrc12/2026.09/bview.20260911.0000.gz
```

The dump is decompressed according to its file extension, so any `.bz2` or `.gz` MRT TABLE_DUMP_V2 file works. Records the decoder cannot read are skipped and counted rather than failing the import, and the count is printed; RIS dumps carry ADD_PATH RIB entries (RFC 8050) and path attribute type codes 20, 21 and 255, which account for roughly 250,000 skipped records out of an rrc04 dump. A dump that yields no usable records at all is treated as a failure, so the next archive is tried. Other RIS collectors are listed at [data.ris.ripe.net](https://data.ris.ripe.net/), and other RouteViews collectors under [archive.routeviews.org](http://archive.routeviews.org/); they vary considerably in size and in how many full-table peers they carry.

### IPv6 routes

By default the ASN and prefix databases hold IPv4 routes only, so an IPv6 address looks up as `ASN: N/A` and an ASN lists no IPv6 prefixes. To include IPv6 routes:

```bash
asname update --ipv6
```

With RouteViews this also downloads the newest [route-views6](http://archive.routeviews.org/route-views6/bgpdata/) dump (~25 MB), since route-views2 collects IPv4 only; if either dump cannot be fetched, the update falls back to RIPE RIS as usual. RIS dumps carry both families already, and their IPv6 routes are dropped when IPv6 is off. An update with `--rib-url` imports the IPv6 routes that one dump holds.

The choice is remembered by the marker file `~/.asname/ipv6-routes`, so later updates, including automatic refreshes, keep importing IPv6 routes. `asname update --no-ipv6` goes back to IPv4 only. `ASNAME_IPV6=1` has the same effect as `--ipv6`, and library callers set `UpdateOptions.IPv6`.

## Database Locations

By default, `asname` stores its auto-updating databases in your home directory under `~/.asname/`. The following files will be created:

- `~/.asname/asname.db`: The binary LC-trie database for IP to ASN resolution.
- `~/.asname/asn_db.txt`: The text file mapping ASNs to their respective names.
- `~/.asname/prefixes.db`: The binary ASN-to-announced-prefixes database, built alongside `asname.db` during BGP RIB updates; ~15 MB.
- `~/.asname/country.db`: The binary LC-trie database for IP to Country mapping.
- `~/.asname/city.mmdb`: The DB-IP Lite city database, in MaxMind DB format. Only present if you have enabled city lookups; ~125 MB.
- `~/.asname/netblock.db`: The IP to registry netblock index, built from the RIRs' bulk whois dumps. Only present if you have enabled netblock lookups.
- `~/.asname/category.db`: The IP and ASN to category index. Only present if you have enabled category lookups; under 1 MB.
- `~/.asname/reputation.db`: The IP and ASN to blocklist index. Only present if you have enabled reputation lookups; ~10 MB.
- `~/.asname/whois-consent.json`: Whether you agreed to live registry (RDAP or whois) lookups, and when you were asked. Delete it to be asked again; it expires after an hour anyway.
- `~/.asname/rdap-ipv4.json`, `rdap-ipv6.json`, `rdap-asn.json`: IANA's RDAP bootstrap files, saying which registry's RDAP server holds which addresses and AS numbers. Written on the first online netblock lookup and fetched again after a week; safe to delete.
- `~/.asname/online-prefixes-consent.json`: The same, for looking up an ASN's prefixes on RIPEstat.
- `~/.asname/ipv6-routes`: Present when `asname update --ipv6`, or the web UI, opted into IPv6 routes; see [IPv6 routes](#ipv6-routes).
- `~/.asname/settings.json`: The refresh age chosen in the web UI, if one was; see [Refresh age](#refresh-age).
- `~/.asname/contact.json`: The contact address sent to bgp.tools, or a note that you declined. Delete it to be asked again.
- `~/.asname/update-record.json`: When each database was last updated, how each of its sources fared, and which could not be read; see [Incremental updates](#incremental-updates).
- `~/.asname/cache/`: The source files downloaded to build the databases above (BGP RIB dump, RIR delegation and whois dumps, cloud provider ranges, VPN server lists, bgp.tools tags, PeeringDB, blocklists and so on). Entries are reused for 24 hours and deleted once older than that, so an update that fails partway through does not download the same files again on the next attempt. An interrupted download is resumed where it stopped rather than restarted. A download that receives nothing for 60 seconds is abandoned as interrupted, so a connection that stops forwarding data cannot hang an update. A source that downloads but will not parse is dropped from the cache so the next update fetches it again. Because the cache applies to every update, two updates less than 24 hours apart build from the same data; delete the directory to force fresh downloads. The directory is safe to delete at any time.

You can override this directory by setting the `ASNAME_DIR` environment variable or using the `--dir` flag. You can also override the path to individual databases using the `ASNAME_DB`, `ASNAME_NAMES`, `ASNAME_PREFIXES`, `ASNAME_COUNTRY`, `ASNAME_CITY`, `ASNAME_NETBLOCK`, `ASNAME_CATEGORY` and `ASNAME_REPUTATION` environment variables or their respective flags.

## Credits

The LC-trie implementation and the binary database format under `pkg/binarytrie`
and `pkg/database` are derived from [asnlookup](https://github.com/banviktor/asnlookup)
by [@banviktor](https://github.com/banviktor), used under the Apache License 2.0.
Those files have been modified
for use here — the database type was reworked into an interface, trie
optimization was parallelised, and the marshalling header was changed. Each file
carries a notice to that effect.

Data comes from [RouteViews](http://archive.routeviews.org/) and
[RIPE RIS](https://data.ris.ripe.net/) (BGP RIB dumps),
[RIPE NCC](https://ftp.ripe.net/ripe/asnames/) (ASN names), and the RIR
delegation statistics files (IP to country).

Category data comes from the providers' own published ranges ([AWS](https://ip-ranges.amazonaws.com/ip-ranges.json),
[Google Cloud](https://www.gstatic.com/ipranges/cloud.json), [Oracle](https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json),
[Fastly](https://api.fastly.com/public-ip-list), [Cloudflare](https://www.cloudflare.com/ips-v4),
[Azure](https://www.microsoft.com/en-us/download/details.aspx?id=56519), DigitalOcean, Linode and Vultr),
Apple's [iCloud Private Relay egress ranges](https://mask-api.icloud.com/egress-ip-ranges.csv),
the [MISP warninglists](https://github.com/MISP/misp-warninglists) (CC0),
[Team Cymru's bogon lists](https://www.team-cymru.com/bogon-reference), the [Tor Project](https://check.torproject.org/torbulkexitlist)
exit list, the server lists NordVPN, Mullvad, Surfshark, Private Internet
Access, IVPN, AirVPN, Windscribe and PrivadoVPN publish for their apps,
[gluetun's VPN server lists](https://github.com/qdm12/gluetun-servers)
(MIT licence) for other providers, [PeeringDB](https://www.peeringdb.com/) network types, and
[bgp.tools](https://bgp.tools/) operator tags.

Reputation data comes from [Spamhaus DROP and ASN-DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/), [IPsum](https://github.com/stamparm/ipsum), [FireHOL](https://github.com/firehol/blocklist-ipsets) levels 2 and 3 and [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/), [C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds) and, with your own abuse.ch key, [ThreatFox](https://threatfox.abuse.ch/). Spamhaus DROP is free for any use under the [Spamhaus DROP terms](https://www.spamhaus.org/drop/terms/).

Netblock data comes from the RIRs' bulk whois dumps, [APNIC](https://ftp.apnic.net/apnic/whois/),
[RIPE NCC](https://ftp.ripe.net/ripe/dbase/split/) and [AFRINIC](https://ftp.afrinic.net/dbase/),
together with ARIN's [delegated statistics](https://ftp.arin.net/pub/stats/arin/),
or ARIN's [bulk whois](https://www.arin.net/reference/research/bulkwhois/) if you
supply your own API key. Each is downloaded on request and none is redistributed
with this tool.

City data is the DB-IP Lite database — IP Geolocation by [DB-IP](https://db-ip.com),
licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). It is
downloaded on request and is not redistributed with this tool.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).
