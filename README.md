# asname

`asname` is a fast, offline command-line utility written in Go for resolving IP addresses, hostnames and URLs to their Autonomous System Number (ASN), the AS owner's name, and the geographical country.

Lookups are answered from local LC-trie databases, so there is no per-query network call and no API key or rate limit to worry about.

## Features

- **Blazing Fast**: Uses offline LC-trie databases for instantaneous IP lookups.
- **Takes Whatever You Have**: An IP address, a hostname, a URL you pasted from a browser, or a file listing any mix of them.
- **ASN & Prefix Lookups**: Query any ASN (`AS15169`) to see its owner, country, classification, and all announced IPv4/IPv6 prefixes.
- **Organization Search**: Search AS names and millions of registry netblocks by organization name or netname (`asname search <query>`) to find matching ASNs with their announced prefixes, IP ranges and CIDRs.
- **Country Listings**: List every IP block registered to a country as CIDRs (`asname country AU`), ready for a firewall or allowlist.
- **City Listings**: List every IP block the city database locates in a city (`asname city "Brisbane, AU"`).
- **Pretty Cards, JSONL & CSV**: Format results as clean multi-line cards (`--pretty`), streamable JSON objects (`--json`), or CSV for spreadsheets (`--csv`).
- **Real-Time Streaming**: Feed targets directly through standard input pipes (`--stream`).
- **REST API Server**: Run as an instant in-memory HTTP daemon (`--rest`) on port `8086`.
- **Names the Actual Owner**: An optional database built from the RIRs' bulk whois dumps resolves an address to the netblock it was assigned in, so a suballocation reports the customer holding it rather than the datacentre announcing it.
- **Says What It Is**: Another optional database classifies an address as cloud, CDN, hosting, residential ISP, mobile or Tor exit, from the providers' own published ranges and operator-declared network types.
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
	asname.WithReverseDNS(true),                  // Enable PTR reverse DNS lookups
	asname.WithAutoUpdate(720 * time.Hour),       // Refresh databases older than 30 days
	asname.WithLog(os.Stderr),                    // Show warnings and update progress (silent by default)
	asname.WithOnlinePrefixes(true),              // Let LookupASN fetch prefixes the local DB lacks (off by default)
)
```

The client reads the same environment variables as the CLI: `ASNAME_DIR` for the data directory, and `ASNAME_DB`, `ASNAME_NAMES`, `ASNAME_COUNTRY`, `ASNAME_CITY`, `ASNAME_NETBLOCK`, `ASNAME_CATEGORY` and `ASNAME_PREFIXES` for individual files. An explicit `WithDataDir` beats `ASNAME_DIR`, a per-file variable beats the directory, and `WithCustomPaths` beats both.

A field the databases cannot answer is empty in a `Result`; the CLI's `Unknown` and `N/A` are display text only. `Result.String()` puts them back for printing.

The library never writes to stderr and never prompts. Messages go to `WithLog` or nowhere. It also stays offline unless you opt in: whois with `WithWhois`, and online ASN prefix lookups with `WithOnlinePrefixes`.

### Updating Databases

```go
// Download the core databases (ASN, names, country) unconditionally.
err := asname.Update(ctx, asname.UpdateOptions{Log: os.Stderr})

// Refresh only what is missing or older than 30 days, and see what changed.
refreshed, err := asname.UpdateStale(ctx, asname.UpdateOptions{City: true, Netblock: true}, 720*time.Hour)
```

A throttled or failing download (HTTP 429 or 5xx) is retried with backoff, honouring `Retry-After`. A database that still cannot be rebuilt keeps its existing file, and the other databases are still updated; the returned error names each failure. The country database is only rewritten when every registry answered, because one missing registry would leave a whole region without countries. Cancelling `ctx` abandons the download in progress. The partial file is kept and resumed next time, and no further database is started. A category update identifies itself to bgp.tools with `UpdateOptions.ContactEmail`, then `$ASNAME_CONTACT_EMAIL`. With neither, it skips the bgp.tools tags rather than asking.

## Usage

Simply pass an IP address to resolve its information:

```bash
$ asname 8.8.8.8
IP: 8.8.8.8 | ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States
```

The argument can equally be a hostname. Every address the name resolves to is looked up, one line each:

```bash
$ asname dns.google
Host: dns.google | IP: 8.8.8.8 | ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States
Host: dns.google | IP: 8.8.4.4 | ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States
```

Or a URL, so you can paste one straight from a browser. The scheme, credentials, port, path, query and fragment are stripped and whatever host remains is looked up:

```bash
$ asname 'https://dns.google:443/resolve?name=example.com'
Host: dns.google | IP: 8.8.8.8 | ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States
```

Or a file listing any mix of the above, one entry per line. Blank lines and `#` comments are ignored, and only the first field of a line is read, so columnar files work as they are:

```bash
$ cat hosts.txt
# resolvers to check
8.8.8.8
1.1.1.1          # cloudflare
https://github.com/anthropics

$ asname hosts.txt
IP: 8.8.8.8 | ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States
IP: 1.1.1.1 | ASN: AS13335 | Name: CLOUDFLARENET - Cloudflare, Inc., US | Country: AU, Australia
Host: github.com | IP: 4.237.22.38 | ASN: AS8075 | Name: MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US | Country: US, United States
```

Entries that cannot be resolved are reported on stderr and the rest of the file is still printed; `asname` then exits non-zero. Names are resolved concurrently, so a long file is not paced by DNS latency.

An argument that parses as an IP address is always treated as one; an ASN formatted as `AS<number>` (or `asn<number>`) resolves the Autonomous System directly; otherwise an existing file is read as a list, and anything else is treated as a hostname or URL.

Add `--reverse-dns` (or `-r`) to also send a reverse DNS query and include PTR names in the output:

```bash
$ asname --reverse-dns 8.8.8.8
IP: 8.8.8.8 | ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States | Reverse DNS: dns.google
```

`--v4-only` and `--v6-only` keep one address family everywhere: a hostname's addresses, an ASN's prefixes, and the blocks `search`, `country` and `city` list.

Flags can go before or after the arguments, so `asname 8.8.8.8 -r`, `asname city Brisbane -p` and `asname -p city Brisbane` all work. The output, address family and data file flags (`-p`, `-j`, `--csv`, `--color`, `--v4-only`, `--dir`, `--city-db`...) work with every command; the rest belong to lookups (`-r`, `--rest`...) or to `search` (`--limit`, `--asns-only`...) alone.

### ASN lookups

Pass an Autonomous System Number directly (`AS15169`, `asn13335`, or just `AS` followed by the number) to look up the organization, country, network classification, and all announced BGP IP prefixes:

```bash
$ asname AS15169
ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States | Category: cdn, content, hosting, vpn | Prefixes: 1415 announced (1239 IPv4, 176 IPv6)
Announced Prefixes:
  8.8.4.0/24
  8.8.8.0/24
  34.0.0.0/20
  ...
```

Add `--pretty` (or `-p`) for a structured card layout summarizing the prefix breakdown and sample list:

```bash
$ asname --pretty AS15169
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

Prefixes are answered instantly and offline via `~/.asname/prefixes.db`, which is built automatically from BGP RIB dumps during `asname update`. If the offline prefix database is not yet generated, `asname` automatically falls back to live queries via the RIPE Stat API.


### City lookups

City-level geolocation is optional and off by default, because the database is
large. Enable it once with `--city` (or `-c`), which downloads it:

```bash
$ asname --city 8.8.8.8
IP: 8.8.8.8 | ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States | City: Mountain View, California
```

After that the flag is not needed — the city is included whenever the database
is present, and refreshed along with everything else:

```bash
$ asname 1.1.1.1
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

### Registry netblocks

The ASN tells you who announces an address, which is often not who is using it.
A suballocation inside a datacentre's range is announced by the datacentre, so
the AS name is theirs and the customer's name appears nowhere.

The RIRs record that assignment as an `inetnum` object in their whois databases,
and they publish those databases in bulk. `asname` can build a local index of
them, enabled once with `--netblock` (or `-n`):

```bash
$ asname --netblock 183.177.54.135
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
[Filling the gaps with whois](#filling-the-gaps-with-whois).

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

### Filling the gaps with whois

LACNIC publishes no usable dump and ARIN's open data names only part of its
space, but both registries will answer a question about a single address over
port 43. So when an address has no offline netblock, asname can ask the registry
directly:

```bash
$ asname 8.8.8.8
asname: 8.8.8.8 has no offline netblock: not every registry publishes owner data
asname: in a form that can be indexed offline. Query whois over the network for
asname: addresses like it? Either answer is remembered for an hour. [y/N] y
IP: 8.8.8.8 | ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States | Netblock: GOGL (Google LLC) [whois]
```

Every other lookup asname does is offline, so this one is asked about rather
than assumed. **Either answer is remembered for an hour**, in
`~/.asname/whois-consent.json`, so a session's work is one question rather than
one per address. After the hour it asks again.

Answers that came from the network are marked `[whois]`, because unlike the rest
of the output they are not reproducible offline and reveal to the registry which
addresses you are looking at.

- `--whois` queries without asking, and does not record an answer — use this in
  scripts.
- `--no-whois` never queries and never asks.
- With no terminal to ask (a pipe, a cron job), asname does not query and prints
  a one-line reminder that `--whois` exists.

The query goes to `whois.iana.org` first to find which registry holds the
address, then to that registry, so it works for any address and not just the two
gaps. asname only reaches for it when the offline database has nothing *and* the
address is one some registry has actually delegated, which keeps it away from
reserved and unallocated space.

Registries rate-limit port 43 hard, so one run stops after 25 online lookups and
says so. A throttled registry answers with a well-formed but empty document; that
is reported as a failure rather than silently shown as an unknown netblock.

`--whois` also works with no netblock database at all, if you would rather ask
the registries every time than keep 300 MB on disk.

Each registry also publishes placeholder objects covering the ranges it does
*not* hold, so that a whois query for someone else's address points you at the
right registry instead of returning nothing. Those are dropped while building,
since a placeholder naming APNIC is worse than no answer at all.

Building the database downloads roughly 290 MB of registry dumps, takes about
two minutes and needs ~1.5 GB of memory while it runs. The result is around
300 MB on disk holding some 6.7 million ranges. It is read from disk by binary
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
$ asname search "Cloudflare"
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
only IPv4 or IPv6 netblocks and ASN prefixes:

```bash
# Only AS names, or only registry netblocks
asname search --asns-only "Valve"
asname search --netblocks-only "Valve"

# Limit results (default unlimited; caps the ASNs and the netblocks separately)
asname search --limit 10 "Google"

# IPv4 only or IPv6 only (netblocks and ASN prefixes; ASNs stay listed)
asname search --v4-only "Fastly"
asname search --v6-only "Amazon"

# Output formats: pretty cards (--pretty), JSON Lines (--json) or CSV (--csv)
asname search --pretty --limit 5 "Cloudflare"
asname search --json "Valve" | jq -r 'select(.type == "netblock") | .cidrs[] + " " + .org'
asname search --json --asns-only "Valve" | jq -r '.ipv4_prefixes[]?'
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
university, Tor exit and so on.

```bash
$ asname -C 13.32.0.1
IP: 13.32.0.1 | ASN: AS16509 | Name: AMAZON-02 - Amazon.com, Inc., US | Country: US, United States | Category: cdn, cloud:aws

$ asname 139.130.4.5
IP: 139.130.4.5 | ASN: AS1221 | Name: ASN-TELSTRA Telstra Limited, AU | Country: AU, Australia | Category: isp, mobile
```

Like the other optional databases, the flag is needed once; after that its
presence on disk is enough. `--no-category` suppresses it for a run. The
database is small — under a megabyte — and builds in a few seconds.

**The two halves of it are not equally trustworthy, and the difference matters.**

*Prefixes* come from the providers themselves. AWS, Google, Oracle, Fastly,
Cloudflare, DigitalOcean, Linode and Vultr all publish the exact ranges they
use, and AWS goes further and names the service, which is how `13.32.0.1` is
reported as a CDN while `52.95.110.1` is just a machine. The Tor Project
publishes its exit list the same way. When one of these names an address, that
is the provider speaking about its own network and it settles the question.

*ASNs* come from bgp.tools' operator tags and PeeringDB's self-reported network
type. These describe **the operator, not the address**: the tag means the AS is
associated with that thing somewhere, not that every address in it is. So
`asname -C 8.8.8.8` reports `cdn, hosting, vpn` — all true of Google, none of
them specifically true of that resolver. Read AS-level answers as "this is the
sort of network it is", not as a fact about the address.

Because of that, a prefix match wins outright and the AS tags are not consulted;
otherwise every EC2 address would inherit `vpn` from Amazon's AS, on the grounds
that somebody, somewhere, runs a VPN on EC2.

Three of bgp.tools' tags are left out entirely for the same reason. `tor` sits
on a quarter of the eyeball ISPs in their data, because subscribers run relays.
`anycast` sits on Telstra, Google and Amazon, because everyone large anycasts
something. `biznet` means the network sells business connectivity, which
describes an ISP rather than the business at the far end.

**What is missing is VPN and proxy detection**, beyond operators who run their
own AS. Most consumer VPN exits are rented from ordinary cloud providers and
are, from routing data alone, indistinguishable from any other virtual machine.
Telling them apart takes active measurement — connecting to the service and
watching where it comes out — which is why that data is sold rather than
published. The Tor exit list is the one exact, free piece of it.

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
$ asname -u -r 8.8.8.8
IP: 8.8.8.8                                | ASN: AS15169      | Name: GOOGLE - Google LLC, US                                      | Country: US, United States         | Reverse DNS: dns.google
```

### Pretty mode

Add `--pretty` (or `-p`) to display results in a structured, multi-line card layout with plenty of whitespace and terminal color highlights:

```bash
$ asname --pretty 8.8.8.8
Target: 8.8.8.8
────────────────────────────────────────────────────────────
  Address Details:
    IP Address:        8.8.8.8 (IPv4)

  Autonomous System:
    ASN:               AS15169
    Organization:      GOOGLE - Google LLC, US

  Location:
    Country:           United States (US)
    City:              Mountain View, California

  Registry Netblock:
    Netname / Org:     GOGL (Google LLC)
    Source:            Live WHOIS

  Network Classification:
    Category:          cdn, content, hosting, vpn
────────────────────────────────────────────────────────────
```

Colors are enabled automatically on interactive terminals and suppressed when piped, unless forced with `--color`. Use `--no-color` (or set the `NO_COLOR` environment variable) to disable colors explicitly.

### JSON lines mode

Add `--json` (or `-j`) to emit results in JSON Lines (`JSONL`) format, one JSON object per resolved IP:

```bash
$ asname --json 8.8.8.8
{"target":"8.8.8.8","host":null,"ip":"8.8.8.8","version":4,"asn":{"number":15169,"asn_string":"AS15169","name":"GOOGLE - Google LLC, US","announced":true},"country":{"code":"US","name":"United States"},"city":{"name":"Mountain View, California","present":true},"category":{"tags":["cdn","content","hosting","vpn"],"raw":"cdn, content, hosting, vpn"}}
```

### CSV mode

Add `--csv` to emit a header row and then one CSV row per result, ready for a spreadsheet or `csvkit`. It works for lookups, `--stream`, `search`, `country` and `city`, and carries the same fields as `--json`. A field with several values (an ASN's prefixes, a netblock's CIDRs, category tags) separates them with spaces, and an unknown value is left empty:

```bash
$ asname --csv --v4-only dns.google
target,host,ip,version,asn,as_name,country_code,country_name,city,netblock,netblock_source,category,reverse_dns,prefixes,error
dns.google,dns.google,8.8.4.4,4,AS15169,"GOOGLE - Google LLC, US",US,United States,"Mountain View, California",Google LLC,offline,cdn content hosting vpn,,,
dns.google,dns.google,8.8.8.8,4,AS15169,"GOOGLE - Google LLC, US",US,United States,"Mountain View, California",Google LLC,offline,cdn content hosting vpn,,,

$ asname country --csv NZ | head -3
country,cidr,version
NZ,14.1.32.0/19,4
NZ,14.102.98.0/23,4
```

The columns are:

| Command | Columns |
|---|---|
| lookup, `--stream` | `target,host,ip,version,asn,as_name,country_code,country_name,city,netblock,netblock_source,category,reverse_dns,prefixes,error` |
| `search` | `type,asn,as_name,country,netname,org,range_start,range_end,version,cidrs,ipv4_prefixes,ipv6_prefixes`, where `type` is `asn` or `netblock` |
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
Databases: ASN (yes), Names (yes), Country (true), City (true), Netblock (true), Category (true)
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
# scope=netblocks searches only one
curl -s "http://127.0.0.1:8086/v1/search?q=Cloudflare&limit=10"

# Base64URL-encoded target lookup
curl -s "http://127.0.0.1:8086/v1/lookup/b64/aHR0cHM6Ly9leGFtcGxlLmNvbQ"

# Bulk batch lookup (JSON or plain text)
curl -s -X POST http://127.0.0.1:8086/v1/bulk \
  -H "Content-Type: application/json" \
  -d '{"targets": ["8.8.8.8", "AS15169", "dns.google"], "reverse_dns": true}'
```

### Manual Updates

You can manually trigger an update of the local databases using:

```bash
asname update
```

You can also update specific databases using the `--db-only`, `--names-only`, `--country-only`, `--city-only`, `--netblock-only`, or `--category-only` flags.

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

## Database Locations

By default, `asname` stores its auto-updating databases in your home directory under `~/.asname/`. The following files will be created:

- `~/.asname/asname.db`: The binary LC-trie database for IP to ASN resolution.
- `~/.asname/asn_db.txt`: The text file mapping ASNs to their respective names.
- `~/.asname/prefixes.db`: The binary ASN-to-announced-prefixes database, built alongside `asname.db` during BGP RIB updates; ~15 MB.
- `~/.asname/country.db`: The binary LC-trie database for IP to Country mapping.
- `~/.asname/city.mmdb`: The DB-IP Lite city database, in MaxMind DB format. Only present if you have enabled city lookups; ~125 MB.
- `~/.asname/netblock.db`: The IP to registry netblock index, built from the RIRs' bulk whois dumps. Only present if you have enabled netblock lookups.
- `~/.asname/category.db`: The IP and ASN to category index. Only present if you have enabled category lookups; under 1 MB.
- `~/.asname/whois-consent.json`: Whether you agreed to live whois lookups, and when you were asked. Delete it to be asked again; it expires after an hour anyway.
- `~/.asname/contact.json`: The contact address sent to bgp.tools, or a note that you declined. Delete it to be asked again.
- `~/.asname/cache/`: The source files downloaded to build the databases above (BGP RIB dump, RIR delegation and whois dumps, and so on). Entries are reused for 24 hours and deleted once older than that, so an update that fails partway through does not download the same files again on the next attempt. An interrupted download is resumed where it stopped rather than restarted. The directory is safe to delete at any time.

You can override this directory by setting the `ASNAME_DIR` environment variable or using the `--dir` flag. You can also override the path to individual databases using the `ASNAME_DB`, `ASNAME_NAMES`, `ASNAME_PREFIXES`, `ASNAME_COUNTRY`, `ASNAME_CITY`, `ASNAME_NETBLOCK`, and `ASNAME_CATEGORY` environment variables or their respective flags.

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
DigitalOcean, Linode and Vultr), the [Tor Project](https://check.torproject.org/torbulkexitlist)
exit list, [PeeringDB](https://www.peeringdb.com/) network types, and
[bgp.tools](https://bgp.tools/) operator tags.

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
