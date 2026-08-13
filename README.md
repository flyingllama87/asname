# asname

`asname` is a fast, offline command-line utility written in Go for resolving IP addresses, hostnames and URLs to their Autonomous System Number (ASN), the AS owner's name, and the geographical country.

Lookups are answered from local LC-trie databases, so there is no per-query network call and no API key or rate limit to worry about.

## Features

- **Blazing Fast**: Uses offline LC-trie databases for instantaneous IP lookups.
- **Takes Whatever You Have**: An IP address, a hostname, a URL you pasted from a browser, or a file listing any mix of them.
- **Names the Actual Owner**: An optional database built from the RIRs' bulk whois dumps resolves an address to the netblock it was assigned in, so a suballocation reports the customer holding it rather than the datacentre announcing it.
- **Auto-Updating**: Automatically fetches the latest RouteViews RIB dumps, RIPE ASN names, and RIR Delegation Statistics to build and maintain its own fresh databases when they get older than 30 days.
- **Fully Standalone**: A single static binary — no Cgo, and no `geoiplookup` or other system tool to install alongside it.

## Installation

```bash
go install github.com/flyingllama87/asname@latest
```

Or build and install from a clone using the provided Makefile, which stamps the
version into the binary and links it statically:

```bash
make build
sudo make install
```

This compiles the tool and places the `asname` binary into `/usr/local/bin/`.
Run `make test` to run the test suite.

## Usage

Simply pass an IP address to resolve its information:

```bash
$ asname 8.8.8.8
IP: 8.8.8.8 → ASN: AS15169 → Name: GOOGLE - Google LLC, US → Country: US, United States
```

The argument can equally be a hostname. Every address the name resolves to is looked up, one line each:

```bash
$ asname dns.google
Host: dns.google → IP: 8.8.8.8 → ASN: AS15169 → Name: GOOGLE - Google LLC, US → Country: US, United States
Host: dns.google → IP: 8.8.4.4 → ASN: AS15169 → Name: GOOGLE - Google LLC, US → Country: US, United States
```

Or a URL, so you can paste one straight from a browser. The scheme, credentials, port, path, query and fragment are stripped and whatever host remains is looked up:

```bash
$ asname 'https://dns.google:443/resolve?name=example.com'
Host: dns.google → IP: 8.8.8.8 → ASN: AS15169 → Name: GOOGLE - Google LLC, US → Country: US, United States
```

Or a file listing any mix of the above, one entry per line. Blank lines and `#` comments are ignored, and only the first field of a line is read, so columnar files work as they are:

```bash
$ cat hosts.txt
# resolvers to check
8.8.8.8
1.1.1.1          # cloudflare
https://github.com/anthropics

$ asname hosts.txt
IP: 8.8.8.8 → ASN: AS15169 → Name: GOOGLE - Google LLC, US → Country: US, United States
IP: 1.1.1.1 → ASN: AS13335 → Name: CLOUDFLARENET - Cloudflare, Inc., US → Country: AU, Australia
Host: github.com → IP: 4.237.22.38 → ASN: AS8075 → Name: MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US → Country: US, United States
```

Entries that cannot be resolved are reported on stderr and the rest of the file is still printed; `asname` then exits non-zero. Names are resolved concurrently, so a long file is not paced by DNS latency.

An argument that parses as an IP address is always treated as one; otherwise an existing file is read as a list, and anything else is treated as a hostname or URL.

Add `--reverse-dns` (or `-r`) to also send a reverse DNS query and include PTR names in the output:

```bash
$ asname --reverse-dns 8.8.8.8
IP: 8.8.8.8 → ASN: AS15169 → Name: GOOGLE - Google LLC, US → Country: US, United States → Reverse DNS: dns.google
```

### City lookups

City-level geolocation is optional and off by default, because the database is
large. Enable it once with `--city` (or `-c`), which downloads it:

```bash
$ asname --city 8.8.8.8
IP: 8.8.8.8 → ASN: AS15169 → Name: GOOGLE - Google LLC, US → Country: US, United States → City: Mountain View, California
```

After that the flag is not needed — the city is included whenever the database
is present, and refreshed along with everything else:

```bash
$ asname 1.1.1.1
IP: 1.1.1.1 → ASN: AS13335 → Name: CLOUDFLARENET - Cloudflare, Inc., US → Country: AU, Australia → City: Sydney, New South Wales
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
IP: 183.177.54.135 → ASN: AS15830 → Name: Equinix Equinix (EMEA) Acquisition Enterprises B.V., NL → Country: AU, Australia → Netblock: SISS-SY4 (Secure Internet Storage Solutions)
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
| ARIN | North America | **Requires a signed agreement.** See below |

Both gaps can be filled a query at a time over whois instead — see
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

Without it, addresses in the ARIN region simply have no netblock and fall back to
what the ASN says — which is most of North America, so it is worth having if you
look at those addresses often.

### Filling the gaps with whois

Neither registry publishes a dump asname can index, but both will happily answer
a question about a single address over port 43. So when an address has no
offline netblock, asname can ask the registry directly:

```bash
$ asname 8.8.8.8
asname: 8.8.8.8 has no offline netblock: ARIN and LACNIC do not publish theirs
asname: in a form that can be indexed offline. Query whois over the network for
asname: addresses like it? Either answer is remembered for an hour. [y/N] y
IP: 8.8.8.8 → ASN: AS15169 → Name: GOOGLE - Google LLC, US → Country: US, United States → Netblock: GOGL (Google LLC) [whois]
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

Add `--uniform` (or `-u`) to print aligned fields:

```bash
$ asname -u -r 8.8.8.8
IP: 8.8.8.8                                → ASN: AS15169      → Name: GOOGLE - Google LLC, US                                      → Country: US, United States         → Reverse DNS: dns.google
```

### Manual Updates

You can manually trigger an update of the local databases using:

```bash
asname update
```

You can also update specific databases using the `--db-only`, `--names-only`, `--country-only`, `--city-only`, or `--netblock-only` flags.

## Database Locations

By default, `asname` stores its auto-updating databases in your home directory under `~/.asname/`. The following files will be created:

- `~/.asname/asname.db`: The binary LC-trie database for IP to ASN resolution.
- `~/.asname/asn_db.txt`: The text file mapping ASNs to their respective names.
- `~/.asname/country.db`: The binary LC-trie database for IP to Country mapping.
- `~/.asname/city.mmdb`: The DB-IP Lite city database, in MaxMind DB format. Only present if you have enabled city lookups; ~125 MB.
- `~/.asname/netblock.db`: The IP to registry netblock index, built from the RIRs' bulk whois dumps. Only present if you have enabled netblock lookups.
- `~/.asname/whois-consent.json`: Whether you agreed to live whois lookups, and when you were asked. Delete it to be asked again; it expires after an hour anyway.

You can override this directory by setting the `ASNAME_DIR` environment variable or using the `--dir` flag. You can also override the path to individual databases using the `ASNAME_DB`, `ASNAME_NAMES`, `ASNAME_COUNTRY`, `ASNAME_CITY`, and `ASNAME_NETBLOCK` environment variables or their respective flags.

## Credits

The LC-trie implementation and the binary database format under `pkg/binarytrie`
and `pkg/database` are derived from [asnlookup](https://github.com/banviktor/asnlookup)
by [@banviktor](https://github.com/banviktor), used under the Apache License 2.0.
Those files have been modified
for use here — the database type was reworked into an interface, trie
optimization was parallelised, and the marshalling header was changed. Each file
carries a notice to that effect.

Data comes from [RouteViews](http://archive.routeviews.org/) (BGP RIB dumps),
[RIPE NCC](https://ftp.ripe.net/ripe/asnames/) (ASN names), and the RIR
delegation statistics files (IP to country).

Netblock data comes from the RIRs' bulk whois dumps — [APNIC](https://ftp.apnic.net/apnic/whois/),
[RIPE NCC](https://ftp.ripe.net/ripe/dbase/split/) and [AFRINIC](https://ftp.afrinic.net/dbase/),
plus [ARIN](https://www.arin.net/reference/research/bulkwhois/) if you supply
your own API key. Each is downloaded on request and none is redistributed with
this tool.

City data is the DB-IP Lite database — IP Geolocation by [DB-IP](https://db-ip.com),
licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). It is
downloaded on request and is not redistributed with this tool.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).
