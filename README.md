# asname

`asname` is a fast, offline command-line utility written in Go for resolving IP addresses, hostnames and URLs to their Autonomous System Number (ASN), the AS owner's name, and the geographical country.

It mirrors the functionality of the original `asname` zsh helper, but executes fully standalone (no Cgo, no system `geoiplookup` dependency) by utilizing an optimized binary LC-trie database format.

## Features

- **Blazing Fast**: Uses offline LC-trie databases for instantaneous IP lookups.
- **Takes Whatever You Have**: An IP address, a hostname, a URL you pasted from a browser, or a file listing any mix of them.
- **Auto-Updating**: Automatically fetches the latest RouteViews RIB dumps, RIPE ASN names, and RIR Delegation Statistics to build and maintain its own fresh databases when they get older than 30 days.
- **Fully Standalone**: Built in Go without any Cgo bindings or external tool dependencies. 

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

You can also update specific databases using the `--db-only`, `--names-only`, or `--country-only` flags.

## Database Locations

By default, `asname` stores its auto-updating databases in your home directory under `~/.asname/`. The following files will be created:

- `~/.asname/asname.db`: The binary LC-trie database for IP to ASN resolution.
- `~/.asname/asn_db.txt`: The text file mapping ASNs to their respective names.
- `~/.asname/country.db`: The binary LC-trie database for IP to Country mapping.

You can override this directory by setting the `ASNAME_DIR` environment variable or using the `--dir` flag. You can also override the path to individual databases using the `ASNAME_DB`, `ASNAME_NAMES`, and `ASNAME_COUNTRY` environment variables or their respective flags.

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

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).
