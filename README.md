# asname

`asname` is a fast, offline command-line utility written in Go for resolving IP addresses to their Autonomous System Number (ASN), the AS owner's name, and the geographical country.

It mirrors the functionality of the original `asname` zsh helper, but executes fully standalone (no Cgo, no system `geoiplookup` dependency) by utilizing an optimized binary LC-trie database format.

## Features

- **Blazing Fast**: Uses offline LC-trie databases for instantaneous IP lookups.
- **Auto-Updating**: Automatically fetches the latest RouteViews RIB dumps, RIPE ASN names, and RIR Delegation Statistics to build and maintain its own fresh databases when they get older than 30 days.
- **Fully Standalone**: Built in Go without any Cgo bindings or external tool dependencies. 

## Installation

You can build and install `asname` directly using the provided Makefile:

```bash
make build
sudo make install
```

This will compile the tool and place the `asname` binary into `/usr/local/bin/`.

## Usage

Simply pass an IP address to resolve its information:

```bash
$ asname 8.8.8.8
IP: 8.8.8.8 → ASN: AS15169 → Name: GOOGLE - Google LLC, US → Country: US, United States
```

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
