# Reputation Database

The optional reputation database (`reputation.db`) flags addresses and ASNs named by free public blocklists. It is opt-in, in the same way as the category database:

- `--reputation` (`-R`) builds it if absent. Once present it is used on every lookup and search without the flag.
- `--no-reputation` suppresses it for a run.
- `asname update --reputation-only` refreshes it on demand. A plain `asname update` refreshes it when present, last, so per-ASN counts use the ASN database just rebuilt.
- Library: `asname.WithReputation(bool)`, `UpdateOptions.Reputation`, `Client.HasReputationDB()`, `Result.Reputation`, `Result.ASNReputation`, `ASNResult.ASNReputation`.
- Output: pretty, JSON and CSV modes only. The default one-line and `--uniform` output omit it.
- Path override: `--reputation-db` or `ASNAME_REPUTATION`.

## Sources

All sources are free, need no key, and were verified downloadable on 2026-10-12.

| Source | URL | Level | Format | Tag |
| :--- | :--- | :--- | :--- | :--- |
| Spamhaus ASN-DROP | https://www.spamhaus.org/drop/asndrop.json | ASN | JSON lines `{"asn":..,"asname":..}`, last line `{"type":"metadata"}` | ASN flag |
| Spamhaus DROP v4/v6 | https://www.spamhaus.org/drop/drop_v4.json, https://www.spamhaus.org/drop/drop_v6.json | CIDR | JSON lines `{"cidr":..,"sblid":..}` | `spamhaus-drop:SBLnnnnnn` |
| IPsum | https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt | IP | `IP<TAB>number of lists` | `ipsum:N` |
| FireHOL level 2 | https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset | IP/CIDR | netset | `firehol-level2` |
| FireHOL level 3 | https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset | IP/CIDR | netset | `firehol-level3` |

Volumes on 2026-10-12: ASN-DROP 431 ASNs, DROP 1,684 IPv4 and 91 IPv6 blocks, IPsum 119,353 addresses, FireHOL level 2 16,178 entries, level 3 10,901 entries. The built database held 126,501 prefixes and 7,774 ASNs in 10.3 MB, and took 6.6 seconds to build.

Excluded:

- FireHOL level 1 contains the full bogon list, so private and unallocated space would be reported as listed. Its remaining content duplicates Spamhaus DROP.
- AbuseIPDB, IBM X-Force and Honeylabs need an API key, a per-address query or a browser, and do not fit an offline bulk database.

## Build

Implemented in `internal/sources/reputationdata.go`.

1. Each list is downloaded and parsed. A list that fails is logged as a warning and skipped; the build fails only when nothing at all was imported.
2. A trie lookup returns only the most specific entry, so the tags of every listed block are copied into each more-specific entry inside it (`inheritCovering`). Without this, an IPsum address inside a DROP /24 would lose its DROP tag.
3. Per-ASN aggregates are attributed using the ASN database (`asname.db`). If it is missing or unreadable the aggregates are skipped with a warning and only the ASN-DROP flag is recorded.
   - `ListedIPs`: distinct IPv4 addresses from IPsum and FireHOL (blocks up to /16 are expanded and de-duplicated; larger blocks and IPv6 entries count once each), attributed to the ASN announcing them.
   - `DropPrefixes`: DROP blocks whose first address is announced by the ASN. DROP space is often unrouted, so many blocks attribute to no ASN.
   - `MaxLists`: the highest IPsum count among the ASN's listed addresses.

## File format

Little-endian. Implemented in `internal/sources/reputation.go`.

| Offset | Size | Field |
| :--- | :--- | :--- |
| 0 | 8 | Magic `ASNREP\x00\x01` |
| 8 | 8 | Trie length in bytes |
| 16 | 4 | Tag set count |
| 20 | 4 | ASN entry count |
| 24 | 8 | Build time, Unix seconds |
| 32 | trie length | LC-trie (`pkg/database` dump) mapping prefix to tag set index (0 means none) |
| | variable | Tag sets, each a comma-separated, sorted, NUL-terminated string |
| | 20 per ASN | ASN (4), flags (4, bit 0 = ASN-DROP), ListedIPs (4), DropPrefixes (4), MaxLists (4), sorted by ASN |

## Lookup

- Address: the trie returns the tag set. The engine sets `Reputation` to a non-nil empty slice when the database is loaded and nothing lists the address, so formatters can print "not listed" rather than omitting the field.
- ASN: the stored aggregates, plus `AnnouncedIPv4` computed at lookup time from `prefixes.db` (overlapping prefixes counted once). The listed share (`ListedIPs / AnnouncedIPv4`) is the main signal: large networks always have some listed addresses, so the count alone misleads. Observed on 2026-10-12: AS15169 (Google) 233 listed IPs, 0.0103% of 2,252,800 announced; AS211486 11 listed IPs, 1.43% of 768 announced; AS398324 (Censys) 1,382 listed IPs, 32% of 4,352 announced.
- Per-ASN results are cached in the engine (`sync.Map`), since counting announced space reads every prefix of the ASN. This took a 5,000 address batch from 1.6 s to 0.26 s.

## Refresh

The same as the other databases: auto-update refreshes it when older than `--max-age` (default 30 days), and the library's `UpdateStale` uses the caller's `maxAge`. Blocklists change daily, so `asname update --reputation-only` refreshes it on demand.
