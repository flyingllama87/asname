# Feature Specification: `--json` Mode (JSONL Output)

## 1. Overview & Objective

The `--json` (or `-j`) mode outputs lookup results in JSON Lines format (`JSONL` / newline-delimited JSON). Each resolved IP address produces a single valid JSON object per line.

This enables programmatic consumption, Unix pipeline integration with tools like `jq`, ingestion into search/indexing platforms (OpenSearch, Elasticsearch, ClickHouse), and automated security scripting.

---

## 2. CLI Invocation & Flags

- **Flags**: `--json`, `-j`
- **Output Format**: JSON Lines (`application/x-ndjson`), one line per resolved IP.
- **Compatibility**:
  - Mutually exclusive with `--uniform` (`-u`) and `--pretty` (`-p`).
  - Compatible with all database options (`--city`, `--netblock`, `--category`, `--reverse-dns`).
  - Compatible with `--stream` mode.

```bash
asname --json 8.8.8.8
asname -j 1.1.1.1 2606:4700::6810:85e5
cat targets.txt | asname --stream --json | jq '.asn.number'
```

---

## 3. JSON Schema Specification

Each line matches the following schema:

```json
{
  "target": "string",
  "host": "string | null",
  "ip": "string",
  "version": 4,
  "asn": {
    "number": 15169,
    "asn_string": "AS15169",
    "name": "GOOGLE - Google LLC, US",
    "announced": true
  },
  "country": {
    "code": "US",
    "name": "United States"
  },
  "city": {
    "name": "Mountain View, California",
    "present": true
  },
  "netblock": {
    "handle": "GOGL",
    "organization": "Google LLC",
    "raw": "GOGL (Google LLC)",
    "source": "whois",
    "live_query": true
  },
  "category": {
    "tags": ["cdn", "hosting", "vpn"],
    "raw": "cdn, hosting, vpn"
  },
  "reverse_dns": {
    "names": ["dns.google"],
    "raw": "dns.google"
  }
}
```

### 3.1 Field Dictionary

| Field | Type | Description |
|---|---|---|
| `target` | `string` | The original raw input string (e.g. URL, hostname, or IP). |
| `host` | `string \| null` | Extracted hostname if input was a hostname or URL; `null` for literal IP. |
| `ip` | `string` | Canonical IP address string. |
| `version` | `integer` | IP version (`4` or `6`). |
| `asn` | `object \| null` | ASN resolution details. `number` is integer (0 if unannounced), `announced` is boolean. |
| `country` | `object \| null` | ISO 3166-1 alpha-2 `code` and full country `name`. |
| `city` | `object \| null` | Resolved city name (omitted or null if city DB not enabled / not found). |
| `netblock` | `object \| null` | Registry assignment details (`handle`, `organization`, and `source`: `"offline"`, `"whois"`, or `null`). |
| `category` | `object \| null` | Classification tag array (e.g. `["cloud:aws", "cdn"]`). |
| `reverse_dns` | `object \| null` | PTR lookup result (`names` string array). Omitted or `null` unless `-r` is enabled. |

---

## 4. Examples

### 4.1 Minimal IPv4 Lookup
Command:
```bash
asname --json 8.8.8.8
```
Output (single line):
```json
{"target":"8.8.8.8","host":null,"ip":"8.8.8.8","version":4,"asn":{"number":15169,"asn_string":"AS15169","name":"GOOGLE - Google LLC, US","announced":true},"country":{"code":"US","name":"United States"}}
```

### 4.2 Full IPv6 Lookup with Hostname, City, Netblock, Categories & RDNS
Command:
```bash
asname --json -r -c -n -C "https://dns.google/resolve"
```
Output (single line):
```json
{"target":"https://dns.google/resolve","host":"dns.google","ip":"2001:4860:4860::8888","version":6,"asn":{"number":15169,"asn_string":"AS15169","name":"GOOGLE - Google LLC, US","announced":true},"country":{"code":"US","name":"United States"},"city":{"name":"Mountain View, California","present":true},"netblock":{"handle":"GOGL","organization":"Google LLC","raw":"GOGL (Google LLC)","source":"whois","live_query":true},"category":{"tags":["cdn","hosting","vpn"],"raw":"cdn, hosting, vpn"},"reverse_dns":{"names":["dns.google"],"raw":"dns.google"}}
```

### 4.3 Error Representation
When an entry fails DNS resolution or parsing during a batch / streaming run, error objects can be written to `stderr` or optionally emitted in the stream if configured:
```json
{"target":"nonexistent.domain.invalid","error":"lookup nonexistent.domain.invalid: no such host"}
```

---

## 5. Implementation Architecture

1. **Dedicated Struct Types**:
   Define `jsonLookupResult`, `jsonASN`, `jsonCountry`, `jsonNetblock`, etc., with explicit `omitempty` / `json:` struct tags in a new `json.go` file.
2. **Streaming Serialization**:
   Use `json.NewEncoder(os.Stdout)` to serialize and flush line-by-line without buffering the entire batch in memory.
3. **No External Dependencies**:
   Uses Go standard library `encoding/json`.
