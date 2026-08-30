# Feature Specification: `--rest` Mode (HTTP REST API Server)

## 1. Overview & Objective

The `--rest` mode runs `asname` as a high-performance HTTP REST daemon in the foreground.

Designed specifically for **SOC (Security Operations Center) and NOC (Network Operations Center) analysts**, security automations, and SIEM/SOAR integrations, the API allows querying raw IP addresses, hostnames, and arbitrary complex URLs without manual sanitization.

All databases are loaded and indexed once on startup; queries are answered from in-memory LC-tries with sub-millisecond offline lookup times.

---

## 2. Server Configuration & CLI Flags

- **Flag**: `--rest`
- **Default Bind Address**: `127.0.0.1:8086` (Safe local default, port 8086 avoids common 8080 conflicts)
- **Associated Flags**:
  - `--listen`, `-l`: Network address and port to bind (e.g. `0.0.0.0:8086`, `127.0.0.1:9000`). Configurable via `ASNAME_LISTEN` environment variable.
  - `--cors`: Enable permissive `Access-Control-Allow-Origin: *` headers for browser dashboards.
  - Database flags (`--city`, `--netblock`, `--category`, `--reverse-dns`) pre-load and activate the respective databases for the server lifecycle.

```bash
# Start server on default 127.0.0.1:8086
asname --rest

# Start server on all interfaces with city and netblock databases enabled
asname --rest --listen 0.0.0.0:8086 --city --netblock -r
```

---

## 3. Endpoints & Analyst-Friendly Query Interfaces

SOC analysts frequently deal with messy inputs (defanged URLs, full HTTP URLs with query parameters, ports, and credentials). The API provides multiple convenient query formats:

### 3.1 `GET /v1/lookup?q={target}` (Recommended for URLs & Scripts)
The most convenient endpoint for passing raw URLs and complex targets without URL path-routing escaping issues.

#### Example Request:
```bash
curl -s "http://127.0.0.1:8086/v1/lookup?q=https://phishing.site:8443/login?user=admin"
```

---

### 3.2 `GET /v1/lookup/{target...}` (Direct Path Lookup)
Allows passing bare IPs or hostnames directly in the path.

#### Example Request:
```bash
curl -s "http://127.0.0.1:8086/v1/lookup/8.8.8.8"
curl -s "http://127.0.0.1:8086/v1/lookup/dns.google?reverse_dns=true"
```

---

### 3.3 `GET /v1/lookup/b64/{base64url_target}` (Base64URL Safe Lookup)
Allows passing Base64URL-encoded strings to guarantee zero URL decoding or proxy routing issues for security scripts and URL analysis pipelines.

#### Example:
Query for `https://evil-bank.com/account`:
`aHR0cHM6Ly9ldmlsLWJhbmsuY29tL2FjY291bnQ`

```bash
curl -s "http://127.0.0.1:8086/v1/lookup/b64/aHR0cHM6Ly9ldmlsLWJhbmsuY29tL2FjY291bnQ"
```

---

### 3.4 `POST /v1/lookup` or `POST /v1/bulk` (Bulk JSON & Plaintext)
Supports batch lookups. Accepts either structured JSON or raw newline-delimited text payloads.

#### JSON Body:
```bash
curl -s -X POST "http://127.0.0.1:8086/v1/bulk" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": [
      "8.8.8.8",
      "1.1.1.1",
      "https://github.com/flyingllama87",
      "2606:4700::6810:85e5"
    ],
    "reverse_dns": true
  }'
```

#### Plaintext Body (`Content-Type: text/plain`):
```bash
curl -s -X POST "http://127.0.0.1:8086/v1/bulk" \
  -H "Content-Type: text/plain" \
  --data-binary $'8.8.8.8\n1.1.1.1\nhttps://github.com'
```

---

### 3.5 `GET /health` / `GET /ready`
Server health and loaded database status.

```bash
curl -s "http://127.0.0.1:8086/health"
```
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "databases": {
    "asn": true,
    "names": true,
    "country": true,
    "city": true,
    "netblock": true,
    "category": true
  }
}
```

---

## 4. Response Schemas

### 4.1 Single / Query Response (200 OK)

```json
{
  "query": "https://dns.google/resolve",
  "count": 2,
  "results": [
    {
      "ip": "8.8.8.8",
      "version": 4,
      "host": "dns.google",
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
        "name": "Mountain View, California"
      },
      "netblock": {
        "handle": "GOGL",
        "organization": "Google LLC",
        "source": "offline"
      },
      "category": {
        "tags": ["cdn", "hosting", "vpn"]
      },
      "reverse_dns": {
        "names": ["dns.google"]
      }
    },
    {
      "ip": "8.8.4.4",
      "version": 4,
      "host": "dns.google",
      "asn": {
        "number": 15169,
        "asn_string": "AS15169",
        "name": "GOOGLE - Google LLC, US",
        "announced": true
      },
      "country": {
        "code": "US",
        "name": "United States"
      }
    }
  ]
}
```

### 4.2 Error Response (400 Bad Request / 404 Not Found)

```json
{
  "error": "invalid target",
  "details": "lookup nonexistent.domain.invalid: no such host"
}
```

---

## 5. Concurrency & Daemon Lifecycle

1. **Foreground Execution & Logging**:
   - Runs in the foreground, logging incoming HTTP requests (`METHOD PATH STATUS DURATION`) to `stdout`.
2. **Read-Only Concurrency**:
   - In-memory tries, name maps, and file descriptor readers (`ReadAt` on netblock DB) are strictly read-only and scale to thousands of concurrent requests across all CPU cores.
3. **Graceful Shutdown**:
   - Listens for `SIGINT` / `SIGTERM`, shuts down HTTP listener with a 5-second graceful drain timeout, and closes open database handles cleanly.
