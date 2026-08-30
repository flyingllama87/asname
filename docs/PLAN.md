# Comprehensive Feature Implementation Plan

This document synthesizes the design, architecture, CLI ergonomics, data schemas, module breakdown, testing strategy, and implementation plan for:
1. **Pretty Mode (`--pretty`, `-p`)** with terminal color auto-detection and generous whitespace.
2. **JSON Lines Mode (`--json`, `-j`)** for streaming and structured JSON output.
3. **Streaming Stdin Mode (`--stream`, `-s`)** with out-of-order fastest-first emission and DNS retry resilience.
4. **Foreground REST API Daemon (`--rest`)** on port `8086` tailored for SOC/NOC analysts with Base64URL and raw URL flexibility.

---

## 1. Feature Summary & Design Decisions

| Feature | Flags & Defaults | Key Technical Decisions | Ref Document |
|---|---|---|---|
| **Pretty Display** | `--pretty`, `-p`<br>`--color` / `--no-color` | Generous whitespace card layout, section headers, contextual metadata (IP version, ISO country code). Terminal ANSI colors enabled on TTY, stripped when piped unless `--color` is provided. | [`docs/pretty_mode.md`](pretty_mode.md) |
| **JSONL Output** | `--json`, `-j` | Streamable JSON Lines format (`one JSON object per line`). Rich structured types for ASN, Country, Netblock, Category, and Reverse DNS. | [`docs/json_mode.md`](json_mode.md) |
| **Streaming Mode** | `--stream`, `-s` | High-throughput line-by-line reading from `stdin`. Fastest-first out-of-order emission. Bounded worker pool. DNS lookup with 1x retry on transient failure and fast failure reporting. | [`docs/stream_mode.md`](stream_mode.md) |
| **REST API Server** | `--rest`<br>`--listen 127.0.0.1:8086`<br>`ASNAME_LISTEN` | Runs as foreground daemon. In-memory trie reuse. Analyst-friendly endpoints: `GET /v1/lookup?q=...`, `GET /v1/lookup/{target...}`, `GET /v1/lookup/b64/{b64target}`, `POST /v1/bulk` (JSON and plain text), and `GET /health`. | [`docs/rest_api.md`](rest_api.md) |

---

## 2. CLI Flags & Compatibility Matrix

### New Flags in `main.go`:
```go
// Output Format Flags (Mutually Exclusive: --pretty, --json, --uniform)
&cli.BoolFlag{
    Name:    "pretty",
    Aliases: []string{"p"},
    Usage:   "display output in a multi-line formatted card layout with generous whitespace",
},
&cli.BoolFlag{
    Name:    "color",
    Usage:   "force ANSI colored output even when stdout is piped",
},
&cli.BoolFlag{
    Name:    "no-color",
    Usage:   "suppress ANSI colored output (also respects NO_COLOR env var)",
},
&cli.BoolFlag{
    Name:    "json",
    Aliases: []string{"j"},
    Usage:   "output lookup results as JSON lines (JSONL)",
},

// Execution Mode Flags (Mutually Exclusive: Positional arg, --stream, --rest)
&cli.BoolFlag{
    Name:    "stream",
    Aliases: []string{"s"},
    Usage:   "stream and resolve targets line-by-line from stdin in real-time",
},
&cli.BoolFlag{
    Name:    "rest",
    Usage:   "run in foreground as an HTTP REST API server",
},
&cli.StringFlag{
    Name:    "listen",
    Aliases: []string{"l"},
    EnvVars: []string{"ASNAME_LISTEN"},
    Value:   "127.0.0.1:8086",
    Usage:   "network address and port to bind for the REST API server",
},
&cli.BoolFlag{
    Name:    "cors",
    Usage:   "enable permissive CORS headers on the REST API server",
},
```

---

## 3. Architecture & Data Flow

```text
                             ┌────────────────────────┐
                             │       CLI Parser       │
                             │      (urfave/cli)      │
                             └───────────┬────────────┘
                                         │
                   ┌─────────────────────┼─────────────────────┐
                   ▼                     ▼                     ▼
          [Positional Run]       [--stream Mode]        [--rest Mode]
          (Batch / Single)       (Stdin Worker Pool)    (HTTP net/http)
                   │                     │                     │
                   └─────────────────────┼─────────────────────┘
                                         ▼
                            ┌────────────────────────┐
                            │     Engine Lookups     │
                            │  - ASN / LC-trie       │
                            │  - Names DB            │
                            │  - Country DB          │
                            │  - City (MaxMind)      │
                            │  - Netblock (Binary)   │
                            │  - Category (Tags)     │
                            │  - Reverse DNS (PTR)   │
                            │  - DNS Resilient Retry │
                            └────────────┬───────────┘
                                         │
                   ┌─────────────────────┼─────────────────────┐
                   ▼                     ▼                     ▼
             Default/Uniform          Pretty               JSON / JSONL
               (Arrow / -u)       (Cards / -p / Color)     (JSONL / -j)
```

---

## 4. Planned File Structure

```text
/asname
├── docs/
│   ├── PLAN.md            # Master plan and architecture overview
│   ├── pretty_mode.md     # Pretty mode specification, mockups & color scheme
│   ├── json_mode.md       # JSON schema & JSONL stream specification
│   ├── stream_mode.md     # Stdin pipeline, worker pool & retry resilience
│   └── rest_api.md        # REST API endpoints, SOC/NOC query formats & specs
├── main.go                # CLI flags and root action router
├── engine.go              # Shared engine, lookupResult and lookups (refactored)
├── format.go              # Arrow / uniform formatters
├── pretty.go              # Card formatter, whitespace layout, ANSI colors & TTY detection
├── json.go                # JSON data models and JSONL serializer
├── stream.go              # Stdin scanner, worker queue, retry loop, signal handler
├── rest.go                # REST server, /v1/lookup, /v1/bulk, /health handlers
└── *_test.go              # Unit and integration test suites
```

---

## 5. Testing & Verification Strategy

1. **Unit Testing**:
   - `pretty_test.go`: Test card formatting, TTY detection mocking, field alignment, and IPv4 vs IPv6 badges.
   - `json_test.go`: Test JSONL serialization, validation against Go structs, and `omitempty` handling.
   - `stream_test.go`: Test `io.Pipe()` stream input, verify out-of-order emission, verify EOF and SIGPIPE behavior.
   - `rest_test.go`: Integration tests with `httptest.Server` verifying:
     - `GET /health`
     - `GET /v1/lookup/8.8.8.8`
     - `GET /v1/lookup?q=https://github.com/foo/bar`
     - `GET /v1/lookup/b64/...`
     - `POST /v1/bulk` with JSON and plaintext bodies
2. **DNS Resilience Test**:
   - Verify transient DNS retry behavior and fast failure when host is nonexistent.
3. **Regression Tests**:
   - Run `go test ./...` across the existing codebase to ensure zero regressions in database builders, trie searches, and update routines.
