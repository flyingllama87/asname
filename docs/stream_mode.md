# Feature Specification: `--stream` Mode (Streaming Stdin Processing)

## 1. Overview & Objective

The `--stream` (or `-s`) mode is engineered for pipeline integration where another program (e.g. `tail -f`, `zeek-cut`, `tcpdump`, `cat`, firewall log forwarders) streams IP addresses, hostnames, or URLs into `asname` via standard input (`stdin`).

Instead of collecting all targets in memory before executing, `asname` continuously ingests, resolves concurrently, and immediately flushes results to standard output.

---

## 2. CLI Invocation & Flags

- **Flags**: `--stream`, `-s`
- **Modifiers**:
  - Combined with `--json`: Streams JSON Lines (`JSONL`) in real time.
  - Combined with `--pretty`: Emits readable cards as each entry completes.
  - Combined with `--reverse-dns` (`-r`), `--city` (`-c`), `--netblock` (`-n`), `--category` (`-C`).

```bash
# Streaming log analysis with JSONL and jq
tail -f /var/log/nginx/access.log | awk '{print $1}' | asname -s -j | jq -c '{ip, asn: .asn.asn_string, country: .country.code}'

# Stream from network tools
tshark -T fields -e ip.src | asname --stream --json

# Streaming targets from stdin in pretty mode
cat hosts.txt | asname -s -p
```

---

## 3. Streaming Architecture & Concurrency Model

```text
               ┌───────────────────────┐
  stdin ──────►│  Line Scanner         │ (Reads line-by-line, trims whitespace & comments)
               └──────────┬────────────┘
                          │ target items
                          ▼
               ┌───────────────────────┐
               │ Dispatcher & Queue    │ (Buffered channel, e.g. cap 256)
               └──────────┬────────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
     [Worker 1]      [Worker 2]      [Worker N (16)]
     DNS (+Retry)    DNS (+Retry)    DNS (+Retry)
     Trie Lookup     Trie Lookup     Trie Lookup
          │               │               │
          └───────────────┼───────────────┘
                          │
                          ▼
               ┌───────────────────────┐
               │ Synchronized Flusher  │ (Immediate write + bufio.Flush to stdout)
               └───────────────────────┘
```

### 3.1 Emission Order (Fastest-First Throughput)
- Streaming runs in **fastest-first out-of-order mode**: as soon as any worker completes a lookup (local trie search takes microseconds, DNS takes milliseconds), it is emitted immediately.
- This ensures that a single unresolvable hostname with high DNS timeout never blocks thousands of IP addresses streaming behind it.

### 3.2 DNS Resilience & Retry Strategy
When feeding live streams from external tools, transient DNS issues or temporary resolver hiccups can occur.
- **DNS Retry Logic**:
  1. Primary DNS lookup with a bounded context timeout (e.g. 2.5s).
  2. If resolution fails with a transient network/temporary error (or server error), the worker retries **once** with a short 250ms backoff.
  3. If the retry fails or the host does not exist (`NXDOMAIN`), the target fails fast and reports to `stderr` (or emits an error JSON in `--json` mode) without stalling the rest of the stream.
- **Bounded Latency**: Total DNS wait per target capped at max ~4 seconds so unresponsive names don't tie up workers indefinitely.

### 3.3 Pipe Management & Signal Safety
- **Immediate Flush**: Every completed record calls `writer.Flush()` / `Sync()` so downstream pipes (like `jq --unbuffered` or `grep --line-buffered`) receive data instantly.
- **SIGPIPE Handling**: If the downstream consumer closes (e.g. `... | asname -s | head -n 10`), `asname` catches `EPIPE` / `SIGPIPE` and exits cleanly with code 0 without noisy stack traces.
- **Graceful EOF**: When `stdin` hits EOF, the worker queue is closed and the flusher drains all remaining in-flight queries before exiting.

---

## 4. Error Handling in Streams

- In **standard / pretty mode**: Failed targets print a concise warning to `stderr` (`asname: bad-host.test: lookup failed: no such host`) while successful entries continue printing to `stdout`.
- In **JSONL mode**: An optional structured error line can be written to `stdout` (e.g. `{"target":"bad-host.test","error":"no such host"}`) so downstream JSON parsers can track dropped packets/queries.
