# Feature Specification: `--pretty` Mode

## 1. Overview & Objective

The default output of `asname` is a dense, single-line format:
```text
IP: 8.8.8.8 | ASN: AS15169 | Name: GOOGLE - Google LLC, US | Country: US, United States
```

The `--pretty` (or `-p`) flag introduces a multi-line, card-based visual format designed with generous vertical and horizontal whitespace, clear section groupings, high-value contextual metadata (IP version, ISO country code, broken-out category badges, netblock provenance), and subtle terminal color highlights.

---

## 2. CLI Invocation & Flags

- **Flags**:
  - `--pretty`, `-p`: Enable card layout.
  - `--color`: Force ANSI color output even when stdout is piped.
  - `--no-color`: Disable ANSI color output completely (respects `NO_COLOR` standard env var).
- **Auto-Detection Behavior**:
  - When output is a **TTY / interactive terminal**: ANSI colors are **enabled** by default.
  - When output is **piped or redirected to a file**: ANSI colors are **disabled** by default to keep data clean, unless explicitly overridden with `--color`.
- **Compatibility**:
  - Mutually exclusive with `--uniform` (`-u`) and `--json` (`-j`).
  - Compatible with all database options (`--city`, `--netblock`, `--category`, `--reverse-dns`).
  - Compatible with `--stream` mode.

```bash
# Pretty output with auto-detected terminal colors
asname -p 8.8.8.8

# Pretty output with all databases enabled
asname -p -r -c -n -C 1.1.1.1

# Piping pretty output with forced colors
asname -p --color 8.8.8.8 | less -R
```

---

## 3. Visual Styling & Color Scheme

When colors are active:
- **Card Borders (`───`)**: Dim / Muted Gray
- **Section Headers** (`Address Details:`, `Autonomous System:`): Bold Cyan
- **Field Labels** (`IP Address:`, `ASN:`, `Country:`): Dim / Gray
- **Field Values**:
  - Target / IP / Host: Bright White / Bold
  - ASN: Bright Magenta / Yellow
  - Country / City: Bright Green
  - Netblock: Bright Cyan
  - Category tags: Bright Yellow / Blue badges
  - Live WHOIS indicator: Yellow `[Live WHOIS]`

When colors are inactive (piped or `NO_COLOR`):
- Uses clean ASCII/Unicode structure (`───`) and whitespace indentation without ANSI escape codes.

---

## 4. Visual Layout Mockups

### 4.1 Single IP Target (Basic Databases)

```text
Target: 8.8.8.8
────────────────────────────────────────────────────────────
  Address Details:
    IP Address:        8.8.8.8 (IPv4)

  Autonomous System:
    ASN:               AS15169
    Organization:      GOOGLE - Google LLC, US

  Location:
    Country:           United States (US)
────────────────────────────────────────────────────────────
```

### 4.2 Full Target with All Features (RDNS, City, Netblock, Category)

```text
Target: 13.32.0.1
────────────────────────────────────────────────────────────
  Address Details:
    IP Address:        13.32.0.1 (IPv4)
    Reverse DNS:       server-13-32-0-1.sea19.r.cloudfront.net

  Autonomous System:
    ASN:               AS16509
    Organization:      AMAZON-02 - Amazon.com, Inc., US

  Location:
    Country:           United States (US)
    City:              Seattle, Washington

  Registry Netblock:
    Netname / Org:     AMAZON-CF (Amazon.com, Inc.)
    Source:            Offline Index

  Network Classification:
    Category:          cdn, cloud:aws
────────────────────────────────────────────────────────────
```

### 4.3 Hostname Expanding to Multiple IPs

```text
Target: dns.google (Host)
Found 2 addresses:

[1/2] 8.8.8.8 (IPv4)
────────────────────────────────────────────────────────────
  Host:                dns.google
  IP Address:          8.8.8.8
  Reverse DNS:         dns.google

  Autonomous System:
    ASN:               AS15169
    Organization:      GOOGLE - Google LLC, US

  Location:
    Country:           United States (US)
    City:              Mountain View, California

  Registry Netblock:
    Netname / Org:     GOGL (Google LLC)
    Source:            Live WHOIS [whois.arin.net]
────────────────────────────────────────────────────────────

[2/2] 8.8.4.4 (IPv4)
────────────────────────────────────────────────────────────
  Host:                dns.google
  IP Address:          8.8.4.4
  Reverse DNS:         dns.google

  Autonomous System:
    ASN:               AS15169
    Organization:      GOOGLE - Google LLC, US

  Location:
    Country:           United States (US)
    City:              Mountain View, California

  Registry Netblock:
    Netname / Org:     GOGL (Google LLC)
    Source:            Live WHOIS [whois.arin.net]
────────────────────────────────────────────────────────────
```

---

## 5. Technical Implementation Details

1. **Terminal Detection**:
   - Check `isatty(stdout)` using standard file descriptor check or `golang.org/x/term` / minimal `syscall.SYS_IOCTL`.
   - Check `os.Getenv("NO_COLOR") != ""`.
2. **Formatter Implementation**:
   - `formatPrettyLookupOutput(res lookupResult, index int, total int, useColor bool) string`
   - Double line-breaks between multiple cards to maintain a roomy, readable layout.
