# TODO

Planned work that is agreed but not started.

## Use RDAP for the online netblock lookup

**Why.** The online fallback (`--whois`, the web UI's Online lookups) asks the
registries over port-43 whois: free-form text whose fields, layout and
character set differ by registry. LACNIC answers in a broken encoding, so
`200.160.2.3` comes back as "N�cleo de Inf. e Coord. do Ponto BR" (the
replacement character is in LACNIC's own response, not added by asname), and
each registry needs its own parsing. RDAP (Registration Data Access Protocol,
RFC 9082/9083) is the registries' modern replacement: JSON over HTTPS, the same
field names everywhere, always UTF-8. ARIN, RIPE NCC, APNIC, LACNIC and AFRINIC
all run it.

**How.**
- Find the registry for an address from IANA's RDAP bootstrap file
  (`https://data.iana.org/rdap/ipv4.json`, `ipv6.json`), cached like the other
  downloaded sources, instead of asking `whois.iana.org`.
- Query `<base>/ip/<address>` and map the response (an `ip network` object) to
  `NetblockInfo`: `name` (netname), `handle`, `startAddress`/`endAddress`,
  `country`, the registrant entity's `fn` from its `vcardArray` (org), and the
  `registration` event date (created).
- Keep the current safeguards: the per-request query allowance
  (`MaxWhoisQueries`), the timeout, and the rate-limit detection (RDAP answers
  HTTP 429).
- Fall back to port-43 whois when a registry's RDAP server fails, at least at
  first.
- Report the source as RDAP in the card's Data Sources and the JSON
  (`"source": "rdap"`), and update the README's "Filling the gaps with whois".
- Tests with recorded responses from each of the five registries, including
  LACNIC's accented names.

Also worth considering once it exists: RDAP for an ASN (`<base>/autnum/<n>`)
when the offline AS names list lacks one.
