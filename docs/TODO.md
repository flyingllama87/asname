# TODO

Planned work that is agreed but not started.

## RDAP for an ASN the offline names list lacks

The online netblock lookup uses RDAP (`internal/sources/rdap.go`). The same
bootstrap mechanism covers AS numbers (`https://data.iana.org/rdap/asn.json`,
then `<base>/autnum/<n>`), which could name an ASN missing from the RIPE NCC
AS names list, behind the same opt-in and query allowance.
