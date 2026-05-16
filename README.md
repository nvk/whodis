# whodis

`whodis` is an RDAP-first domain intelligence CLI. It reports registration data,
DNS records, IP ownership, TLS certificate state, and optional HTTP redirects as
separate facts instead of blending them into one fragile WHOIS scrape.

## Features

- RDAP-first registration lookup using IANA bootstrap data
- Legacy WHOIS fallback for TLDs without usable RDAP
- Optional `python-whois` and command-line WHOIS modes
- DNS lookups for A, AAAA, CNAME, NS, MX, TXT, SOA, SRV, CAA, DS, DNSKEY, and reverse PTR
- DMARC TXT discovery at `_dmarc.<domain>`
- IP RDAP lookups for resolved A/AAAA addresses
- Optional command-line `dig`/`whois` lookup mode
- TLS certificate inspection with verification state and expiry
- Optional HTTP/HTTPS redirect checking with per-protocol details
- Text, JSON, and CSV output

## Installation

```bash
python3 -m pip install .
```

## Usage

```bash
# Human-readable report
whodis example.com

# Stable machine-readable output
whodis --format json example.com

# Optional redirect chain
whodis --check-redirect example.com

# Save output
whodis --output result.json --format json example.com

# Skip sections
whodis --no-dns example.com
whodis --no-ip example.com
whodis --no-tls example.com

# Force legacy WHOIS instead of RDAP
whodis --whois example.com

# Use python-whois as the registration source
whodis --python-whois example.com

# Use command-line tools for WHOIS, DNS, and IP lookups
whodis --use-command-line example.com
```

## Notes

RDAP is the primary registration data protocol for gTLDs after the January 28,
2025 WHOIS sunset. WHOIS remains a compatibility fallback, but JSON RDAP data is
the source of truth when available.

## License

MIT License
