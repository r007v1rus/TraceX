# Changelog

## 0.2.0

### Added
- `webscan`: deep, budgeted web audit (headers, 30+ exposure checks, JavaScript secret and endpoint
  analysis, source maps, library versions, robots.txt probing, WordPress checks, cookies, CORS,
  HTTP methods, TLS, HTTP-to-HTTPS redirect, same-origin crawl).
- `tools`: integrates installed `nmap` and `whatweb`.
- Findings with severity and a remediation for each; security score, grade and a "fix first" list.
- DNS email-security analysis (SPF, DMARC, DKIM, CAA, nameservers).
- Subdomain DNS triage: live/dead hosts, dangling-CNAME takeover detection, sensitive hostnames.
- Domain health from RDAP: expiry, age, transfer lock, DNSSEC.
- `http`/`webscan`/`tools` accept `host:port`, `localhost` and IP addresses.
- `--json`, `--output report.{json,md}`, `--deep`, `--max-requests`.
- `examples/vulnerable_demo.py`, a safe local practice target.
- CI workflow, CONTRIBUTING, SECURITY, `python -m tracex`.

### Fixed
- Syntax error in the interactive menu loop and mismatched Rich markup in the banner.

## 0.1.0

- Interactive menu, domain validation and `version` command.
