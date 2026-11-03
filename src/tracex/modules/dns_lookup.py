from __future__ import annotations

import re
from typing import Any

import dns.exception
import dns.resolver

from tracex.core.base import Module, ModuleError
from tracex.core.findings import finding, sort_findings

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2"]


def _unquote(text: str) -> str:
    """Join the quoted chunks of a TXT record: '"a" "b"' -> 'ab'."""
    chunks = re.findall(r'"([^"]*)"', text)
    return "".join(chunks) if chunks else text.strip('"')


def txt_values(resolver, name: str) -> list[str]:
    """TXT strings for a name ([] on any DNS failure); chunks are re-joined."""
    try:
        answer = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout):
        return []
    return [_unquote(r.to_text()) for r in answer]


def analyze_email_security(
    domain: str, records: dict[str, list[str]], resolver
) -> tuple[dict[str, Any], list[dict]]:
    findings: list[dict] = []
    has_mx = bool(records.get("MX"))
    txt = [_unquote(t) for t in records.get("TXT", [])]

    # SPF ---------------------------------------------------------------
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    spf_fix = "Publish an SPF record, e.g. `v=spf1 include:_spf.your-mail-provider.com -all`."
    if not spf:
        findings.append(finding(
            "medium" if has_mx else "low", "No SPF record",
            "Anyone can forge mail from this domain" if has_mx else "Domain sends no mail but can still be spoofed",
            spf_fix if has_mx else "Publish `v=spf1 -all` to declare that the domain sends no mail."))
    elif len(spf) > 1:
        findings.append(finding("medium", "Multiple SPF records",
                                "Receivers treat this as invalid", "Merge them into a single SPF record."))
    else:
        policy = spf[0].split()[-1].lower()
        if policy == "+all":
            findings.append(finding("high", "SPF allows any sender (+all)", spf[0],
                                    "Replace `+all` with `-all` (or `~all` while testing)."))
        elif policy == "?all":
            findings.append(finding("medium", "SPF is neutral (?all)", spf[0],
                                    "Use `-all` or `~all` so spoofed mail is rejected or flagged."))
        elif policy == "~all":
            findings.append(finding("info", "SPF uses softfail (~all)", spf[0],
                                    "Move to `-all` once all legitimate senders are listed."))

    # DMARC -------------------------------------------------------------
    dmarc = [t for t in txt_values(resolver, f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        findings.append(finding(
            "medium" if has_mx else "low", "No DMARC record", "",
            f"Add a TXT record at _dmarc.{domain}: `v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}`."))
    else:
        m = re.search(r"\bp=(\w+)", dmarc[0], re.I)
        if m and m.group(1).lower() == "none":
            findings.append(finding("low", "DMARC is monitor-only (p=none)", dmarc[0],
                                    "After reviewing reports, move to p=quarantine, then p=reject."))

    # DKIM / MTA-STS -------------------------------------------------------
    dkim = [s for s in DKIM_SELECTORS
            if any("p=" in t for t in txt_values(resolver, f"{s}._domainkey.{domain}"))]
    if has_mx and not dkim:
        findings.append(finding("info", "No DKIM key found at common selectors",
                                "Not conclusive: selectors are provider-specific",
                                "Make sure outgoing mail is DKIM-signed."))
    mta_sts = bool(txt_values(resolver, f"_mta-sts.{domain}"))

    # CAA / NS ------------------------------------------------------------
    if not records.get("CAA"):
        findings.append(finding("info", "No CAA record", "Any CA may issue certificates for this domain",
                                "Add a CAA record to limit which CAs can issue certificates."))
    if 0 < len(records.get("NS", [])) < 2:
        findings.append(finding("low", "Only one nameserver", "",
                                "Use at least two nameservers on separate networks."))

    info = {
        "spf": spf[0] if spf else None,
        "dmarc": dmarc[0] if dmarc else None,
        "dkim_selectors_found": dkim,
        "mta_sts": mta_sts,
    }
    return info, sort_findings(findings)


class DnsLookup(Module):
    name = "dns"
    description = "DNS records plus email-security checks (SPF, DMARC, DKIM, CAA)"
    target_type = "domain"

    def __init__(self, resolver: dns.resolver.Resolver | None = None) -> None:
        self._resolver = resolver

    def _get_resolver(self) -> dns.resolver.Resolver:
        if self._resolver is not None:
            return self._resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0
        return resolver

    def collect(self, target: str, **_: Any) -> dict[str, Any]:
        resolver = self._get_resolver()
        records: dict[str, list[str]] = {}
        failures = 0

        for rtype in RECORD_TYPES:
            try:
                answer = resolver.resolve(target, rtype)
                records[rtype] = sorted(r.to_text() for r in answer)
            except dns.resolver.NXDOMAIN:
                raise ModuleError(f"{target} does not exist (NXDOMAIN).")
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                continue
            except dns.exception.Timeout:
                failures += 1

        if failures == len(RECORD_TYPES):
            raise ModuleError("DNS queries timed out (check your connection).")

        email, findings = analyze_email_security(target, records, resolver)
        return {"records": records, "email_security": email, "findings": findings}
