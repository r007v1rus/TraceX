from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from tracex.core.base import Module, ModuleError
from tracex.core.findings import finding, sort_findings
from tracex.core.http import make_client

RDAP_URL = "https://rdap.org/domain/{domain}"


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def analyze_domain_health(data: dict, now: datetime | None = None) -> tuple[dict, list[dict]]:
    """Expiry, age, transfer lock and DNSSEC checks from an RDAP record."""
    now = now or datetime.now(timezone.utc)
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    registered, expires = _parse_date(events.get("registration")), _parse_date(events.get("expiration"))
    status = [s.lower() for s in data.get("status", [])]
    findings: list[dict] = []
    info: dict[str, Any] = {}

    if registered:
        info["age_days"] = (now - registered).days
        if info["age_days"] < 30:
            findings.append(finding("info", "Recently registered domain", f"{info['age_days']} days old",
                                    "New domains are often flagged by spam filters; verify it is yours."))
    if expires:
        left = (expires - now).days
        info["days_until_expiry"] = left
        if left < 0:
            findings.append(finding("high", "Domain registration expired", f"{-left} days ago",
                                    "Renew immediately before someone else registers it."))
        elif left < 30:
            findings.append(finding("medium", "Domain expires soon", f"{left} days left",
                                    "Renew it and enable auto-renew."))
        elif left < 60:
            findings.append(finding("low", "Domain expires within 60 days", f"{left} days left",
                                    "Enable auto-renew at the registrar."))
    if any("pending delete" in s or "redemption" in s for s in status):
        findings.append(finding("high", "Domain is in deletion/redemption", ", ".join(status),
                                "Contact the registrar to restore it."))
    if status and not any("transfer prohibited" in s for s in status):
        findings.append(finding("low", "Registrar transfer lock not enabled", "",
                                "Enable the registrar lock to prevent unauthorized transfers."))
    secure = data.get("secureDNS") or {}
    info["dnssec"] = bool(secure.get("delegationSigned"))
    if "secureDNS" in data and not info["dnssec"]:
        findings.append(finding("info", "DNSSEC not enabled", "",
                                "Enable DNSSEC at your registrar/DNS host if supported."))
    return info, sort_findings(findings)


def _registrar_name(entities: list[dict]) -> str | None:
    for entity in entities:
        if "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray", [None, []])[1]
            for item in vcard:
                if item and item[0] == "fn":
                    return item[3]
    return None


class WhoisLookup(Module):
    """Registration data via RDAP (the structured successor of WHOIS).

    Only registrar/lifecycle data is kept; contact details are deliberately
    not collected.
    """

    name = "whois"
    description = "Domain registration info via RDAP (registrar, dates, status, nameservers)"
    target_type = "domain"

    def collect(self, target: str, **_: Any) -> dict[str, Any]:
        with make_client(timeout=15.0) as client:
            try:
                response = client.get(RDAP_URL.format(domain=target))
            except httpx.HTTPError as error:
                raise ModuleError(f"RDAP request failed: {error}")

        if response.status_code == 404:
            raise ModuleError(f"No RDAP record found for {target}.")
        if response.status_code != 200:
            raise ModuleError(f"RDAP server returned HTTP {response.status_code}.")

        data = response.json()
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
        health, findings = analyze_domain_health(data)

        return {
            "domain": data.get("ldhName", target),
            "registrar": _registrar_name(data.get("entities", [])),
            "registered": events.get("registration"),
            "expires": events.get("expiration"),
            "last_changed": events.get("last changed"),
            "status": data.get("status", []),
            "nameservers": sorted(
                n.get("ldhName", "").lower() for n in data.get("nameservers", [])
            ),
            **health,
            "findings": findings,
        }
