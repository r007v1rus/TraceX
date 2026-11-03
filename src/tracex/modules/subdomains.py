from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import dns.exception
import dns.resolver
import httpx

from tracex.core.base import Module, ModuleError
from tracex.core.findings import finding, sort_findings
from tracex.core.http import make_client

CRT_URL = "https://crt.sh/"
RESOLVE_CAP = 150

SENSITIVE_NAME = re.compile(
    r"(^|[.-])(dev|test|staging|stage|uat|qa|admin|internal|intranet|vpn|jenkins|gitlab|git|jira|"
    r"grafana|kibana|phpmyadmin|backup|old|beta|demo|sandbox|debug)([.-]|$)"
)

# CNAME suffix -> service. A dangling CNAME to one of these is a classic takeover.
THIRD_PARTY = {
    "github.io": "GitHub Pages", "herokuapp.com": "Heroku", "s3.amazonaws.com": "AWS S3",
    "azurewebsites.net": "Azure App Service", "cloudapp.net": "Azure",
    "trafficmanager.net": "Azure Traffic Manager", "myshopify.com": "Shopify",
    "surge.sh": "Surge", "bitbucket.io": "Bitbucket Pages", "ghost.io": "Ghost",
    "pantheonsite.io": "Pantheon", "zendesk.com": "Zendesk", "netlify.app": "Netlify",
    "readme.io": "Readme",
}


def extract_subdomains(rows: list[dict], domain: str) -> list[str]:
    found: set[str] = set()
    suffix = "." + domain
    for row in rows:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lower().removeprefix("*.")
            if name == domain or name.endswith(suffix):
                found.add(name)
    return sorted(found)


def service_for(cname: str | None) -> str | None:
    if not cname:
        return None
    cname = cname.rstrip(".").lower()
    for suffix, service in THIRD_PARTY.items():
        if cname == suffix or cname.endswith("." + suffix):
            return service
    return None


def resolve_host(resolver, name: str) -> dict[str, Any]:
    """IPs and CNAME target for one hostname, plus whether the CNAME target exists."""
    ips: list[str] = []
    cname: str | None = None
    for rtype in ("CNAME", "A", "AAAA"):
        try:
            answer = resolver.resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                dns.exception.Timeout):
            continue
        if rtype == "CNAME":
            cname = next(iter(answer)).to_text().rstrip(".")
        else:
            ips += [r.to_text() for r in answer]

    target_exists = True
    if cname and not ips:
        try:
            resolver.resolve(cname, "A")
        except dns.resolver.NXDOMAIN:
            target_exists = False
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
    return {"name": name, "ips": sorted(set(ips)), "cname": cname, "target_exists": target_exists}


class Subdomains(Module):
    """Passive subdomain discovery (Certificate Transparency) plus DNS triage."""

    name = "subdomains"
    description = "Subdomains from CT logs, live/dead check, takeover and sensitive-host detection"
    target_type = "domain"

    def __init__(self, resolver: dns.resolver.Resolver | None = None) -> None:
        self._resolver = resolver

    def _get_resolver(self):
        if self._resolver is not None:
            return self._resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3.0
        return resolver

    def collect(self, target: str, **_: Any) -> dict[str, Any]:
        with make_client(timeout=45.0) as client:
            try:
                response = client.get(CRT_URL, params={"q": f"%.{target}", "output": "json"})
            except httpx.HTTPError as error:
                raise ModuleError(f"crt.sh request failed: {error}")

        if response.status_code != 200:
            raise ModuleError(f"crt.sh returned HTTP {response.status_code} (try again later).")

        try:
            rows = response.json()
        except ValueError:
            raise ModuleError("crt.sh returned an unreadable response.")

        names = extract_subdomains(rows, target)
        resolver = self._get_resolver()
        to_resolve = names[:RESOLVE_CAP]
        with ThreadPoolExecutor(max_workers=20) as pool:
            resolved = list(pool.map(lambda n: resolve_host(resolver, n), to_resolve))

        live = [r for r in resolved if r["ips"]]
        dead = [r["name"] for r in resolved if not r["ips"] and not r["cname"]]
        findings: list[dict] = []

        for r in resolved:
            service = service_for(r["cname"])
            if r["cname"] and not r["ips"] and not r["target_exists"]:
                findings.append(finding(
                    "high", "Dangling CNAME (possible subdomain takeover)",
                    f"{r['name']} -> {r['cname']}" + (f" ({service})" if service else ""),
                    "Delete the DNS record, or re-claim the resource at the third-party service."))

        sensitive = [r["name"] for r in resolved if SENSITIVE_NAME.search(r["name"].removesuffix("." + target))]
        if sensitive:
            findings.append(finding(
                "low", "Sensitive-looking hostnames visible in CT logs",
                ", ".join(sensitive[:8]) + (f" (+{len(sensitive) - 8} more)" if len(sensitive) > 8 else ""),
                "Make sure these hosts require authentication or are not internet-reachable."))

        return {
            "count": len(names),
            "resolved": len(to_resolve),
            "live": len(live),
            "no_dns": len(dead),
            "findings": sort_findings(findings),
            "live_hosts": [
                {"name": r["name"], "ips": r["ips"], "service": service_for(r["cname"]) or "-"}
                for r in live
            ],
            "subdomains": names,
        }
