from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

import httpx

from tracex.core.base import Module, ModuleError
from tracex.core.http import make_client
from tracex.utils.validators import validate_http_target

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

INFO_HEADERS = ["server", "x-powered-by", "via", "content-type", "x-generator"]

# (technology, where, pattern) — simple, passive signatures.
SIGNATURES = [
    ("Cloudflare", "headers", re.compile(r"cloudflare|cf-ray", re.I)),
    ("nginx", "server", re.compile(r"nginx", re.I)),
    ("Apache", "server", re.compile(r"apache", re.I)),
    ("Microsoft IIS", "server", re.compile(r"iis", re.I)),
    ("PHP", "x-powered-by", re.compile(r"php", re.I)),
    ("ASP.NET", "x-powered-by", re.compile(r"asp\.net", re.I)),
    ("Express", "x-powered-by", re.compile(r"express", re.I)),
    ("WordPress", "body", re.compile(r"wp-content|wp-includes", re.I)),
    ("Drupal", "body", re.compile(r"drupal-settings-json|/sites/default/files", re.I)),
    ("Joomla", "body", re.compile(r"/media/jui/|joomla", re.I)),
    ("Shopify", "body", re.compile(r"cdn\.shopify\.com", re.I)),
    ("Next.js", "body", re.compile(r"/_next/static", re.I)),
    ("React", "body", re.compile(r"data-reactroot|react(?:-dom)?\.(?:production|development)", re.I)),
    ("Vue.js", "body", re.compile(r"vue(?:\.runtime)?(?:\.min)?\.js|data-v-[0-9a-f]{6,}", re.I)),
    ("jQuery", "body", re.compile(r"jquery[-.\d]*(?:\.min)?\.js", re.I)),
    ("Bootstrap", "body", re.compile(r"bootstrap(?:\.min)?\.(?:css|js)", re.I)),
]

GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def detect_technologies(headers: dict[str, str], body: str) -> list[str]:
    lowered = {k.lower(): v for k, v in headers.items()}
    header_blob = " ".join(f"{k}: {v}" for k, v in lowered.items())
    found: set[str] = set()

    for tech, where, pattern in SIGNATURES:
        if where == "headers":
            hit = pattern.search(header_blob)
        elif where == "body":
            hit = pattern.search(body)
        else:
            hit = pattern.search(lowered.get(where, ""))
        if hit:
            found.add(tech)

    match = GENERATOR.search(body)
    if match:
        found.add(f"generator: {match.group(1).strip()}")

    return sorted(found)


class HttpFingerprint(Module):
    name = "http"
    description = "HTTP headers, redirect chain, security headers and tech fingerprint"
    target_type = "domain"

    def validate(self, target: str) -> str:
        return validate_http_target(target)

    @staticmethod
    def _candidate_urls(target: str) -> list[str]:
        """URLs to try, in order. An explicit scheme is respected."""
        if "://" in target:
            return [target]
        host = urlsplit(f"//{target}").hostname or ""
        try:
            ipaddress.ip_address(host)
            local = True
        except ValueError:
            local = host == "localhost"
        # Local dev servers are almost always plain HTTP.
        schemes = ("http", "https") if local else ("https", "http")
        return [f"{scheme}://{target}" for scheme in schemes]

    def _fetch(self, url: str) -> httpx.Response:
        with make_client(timeout=12.0) as client:
            return client.get(url)

    def collect(self, target: str, **_: Any) -> dict[str, Any]:
        response = None
        last_error: Exception | None = None

        for url in self._candidate_urls(target):
            try:
                response = self._fetch(url)
                break
            except httpx.HTTPError as error:
                last_error = error

        if response is None:
            raise ModuleError(f"Could not connect over HTTP(S): {last_error}")

        headers = dict(response.headers)
        lowered = {k.lower(): v for k, v in headers.items()}
        body = response.text[:200_000]

        title_match = TITLE.search(body)
        chain = [f"{r.status_code} {r.url}" for r in response.history]

        return {
            "final_url": str(response.url),
            "status": response.status_code,
            "redirects": chain,
            "title": " ".join(title_match.group(1).split()) if title_match else None,
            "info_headers": {h: lowered[h] for h in INFO_HEADERS if h in lowered},
            "security_headers": {
                h: ("present" if h in lowered else "MISSING") for h in SECURITY_HEADERS
            },
            "technologies": detect_technologies(headers, body),
        }
