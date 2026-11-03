from __future__ import annotations

from tracex.core.base import Module
from tracex.modules.dns_lookup import DnsLookup
from tracex.modules.external_tools import ExternalTools
from tracex.modules.http_fingerprint import HttpFingerprint
from tracex.modules.subdomains import Subdomains
from tracex.modules.username_check import UsernameCheck
from tracex.modules.webscan import WebScan
from tracex.modules.whois_lookup import WhoisLookup

MODULES: dict[str, Module] = {
    m.name: m
    for m in (
        DnsLookup(),
        WhoisLookup(),
        Subdomains(),
        HttpFingerprint(),
        WebScan(),
        ExternalTools(),
        UsernameCheck(),
    )
}

# Modules run by the all-in-one `scan` (webscan supersedes the quick http check).
SCAN_MODULES = ["dns", "whois", "subdomains", "webscan"]
DOMAIN_MODULES = SCAN_MODULES


def get_module(name: str) -> Module:
    return MODULES[name]
