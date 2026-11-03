import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import dns.resolver
import httpx
import pytest
from typer.testing import CliRunner

from tracex.core.findings import build_summary, finding, grade_for
from tracex.core.models import ModuleResult
from tracex.core.report import to_json, to_markdown
from tracex.main import app
from tracex.modules import subdomains
from tracex.modules.dns_lookup import analyze_email_security
from tracex.modules.webscan import (
    WebScan,
    detect_libraries,
    find_emails,
    outdated_library_findings,
    scan_secrets,
)
from tracex.modules.whois_lookup import analyze_domain_health


# ------------------------------------------------------------------ helpers
class Rec:
    def __init__(self, text):
        self.text = text

    def to_text(self):
        return self.text


class NameResolver:
    """Resolver that answers per (name, type); names in `missing` are NXDOMAIN."""

    def __init__(self, table=None, missing=()):
        self.table = {(n, t): v for (n, t), v in (table or {}).items()}
        self.missing = set(missing)

    def resolve(self, name, rtype):
        name = name.rstrip(".")
        if name in self.missing:
            raise dns.resolver.NXDOMAIN()
        if (name, rtype) in self.table:
            return [Rec(x) for x in self.table[(name, rtype)]]
        raise dns.resolver.NoAnswer()


def titles(findings):
    return [f["title"] for f in findings]


# ------------------------------------------------------------ email security
def test_email_security_flags_problems():
    records = {"MX": ["10 mail.x.com."], "TXT": ['"v=spf1 +all"'], "NS": ["ns1.x.com."]}
    info, findings = analyze_email_security("example.com", records, NameResolver())
    t = titles(findings)
    assert "SPF allows any sender (+all)" in t
    assert "No DMARC record" in t
    assert "Only one nameserver" in t
    assert "No CAA record" in t
    assert findings[0]["severity"] == "high" and findings[0]["fix"]
    assert info["spf"] == "v=spf1 +all" and info["dmarc"] is None


def test_email_security_clean_config():
    records = {
        "MX": ["10 mail.x.com."], "NS": ["ns1.x.com.", "ns2.x.com."], "CAA": ['0 issue "letsencrypt.org"'],
        "TXT": ['"v=spf1 include:_spf.google.com -all"'],
    }
    resolver = NameResolver({
        ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject"'],
        ("google._domainkey.example.com", "TXT"): ['"v=DKIM1; k=rsa; " "p=ABC"'],
    })
    info, findings = analyze_email_security("example.com", records, resolver)
    assert findings == []
    assert info["dkim_selectors_found"] == ["google"]


def test_dmarc_monitor_only_and_spf_softfail():
    records = {"MX": ["10 m."], "NS": ["a.", "b."], "CAA": ["x"], "TXT": ['"v=spf1 -all ~all"']}
    resolver = NameResolver({("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=none"']})
    _, findings = analyze_email_security("example.com", records, resolver)
    assert "DMARC is monitor-only (p=none)" in titles(findings)
    assert "SPF uses softfail (~all)" in titles(findings)


# --------------------------------------------------------- subdomain takeover
def test_subdomain_takeover_and_sensitive_hosts(monkeypatch):
    rows = [{"name_value": "a.example.com\ndead.example.com\nstaging.example.com"}]
    monkeypatch.setattr(
        subdomains, "make_client",
        lambda *a, **k: httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=rows))),
    )
    resolver = NameResolver(
        {
            ("a.example.com", "A"): ["1.2.3.4"],
            ("staging.example.com", "A"): ["1.2.3.5"],
            ("dead.example.com", "CNAME"): ["gone.herokuapp.com."],
        },
        missing={"gone.herokuapp.com"},
    )
    data = subdomains.Subdomains(resolver).run("example.com").data
    assert data["count"] == 3 and data["live"] == 2
    dangling = [f for f in data["findings"] if "takeover" in f["title"]]
    assert dangling and dangling[0]["severity"] == "high"
    assert "Heroku" in dangling[0]["detail"]
    assert any("staging.example.com" in f["detail"] for f in data["findings"] if f["severity"] == "low")


def test_service_for():
    assert subdomains.service_for("foo.github.io.") == "GitHub Pages"
    assert subdomains.service_for("example.com") is None


# ---------------------------------------------------------------- whois health
def test_domain_health_findings():
    data = {
        "events": [
            {"eventAction": "registration", "eventDate": "2025-12-25T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2026-01-20T00:00:00Z"},
        ],
        "status": ["active"],
        "secureDNS": {"delegationSigned": False},
    }
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    info, findings = analyze_domain_health(data, now)
    assert info["age_days"] == 7 and info["days_until_expiry"] == 19
    t = titles(findings)
    assert "Domain expires soon" in t and "Registrar transfer lock not enabled" in t
    assert "Recently registered domain" in t and "DNSSEC not enabled" in t


def test_domain_health_expired():
    data = {"events": [{"eventAction": "expiration", "eventDate": "2025-12-01T00:00:00Z"}],
            "status": ["client transfer prohibited"]}
    _, findings = analyze_domain_health(data, datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert findings[0]["severity"] == "high" and "expired" in findings[0]["title"]


# ----------------------------------------------------- content intelligence
def test_scan_secrets_masks_values():
    found = scan_secrets('k="AKIAABCDEFGHIJKLMNOP"; other = "ghp_' + "a" * 36 + '"')
    assert {f["type"] for f in found} == {"AWS access key", "GitHub token"}
    assert all("AKIAABCDEFGHIJKLMNOP" not in f["sample"] for f in found)


def test_scan_secrets_ignores_normal_text():
    assert scan_secrets("const x = 'hello world'; // nothing here AKIA short") == []


def test_libraries_and_outdated():
    libs = detect_libraries("/js/jquery-1.12.4.min.js /bootstrap-4.1.0.js /angular.min-1.8.2.js")
    assert libs == {"jQuery": "1.12.4", "Bootstrap": "4.1.0", "AngularJS": "1.8.2"}
    t = titles(outdated_library_findings(libs))
    assert any("jQuery" in x for x in t) and any("Bootstrap" in x for x in t) and any("AngularJS" in x for x in t)
    assert outdated_library_findings({"jQuery": "3.7.1", "Bootstrap": "5.3.0"}) == []


def test_find_emails_skips_image_names():
    assert find_emails("mail bob@Example.com or logo@2x.png") == ["bob@example.com"]


# ----------------------------------------------------------- deep webscan
class DeepHandler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else body.encode())

    def do_GET(self):
        routes = {
            "/": (
                '<html><head><link href="/wp-content/x.css">'
                '<script src="/app.js"></script><script src="/js/jquery-1.12.4.min.js"></script></head>'
                "<body><!-- TODO remove admin password --> contact: sales@demo.test</body></html>",
                "text/html",
            ),
            "/app.js": ('var k="AKIAABCDEFGHIJKLMNOP"; fetch("/api/users");\n//# sourceMappingURL=app.js.map', "application/javascript"),
            "/app.js.map": ('{"version":3,"sources":["a.js"]}', "application/json"),
            "/js/jquery-1.12.4.min.js": ("/*! jQuery v1.12.4 */", "application/javascript"),
            "/robots.txt": ("User-agent: *\nDisallow: /admin\nDisallow: /nothing-here\n", "text/plain"),
            "/admin": ("<html>admin console</html>", "text/html"),
            "/wp-json/wp/v2/users": ('[{"id":1,"slug":"admin"}]', "application/json"),
        }
        if self.path in routes:
            self._send(200, *routes[self.path])
        else:
            self._send(404, "nope", "text/plain")

    def log_message(self, *args):
        pass


@pytest.fixture
def deep_port():
    server = HTTPServer(("127.0.0.1", 0), DeepHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()


def test_webscan_deep_intelligence(deep_port):
    result = WebScan().run(f"localhost:{deep_port}")
    assert result.ok, result.error
    d = result.data
    t = titles(d["findings"])

    assert any("Possible secret" in x and "AWS" in x for x in t)
    assert d["secrets"] and "AKIAABCDEFGHIJKLMNOP" not in json.dumps(d["secrets"])
    assert "JavaScript source map exposed" in t
    assert any("Outdated jQuery" in x for x in t)
    assert "HTML comments contain sensitive-looking words" in t
    assert "WordPress user enumeration via REST API" in t
    assert "/api/users" in d["api_endpoints"]
    assert "sales@demo.test" in d["emails"]
    assert d["libraries"]["jQuery"] == "1.12.4"
    assert "WordPress" in d["technologies"]
    assert d["interesting_paths"] == [{"path": "/admin", "status": 200}]
    assert all(f["fix"] for f in d["findings"] if f["severity"] in ("high", "medium"))
    assert d["grade"] in "ABCDF" and d["score"] < 100
    assert int(d["requests_used"].split("/")[0]) <= 50


def test_plain_http_localhost_is_not_alarming(deep_port):
    f = {x["title"]: x for x in WebScan().run(f"localhost:{deep_port}").data["findings"]}
    assert f["Site served over plain HTTP"]["severity"] == "info"


# ------------------------------------------------------- summary and reports
def sample_results():
    return [
        ModuleResult("webscan", "x.com", data={"findings": [
            finding("low", "Low thing", "", "fix low"),
            finding("high", "Big thing", "", "fix big"),
            finding("info", "FYI", "", "ignored"),
        ]}),
        ModuleResult("dns", "x.com", ok=False, error="boom"),
    ]


def test_grade_thresholds():
    scores = (100, 90, 89, 80, 65, 50, 49, 0)
    assert [grade_for(s) for s in scores] == ["A", "A", "B", "B", "C", "D", "F", "F"]


def test_build_summary():
    s = build_summary(sample_results())
    assert s["score"] == 84 and s["grade"] == "B"
    assert s["counts"] == {"high": 1, "medium": 0, "low": 1, "info": 1}
    assert [a["title"] for a in s["top_actions"]] == ["Big thing", "Low thing"]  # high first, info excluded
    assert s["modules_failed"] == ["dns"]


def test_reports_include_summary_and_fixes():
    assert json.loads(to_json(sample_results()))["summary"]["grade"] == "B"
    md = to_markdown(sample_results())
    assert "Security grade: B" in md and "Fix first" in md and "| high | Big thing |" in md


def test_menu_prompt_has_no_example_hint():
    result = CliRunner().invoke(app, [], input="y\n06\nlocalhost:1\nn\nn\n00\n")
    assert "domain or host:port" in result.output
    assert "e.g." not in result.output
