import dns.exception
import dns.resolver
import httpx

from tracex.modules import dns_lookup, subdomains, username_check, whois_lookup
from tracex.modules.http_fingerprint import HttpFingerprint, detect_technologies


def mock_client(handler):
    def factory(*args, **kwargs):
        return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    return factory


# ---- DNS -------------------------------------------------------------
class FakeAnswer(list):
    pass


class FakeRecord:
    def __init__(self, text):
        self.text = text

    def to_text(self):
        return self.text


class FakeResolver:
    def __init__(self, table=None, exc=None):
        self.table, self.exc = table or {}, exc

    def resolve(self, name, rtype):
        if self.exc:
            raise self.exc
        if rtype in self.table:
            return FakeAnswer(FakeRecord(t) for t in self.table[rtype])
        raise dns.resolver.NoAnswer()


def test_dns_collects_records():
    mod = dns_lookup.DnsLookup(FakeResolver({"A": ["2.2.2.2", "1.1.1.1"], "MX": ["10 mail.x.com."]}))
    result = mod.run("x.com")
    assert result.ok
    assert result.data["records"] == {"A": ["1.1.1.1", "2.2.2.2"], "MX": ["10 mail.x.com."]}


def test_dns_nxdomain():
    result = dns_lookup.DnsLookup(FakeResolver(exc=dns.resolver.NXDOMAIN())).run("nope.example")
    assert not result.ok and "NXDOMAIN" in result.error


def test_dns_all_timeouts():
    result = dns_lookup.DnsLookup(FakeResolver(exc=dns.exception.Timeout())).run("x.com")
    assert not result.ok and "timed out" in result.error


# ---- RDAP ------------------------------------------------------------
RDAP = {
    "ldhName": "example.com",
    "status": ["client transfer prohibited"],
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2030-08-13T04:00:00Z"},
    ],
    "nameservers": [{"ldhName": "B.IANA-SERVERS.NET"}, {"ldhName": "a.iana-servers.net"}],
    "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]]]}],
}


def test_whois_parses_rdap(monkeypatch):
    monkeypatch.setattr(whois_lookup, "make_client", mock_client(lambda r: httpx.Response(200, json=RDAP)))
    result = whois_lookup.WhoisLookup().run("example.com")
    assert result.ok
    assert result.data["registrar"].startswith("RESERVED")
    assert result.data["registered"] == "1995-08-14T04:00:00Z"
    assert result.data["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]


def test_whois_not_found(monkeypatch):
    monkeypatch.setattr(whois_lookup, "make_client", mock_client(lambda r: httpx.Response(404)))
    result = whois_lookup.WhoisLookup().run("nothing.example")
    assert not result.ok and "No RDAP record" in result.error


# ---- crt.sh ----------------------------------------------------------
def test_extract_subdomains():
    rows = [
        {"name_value": "www.example.com\n*.example.com"},
        {"name_value": "API.example.com"},
        {"name_value": "example.com"},
        {"name_value": "evil-example.com"},
        {"name_value": "other.org"},
    ]
    assert subdomains.extract_subdomains(rows, "example.com") == [
        "api.example.com", "example.com", "www.example.com",
    ]


def test_subdomains_module(monkeypatch):
    rows = [{"name_value": "a.example.com"}, {"name_value": "b.example.com"}]
    monkeypatch.setattr(subdomains, "make_client", mock_client(lambda r: httpx.Response(200, json=rows)))
    result = subdomains.Subdomains(FakeResolver()).run("example.com")
    assert result.ok
    assert result.data["count"] == 2
    assert result.data["subdomains"] == ["a.example.com", "b.example.com"]


def test_subdomains_bad_json(monkeypatch):
    monkeypatch.setattr(subdomains, "make_client", mock_client(lambda r: httpx.Response(200, text="<html>")))
    assert not subdomains.Subdomains(FakeResolver()).run("example.com").ok


# ---- HTTP fingerprint --------------------------------------------------
def test_detect_technologies():
    headers = {"Server": "nginx/1.25", "X-Powered-By": "PHP/8.3", "CF-Ray": "abc"}
    body = '<meta name="generator" content="WordPress 6.5"><link href="/wp-content/x.css">'
    techs = detect_technologies(headers, body)
    for expected in ("nginx", "PHP", "Cloudflare", "WordPress", "generator: WordPress 6.5"):
        assert expected in techs


def test_http_fingerprint(monkeypatch):
    def fake_fetch(self, url):
        return httpx.Response(
            200,
            headers={"Server": "Apache", "Strict-Transport-Security": "max-age=1"},
            text="<html><title> Hello  World </title></html>",
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr(HttpFingerprint, "_fetch", fake_fetch)
    data = HttpFingerprint().run("example.com").data
    assert data["status"] == 200
    assert data["title"] == "Hello World"
    assert data["security_headers"]["strict-transport-security"] == "present"
    assert data["security_headers"]["content-security-policy"] == "MISSING"
    assert "Apache" in data["technologies"]


def test_http_fingerprint_unreachable(monkeypatch):
    def boom(self, url):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(HttpFingerprint, "_fetch", boom)
    result = HttpFingerprint().run("example.com")
    assert not result.ok and "Could not connect" in result.error


# ---- username ----------------------------------------------------------
def test_username_check(monkeypatch):
    def handler(request):
        host = request.url.host
        return httpx.Response({"github.com": 200, "gitlab.com": 404}.get(host, 429))

    monkeypatch.setattr(username_check, "make_client", mock_client(handler))
    data = username_check.UsernameCheck().run("octocat").data
    by_site = {r["site"]: r["status"] for r in data["sites"]}
    assert by_site["GitHub"] == "found"
    assert by_site["GitLab"] == "not found"
    assert by_site["PyPI"] == "unknown"
    assert data["found_on"] == 1 and data["checked"] == len(username_check.SITES)


# ---- real local server (no mocks) ----------------------------------------
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from tracex.utils.validators import validate_http_target


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><title>Local</title><link href='/wp-content/a.css'></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def local_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()


@pytest.mark.parametrize("fmt", ["localhost:{p}", "127.0.0.1:{p}", "http://localhost:{p}/"])
def test_http_module_on_real_local_server(local_server, fmt):
    mod = HttpFingerprint()
    target = mod.validate(fmt.format(p=local_server))
    result = mod.run(target)
    assert result.ok, result.error
    assert result.data["status"] == 200
    assert result.data["title"] == "Local"
    assert result.data["security_headers"]["x-frame-options"] == "present"
    assert "WordPress" in result.data["technologies"]


def test_http_module_connection_refused():
    result = HttpFingerprint().run("localhost:1")
    assert not result.ok and "Could not connect" in result.error


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("localhost:8080", "localhost:8080"),
        ("http://localhost:8080/", "http://localhost:8080"),
        ("127.0.0.1:3000/login", "127.0.0.1:3000/login"),
        ("Example.COM", "example.com"),
        ("https://Example.com:8443/a?b=1", "https://example.com:8443/a?b=1"),
        ("[::1]:8080", "[::1]:8080"),
    ],
)
def test_validate_http_target_ok(raw, expected):
    assert validate_http_target(raw) == expected


@pytest.mark.parametrize("raw", ["", "ftp://x.com", "localhost:99999", "localhost:abc", "bad_host.com", "http://"])
def test_validate_http_target_bad(raw):
    with pytest.raises(ValueError):
        validate_http_target(raw)


def test_other_modules_still_reject_localhost():
    from tracex.modules.dns_lookup import DnsLookup
    with pytest.raises(ValueError):
        DnsLookup().validate("localhost:8080")
