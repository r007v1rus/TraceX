import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from tracex.modules.external_tools import ExternalTools, parse_nmap_xml, parse_whatweb_json
from tracex.modules.webscan import (
    WebScan,
    analyze_cookies,
    matches_baseline,
    norm_url,
)

INDEX = (
    b"<html><head><title>Demo</title>"
    b'<script src="https://cdn.example.net/lib.js"></script></head><body>'
    b'<a href="/about">a</a><a href="/">home</a><a href="https://other.example.org/x">e</a>'
    b'<form action="/login" method="post"><input name="user"><input name="pw" type="password"></form>'
    b"</body></html>"
)


class WeakHandler(BaseHTTPRequestHandler):
    server_version = "Weak/1.2"

    def _send(self, code, body, ctype="text/html", extra=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        origin = self.headers.get("Origin")
        cors = (
            [("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", "true")]
            if origin else []
        )
        routes = {
            "/": (INDEX, "text/html", [("Set-Cookie", "sessionid=abc; Path=/")] + cors),
            "/about": (b"<html><a href='/'>h</a></html>", "text/html", []),
            "/robots.txt": (b"User-agent: *\nDisallow: /admin\n", "text/plain", []),
            "/.git/HEAD": (b"ref: refs/heads/main\n", "text/plain", []),
            "/.env": (b"DB_PASSWORD=x\nAPI_KEY=y\n", "text/plain", []),
        }
        if self.path in routes:
            body, ctype, extra = routes[self.path]
            self._send(200, body, ctype, extra)
        else:
            self._send(404, b"nope", "text/plain")

    def do_OPTIONS(self):
        self._send(200, b"", "text/plain", [("Allow", "GET, TRACE, DELETE")])

    def log_message(self, *args):
        pass


class SpaHandler(WeakHandler):
    """Catch-all app: every path returns 200 with the same HTML shell."""

    def do_GET(self):
        self._send(200, b"<html><body><div id='root'></div></body></html>")


def serve(handler):
    server = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def weak_port():
    server = serve(WeakHandler)
    yield server.server_address[1]
    server.shutdown()


@pytest.fixture
def spa_port():
    server = serve(SpaHandler)
    yield server.server_address[1]
    server.shutdown()


def titles(data, severity=None):
    return [f["title"] for f in data["findings"] if severity in (None, f["severity"])]


def test_webscan_finds_planted_issues(weak_port):
    result = WebScan().run(f"localhost:{weak_port}")
    assert result.ok, result.error
    d = result.data

    high = titles(d, "high")
    assert any(".git/HEAD" in t for t in high)
    assert any(".env" in t for t in high)
    assert any("CORS reflects" in t for t in high)  # reflected origin + credentials

    assert any("TRACE" in t for t in titles(d))
    assert any("sessionid" in t and "HttpOnly" in t for t in titles(d))
    assert any("Missing Content-Security-Policy" in t for t in titles(d))
    assert any("without SRI" in t for t in titles(d))

    assert d["robots_disallow"] == ["/admin"]
    assert d["external_domains"] == ["cdn.example.net", "other.example.org"]
    assert d["pages_crawled"] == 2  # "/" and "/about", no duplicate crawl of "/"
    assert len(d["forms"]) == 1 and d["forms"][0]["password"] is True
    assert d["summary"]["high"] >= 3


def test_webscan_respects_budget(weak_port):
    normal = WebScan().run(f"localhost:{weak_port}").data
    used, limit = map(int, normal["requests_used"].split("/"))
    assert limit == 50 and used <= 50

    capped = WebScan().run(f"localhost:{weak_port}", max_requests=8).data
    used, limit = map(int, capped["requests_used"].split("/"))
    assert limit == 8 and used == 8
    assert "Request budget reached" in titles(capped, "info")


def test_deep_mode_checks_more_paths(weak_port):
    normal = int(WebScan().run(f"localhost:{weak_port}").data["requests_used"].split("/")[0])
    deep = WebScan().run(f"localhost:{weak_port}", deep=True).data
    used, limit = map(int, deep["requests_used"].split("/"))
    assert limit == 150 and used > normal


def test_spa_catch_all_causes_no_false_positives(spa_port):
    d = WebScan().run(f"localhost:{spa_port}").data
    assert d["exposed_paths"] == []
    assert not any(f["severity"] == "high" for f in d["findings"])


def test_unreachable_target():
    result = WebScan().run("localhost:1")
    assert not result.ok and "Could not connect" in result.error


def test_matches_baseline_logic():
    import httpx

    base = (404, "text/html", 100, "abc")
    same = httpx.Response(404, headers={"content-type": "text/html"}, content=b"x" * 102)
    other = httpx.Response(200, headers={"content-type": "text/plain"}, content=b"ref: x")
    assert matches_baseline(same, base)
    assert not matches_baseline(other, base)
    assert not matches_baseline(other, None)


def test_norm_url():
    assert norm_url("http://h:8080") == "http://h:8080/"
    assert norm_url("http://h/a#frag") == "http://h/a"


def test_analyze_cookies():
    cookies = analyze_cookies(
        ["sid=1; Path=/; Secure; HttpOnly; SameSite=Lax", "pref=dark"], is_https=True
    )
    assert cookies[0] == {"name": "sid", "secure": True, "httponly": True, "samesite": "Lax"}
    assert cookies[1] == {"name": "pref", "secure": False, "httponly": False, "samesite": "-"}


# ---- external tools ---------------------------------------------------------
NMAP_XML = """<nmaprun><host><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/></port>
<port protocol="tcp" portid="23"><state state="closed"/><service name="telnet"/></port>
</ports></host></nmaprun>"""


def test_parse_nmap_xml():
    assert parse_nmap_xml(NMAP_XML) == [
        {"port": "22/tcp", "service": "ssh", "product": "OpenSSH 9.6"},
        {"port": "80/tcp", "service": "http", "product": "nginx"},
    ]


def test_parse_whatweb_json_array_and_lines():
    array = '[{"plugins": {"nginx": {"version": ["1.25"]}, "HTML5": {}}}]'
    assert parse_whatweb_json(array) == ["HTML5", "nginx 1.25"]
    lines = '[\n{"plugins": {"PHP": {"version": ["8.3"]}}},\n]'
    assert parse_whatweb_json(lines) == ["PHP 8.3"]


def test_tools_missing(monkeypatch):
    monkeypatch.setattr("tracex.modules.external_tools.shutil.which", lambda t: None)
    result = ExternalTools().run("localhost:8080")
    assert not result.ok and "No supported tools" in result.error


def test_tools_command_is_a_safe_arg_list(monkeypatch):
    calls = []

    class Done:
        returncode, stdout, stderr = 0, "<nmaprun/>", ""

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return Done()

    monkeypatch.setattr("tracex.modules.external_tools.shutil.which",
                        lambda t: "/usr/bin/nmap" if t == "nmap" else None)
    monkeypatch.setattr("tracex.modules.external_tools.subprocess.run", fake_run)
    result = ExternalTools().run("localhost:8080")
    assert result.ok
    args, kwargs = calls[0]
    assert isinstance(args, list) and kwargs["shell"] is False
    assert args[-1] == "localhost" and args[args.index("-p") + 1] == "8080"


def test_tools_rejects_injection_attempts():
    for bad in ("localhost; rm -rf /", "$(id).com", "a b.com", "-oN x.com"):
        with pytest.raises(ValueError):
            ExternalTools().validate(bad)
