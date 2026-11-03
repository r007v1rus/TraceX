"""Deep, budgeted web audit of a site you are authorized to assess.

Steps: fingerprint -> exposure checks -> methods/CORS -> TLS -> cookies ->
crawl (same origin only).  Every HTTP request counts against a budget
(default 50, 150 with ``deep=True``).
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import socket
import ssl
import time
from html.parser import HTMLParser
from typing import Any, Callable
from urllib.parse import urldefrag, urljoin, urlsplit

import httpx

from tracex.core.base import Module, ModuleError
from tracex.core.fetcher import Fetcher
from tracex.core.findings import PENALTY, SEVERITY_ORDER, count_by_severity, finding, grade_for, sort_findings
from tracex.core.http import make_client
from tracex.modules.http_fingerprint import (
    SECURITY_HEADERS,
    TITLE,
    HttpFingerprint,
    detect_technologies,
)
from tracex.utils.validators import validate_http_target

NORMAL_BUDGET = 50
DEEP_BUDGET = 150
NORMAL_PAGES = 8
DEEP_PAGES = 30

ASSET_EXT = re.compile(
    r"\.(png|jpe?g|gif|svg|webp|ico|css|js|map|pdf|zip|gz|tar|mp[34]|webm|woff2?|ttf|eot)$", re.I
)
TEST_ORIGIN = "https://tracex-cors-test.invalid"
SESSIONISH = re.compile(r"sess|sid|token|auth|jwt|login", re.I)


# ---------------------------------------------------------------- HTML parsing
class PageParser(HTMLParser):
    def __init__(self, base: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base = base
        self.links: list[str] = []
        self.scripts: list[dict[str, Any]] = []
        self.resources: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.comments: list[str] = []
        self._form: dict[str, Any] | None = None

    def _abs(self, value: str) -> str | None:
        url = urldefrag(urljoin(self.base, value.strip()))[0]
        return url if urlsplit(url).scheme in ("http", "https") else None

    def handle_starttag(self, tag: str, attrs: list) -> None:
        a = {k: v for k, v in attrs if v is not None}
        if tag == "a" and a.get("href"):
            if (u := self._abs(a["href"])):
                self.links.append(u)
        elif tag == "script" and a.get("src"):
            if (u := self._abs(a["src"])):
                self.scripts.append({"src": u, "integrity": bool(a.get("integrity"))})
        elif tag == "link" and a.get("href"):
            if (u := self._abs(a["href"])):
                self.resources.append(u)
        elif tag in ("img", "iframe", "source", "video", "audio", "embed") and a.get("src"):
            if (u := self._abs(a["src"])):
                self.resources.append(u)
        elif tag == "form":
            self._form = {
                "page": self.base,
                "action": self._abs(a.get("action") or "") or self.base,
                "method": (a.get("method") or "GET").upper(),
                "inputs": [],
                "has_password": False,
            }
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None:
            if a.get("name"):
                self._form["inputs"].append(a["name"])
            if a.get("type", "").lower() == "password":
                self._form["has_password"] = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None

    def handle_comment(self, data: str) -> None:
        self.comments.append(data.strip())


def norm_url(url: str) -> str:
    """Drop the fragment and make an empty path "/" so duplicates collapse."""
    url = urldefrag(url)[0]
    parts = urlsplit(url)
    return parts._replace(path=parts.path or "/").geturl()


def origin_of(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


# ------------------------------------------------------------------- exposure
def _text(r: httpx.Response) -> str:
    return r.text[:20000]


def _not_html(r: httpx.Response) -> bool:
    return "<html" not in _text(r)[:500].lower() and "text/html" not in r.headers.get("content-type", "")


def _is_json_with(*keys: str) -> Callable[[httpx.Response], bool]:
    def check(r: httpx.Response) -> bool:
        try:
            data = r.json()
        except ValueError:
            return False
        return isinstance(data, dict) and any(k in data for k in keys)
    return check


def _env_like(r: httpx.Response) -> bool:
    return _not_html(r) and bool(re.search(r"^[A-Za-z0-9_.]+\s*=\s*\S*", _text(r), re.M))


def _contains(*needles: str, plain: bool = False) -> Callable[[httpx.Response], bool]:
    """Body contains any needle (case-insensitive); ``plain`` also rejects HTML."""

    def check(r: httpx.Response) -> bool:
        if plain and not _not_html(r):
            return False
        text = _text(r).lower()
        return any(n.lower() in text for n in needles)

    return check


def _magic(prefix: bytes) -> Callable[[httpx.Response], bool]:
    return lambda r: r.content[: len(prefix)] == prefix


def _sql(r: httpx.Response) -> bool:
    return _not_html(r) and bool(re.search(r"create table|insert into|drop table", _text(r), re.I))


def _php_source(r: httpx.Response) -> bool:
    return "<?php" in _text(r)


# (path, severity, title, validator)
EXPOSURES: list[tuple[str, str, str, Callable[[httpx.Response], bool]]] = [
    ("robots.txt", "info", "robots.txt present", _contains("user-agent", "disallow", plain=True)),
    ("sitemap.xml", "info", "sitemap.xml present", _contains("<urlset", "<sitemapindex")),
    (".well-known/security.txt", "info", "security.txt present", _contains("contact:", plain=True)),
    (".git/HEAD", "high", "Exposed Git repository (.git/HEAD)", lambda r: _text(r).startswith("ref:")),
    (".git/config", "high", "Exposed Git config (.git/config)", _contains("[core]")),
    (".env", "high", "Exposed environment file (.env)", _env_like),
    (".env.local", "high", "Exposed environment file (.env.local)", _env_like),
    (".DS_Store", "low", "Exposed .DS_Store (directory listing leak)", _magic(b"\x00\x00\x00\x01Bud1")),
    (".htaccess", "medium", "Readable .htaccess", _contains("rewriteengine", "authtype", "deny from", "require ", plain=True)),
    (".svn/entries", "high", "Exposed Subversion metadata", lambda r: _not_html(r) and len(r.content) > 0),
    ("backup.zip", "high", "Downloadable backup archive (backup.zip)", _magic(b"PK")),
    ("site.zip", "high", "Downloadable backup archive (site.zip)", _magic(b"PK")),
    ("backup.sql", "high", "Downloadable SQL dump (backup.sql)", _sql),
    ("db.sql", "high", "Downloadable SQL dump (db.sql)", _sql),
    ("dump.sql", "high", "Downloadable SQL dump (dump.sql)", _sql),
    ("wp-config.php.bak", "high", "Config source disclosed (wp-config.php.bak)", _php_source),
    ("config.php.bak", "high", "Config source disclosed (config.php.bak)", _php_source),
    ("phpinfo.php", "medium", "phpinfo() page exposed", _contains("php version", "phpinfo()")),
    ("server-status", "medium", "Apache server-status exposed", _contains("apache server status")),
    ("actuator/health", "low", "Spring actuator health exposed", _is_json_with("status")),
    ("actuator/env", "high", "Spring actuator env exposed", _is_json_with("propertySources", "activeProfiles")),
    ("package.json", "low", "package.json readable (dependency disclosure)", _is_json_with("dependencies", "devDependencies", "scripts")),
    ("composer.json", "low", "composer.json readable (dependency disclosure)", _is_json_with("require", "autoload")),
    ("Dockerfile", "medium", "Dockerfile readable", lambda r: _not_html(r) and bool(re.search(r"^\s*FROM\s+\S+", _text(r), re.M | re.I))),
    ("docker-compose.yml", "medium", "docker-compose.yml readable", _contains("services:", plain=True)),
    ("uploads/", "medium", "Directory listing enabled (/uploads/)", _contains("index of /")),
    ("backup/", "high", "Directory listing enabled (/backup/)", _contains("index of /")),
    ("files/", "medium", "Directory listing enabled (/files/)", _contains("index of /")),
    ("openapi.json", "info", "OpenAPI spec exposed", _is_json_with("openapi", "swagger")),
    ("swagger.json", "info", "Swagger spec exposed", _is_json_with("openapi", "swagger")),
]

DEEP_EXPOSURES: list[tuple[str, str, str, Callable[[httpx.Response], bool]]] = [
    (".env.production", "high", "Exposed environment file (.env.production)", _env_like),
    (".env.backup", "high", "Exposed environment file (.env.backup)", _env_like),
    (".git/index", "high", "Exposed Git index", _magic(b"DIRC")),
    (".gitignore", "low", ".gitignore readable", lambda r: _not_html(r) and len(r.content) > 0),
    ("web.config", "medium", "web.config readable", _contains("<configuration", plain=True)),
    ("crossdomain.xml", "info", "crossdomain.xml present", _contains("cross-domain-policy")),
    ("config.json", "medium", "config.json readable", _is_json_with("password", "secret", "apiKey", "api_key", "database", "db")),
    ("database.sql", "high", "Downloadable SQL dump (database.sql)", _sql),
    ("www.zip", "high", "Downloadable backup archive (www.zip)", _magic(b"PK")),
    ("backup.tar.gz", "high", "Downloadable backup archive (backup.tar.gz)", _magic(b"\x1f\x8b")),
    ("info.php", "medium", "phpinfo() page exposed (info.php)", _contains("php version", "phpinfo()")),
    ("test.php", "low", "test.php present", _php_source),
    ("index.php.bak", "high", "Source disclosed (index.php.bak)", _php_source),
    ("elmah.axd", "medium", "ELMAH error log exposed", _contains("error log for")),
    ("trace.axd", "medium", "ASP.NET trace exposed", _contains("application trace")),
    ("console", "high", "Debug console exposed", _contains("werkzeug", "interactive console")),
    ("_profiler", "medium", "Symfony profiler exposed", _contains("symfony profiler")),
    ("error_log", "medium", "error_log readable", lambda r: _not_html(r) and bool(re.search(r"\[\w{3} \w{3} \d+", _text(r)))),
]


def _fingerprint(r: httpx.Response) -> tuple[int, str, int, str]:
    return (
        r.status_code,
        r.headers.get("content-type", "").split(";")[0],
        len(r.content),
        hashlib.sha1(r.content[:2048]).hexdigest(),
    )


def matches_baseline(r: httpx.Response, base: tuple[int, str, int, str] | None) -> bool:
    """True when a response is just the site's generic not-found/catch-all page."""
    if base is None:
        return False
    status, ctype, length, digest = _fingerprint(r)
    b_status, b_ctype, b_length, b_digest = base
    if status != b_status or ctype != b_ctype:
        return False
    return digest == b_digest or abs(length - b_length) <= max(32, int(0.05 * b_length))


def check_exposures(
    fetcher: Fetcher,
    origin: str,
    items: list,
    baseline: tuple[int, str, int, str] | None,
) -> tuple[list[dict], list[str], bool]:
    found: list[dict] = []
    robots_disallow: list[str] = []
    skipped = False
    for path, severity, title, validator in items:
        r = fetcher.get(f"{origin}/{path}", follow_redirects=False)
        if r is None:
            if fetcher.exhausted:
                skipped = True
                break
            continue
        if r.status_code != 200 or matches_baseline(r, baseline):
            continue
        try:
            valid = validator(r)
        except Exception:
            valid = False
        if not valid:
            continue
        found.append({"path": f"/{path}", "severity": severity, "title": title})
        if path == "robots.txt":
            robots_disallow = [
                line.split(":", 1)[1].strip()
                for line in _text(r).splitlines()
                if line.lower().startswith("disallow:") and line.split(":", 1)[1].strip()
            ][:15]
    return found, robots_disallow, skipped


# --------------------------------------------------------------------- cookies
def analyze_cookies(set_cookie_headers: list[str], is_https: bool) -> list[dict]:
    cookies = []
    for raw in set_cookie_headers:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0]
        attrs = {p.split("=", 1)[0].lower(): (p.split("=", 1)[1] if "=" in p else "") for p in parts[1:]}
        cookies.append(
            {
                "name": name,
                "secure": "secure" in attrs,
                "httponly": "httponly" in attrs,
                "samesite": attrs.get("samesite") or "-",
            }
        )
    return cookies


# ------------------------------------------------------------------------- TLS
def analyze_tls(host: str, port: int, timeout: float = 8.0) -> dict[str, Any]:
    info: dict[str, Any] = {}

    def handshake(ctx: ssl.SSLContext):
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return tls.getpeercert(), tls.version(), (tls.cipher() or ("?",))[0]

    try:
        cert, version, cipher = handshake(ssl.create_default_context())
        info.update(trusted=True, protocol=version, cipher=cipher)
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        info["subject"] = subject.get("commonName", "-")
        info["issuer"] = issuer.get("organizationName") or issuer.get("commonName", "-")
        info["san"] = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:10]
        info["not_after"] = cert.get("notAfter")
        if cert.get("notAfter"):
            info["days_left"] = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400)
    except ssl.SSLCertVerificationError as error:
        info.update(trusted=False, verify_error=error.verify_message or str(error))
        loose = ssl.create_default_context()
        loose.check_hostname = False
        loose.verify_mode = ssl.CERT_NONE
        try:
            _, version, cipher = handshake(loose)
            info.update(protocol=version, cipher=cipher)
        except (OSError, ssl.SSLError):
            pass
    except (OSError, ssl.SSLError) as error:
        return {"error": f"{type(error).__name__}: {error}"}
    return info




# --------------------------------------------------- WordPress (conditional)
WORDPRESS_PROBES: list[tuple[str, str, str, Callable[[httpx.Response], bool]]] = [
    ("wp-json/wp/v2/users", "medium", "WordPress user enumeration via REST API",
     lambda r: _text(r).lstrip().startswith("[") and '"slug"' in _text(r)),
    ("xmlrpc.php", "low", "WordPress XML-RPC enabled", _contains("xml-rpc server accepts post")),
    ("wp-content/debug.log", "high", "WordPress debug.log exposed",
     lambda r: _not_html(r) and len(r.content) > 0),
    ("readme.html", "low", "WordPress readme.html reveals version", _contains("wordpress")),
]

# ------------------------------------------------------ content intelligence
SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Stripe live key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
]
ENDPOINT_RE = re.compile(r"""["'`](/(?:api|v\d|graphql|rest|admin|auth|oauth|internal)[A-Za-z0-9_\-./{}:]*)["'`]""")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)")
SENSITIVE_COMMENT = re.compile(r"password|passwd|secret|token|api[_-]?key|credential|todo|fixme|debug|admin", re.I)
SENSITIVE_PATH = re.compile(r"admin|backup|private|internal|config|db|staging|secret|old|dev", re.I)

LIB_PATTERNS = {
    "jQuery": [re.compile(r"jquery[-.@/]v?(\d+\.\d+\.\d+)", re.I), re.compile(r"jQuery(?: JavaScript Library)? v(\d+\.\d+\.\d+)")],
    "Bootstrap": [re.compile(r"bootstrap[-.@/]v?(\d+\.\d+\.\d+)", re.I), re.compile(r"Bootstrap v(\d+\.\d+\.\d+)")],
    "AngularJS": [re.compile(r"angular(?:\.min)?[-.@/]v?(1\.\d+\.\d+)", re.I), re.compile(r"AngularJS v(1\.\d+\.\d+)")],
}

COOKIE_TECH = {
    "phpsessid": "PHP", "jsessionid": "Java", "asp.net_sessionid": "ASP.NET",
    "laravel_session": "Laravel", "csrftoken": "Django", "connect.sid": "Express (Node.js)",
}


def mask(value: str) -> str:
    return f"{value[:4]}…{value[-2:]}" if len(value) > 8 else "…"


def scan_secrets(text: str) -> list[dict[str, str]]:
    found, seen = [], set()
    for label, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            key = (label, m.group(0))
            if key not in seen:
                seen.add(key)
                found.append({"type": label, "sample": mask(m.group(0))})
    return found


def find_endpoints(text: str) -> list[str]:
    return sorted(set(ENDPOINT_RE.findall(text)))[:30]


def find_emails(text: str) -> list[str]:
    bad_ext = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js")
    return sorted({e.lower() for e in EMAIL_RE.findall(text) if not e.lower().endswith(bad_ext)})[:20]


def detect_libraries(*texts: str) -> dict[str, str]:
    libs: dict[str, str] = {}
    for name, patterns in LIB_PATTERNS.items():
        for text in texts:
            for pattern in patterns:
                m = pattern.search(text)
                if m:
                    libs.setdefault(name, m.group(1))
    return libs


def _ver(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def outdated_library_findings(libs: dict[str, str]) -> list[dict]:
    out = []
    if (v := libs.get("jQuery")) and _ver(v) < (3, 5, 0):
        out.append(finding("medium", f"Outdated jQuery {v}", "XSS flaws CVE-2020-11022/11023 (fixed in 3.5.0)",
                           "Upgrade jQuery to 3.5.0 or newer."))
    if (v := libs.get("Bootstrap")) and ((_ver(v) < (3, 4, 1)) or ((4, 0, 0) <= _ver(v) < (4, 3, 1))):
        out.append(finding("low", f"Outdated Bootstrap {v}", "XSS flaw CVE-2019-8331",
                           "Upgrade Bootstrap to 3.4.1 / 4.3.1 or newer."))
    if (v := libs.get("AngularJS")):
        out.append(finding("medium", f"AngularJS {v} is end-of-life", "No security fixes since Dec 2021",
                           "Migrate to a supported framework."))
    return out


def cookie_technologies(cookies: list[dict]) -> list[str]:
    return sorted({COOKIE_TECH[c["name"].lower()] for c in cookies if c["name"].lower() in COOKIE_TECH})


FIX = {
    "hsts": "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
    "csp": "Add a Content-Security-Policy, e.g. `default-src 'self'`, and loosen only as needed.",
    "xfo": "Send `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`.",
    "nosniff": "Send `X-Content-Type-Options: nosniff`.",
    "referrer": "Send `Referrer-Policy: strict-origin-when-cross-origin`.",
    "server": "Hide the version (Apache: `ServerTokens Prod`; nginx: `server_tokens off`).",
    "powered": "Remove it (PHP: `expose_php = Off`; Express: `app.disable('x-powered-by')`).",
    "block_file": "Remove the file from the web root and block the path in the server config; rotate any secret it contained.",
}


# ----------------------------------------------------------------- the module
def _is_local(url: str) -> bool:
    host = urlsplit(url).hostname or ""
    return host in ("localhost", "127.0.0.1", "::1")


def _exposure_fix(path: str) -> str:
    if path.endswith("/"):
        return "Disable directory listing (Apache: `Options -Indexes`; nginx: `autoindex off`)."
    if path.startswith("/.git") or path.startswith("/.svn"):
        return "Deny access to VCS folders in the server config, remove them from the web root, and rotate any secrets in the history."
    return FIX["block_file"]


class WebScan(Module):
    name = "webscan"
    description = "Deep web audit: headers, exposed files, JS secrets, cookies, CORS, TLS, crawl"
    target_type = "domain"

    def validate(self, target: str) -> str:
        return validate_http_target(target)

    def collect(
        self,
        target: str,
        deep: bool = False,
        max_requests: int | None = None,
        **_: Any,
    ) -> dict[str, Any]:
        limit = max_requests or (DEEP_BUDGET if deep else NORMAL_BUDGET)
        page_cap = DEEP_PAGES if deep else NORMAL_PAGES
        js_cap = 12 if deep else 4
        probe_cap = 15 if deep else 5
        findings: list[dict] = []

        def add(sev: str, title: str, detail: str = "", fix: str = "") -> None:
            findings.append(finding(sev, title, detail, fix))

        # verify=False so a bad certificate never stops the audit; trust is
        # reported separately by the TLS step.
        with make_client(timeout=10.0, verify=False) as client:
            fetcher = Fetcher(client, limit)

            # 1. main page ---------------------------------------------------
            main = None
            for url in HttpFingerprint._candidate_urls(target):
                main = fetcher.get(url)
                if main is not None:
                    break
            if main is None:
                raise ModuleError("Could not connect over HTTP(S).")

            final_url = norm_url(str(main.url))
            origin = origin_of(final_url)
            split = urlsplit(final_url)
            is_https = split.scheme == "https"
            local = _is_local(final_url)
            headers = dict(main.headers)
            lowered = {k.lower(): v for k, v in headers.items()}
            body = main.text[:300_000]
            cookies = analyze_cookies(main.headers.get_list("set-cookie"), is_https)
            techs = set(detect_technologies(headers, body)) | set(cookie_technologies(cookies))

            # 2. headers -----------------------------------------------------
            if is_https and "strict-transport-security" not in lowered:
                add("medium", "Missing HSTS header", "Strict-Transport-Security not set", FIX["hsts"])
            if "content-security-policy" not in lowered:
                add("medium", "Missing Content-Security-Policy", "", FIX["csp"])
            if "x-frame-options" not in lowered and "frame-ancestors" not in lowered.get(
                "content-security-policy", ""
            ):
                add("low", "Clickjacking protection missing", "No X-Frame-Options / frame-ancestors", FIX["xfo"])
            if "x-content-type-options" not in lowered:
                add("low", "Missing X-Content-Type-Options header", "", FIX["nosniff"])
            if "referrer-policy" not in lowered:
                add("low", "Missing Referrer-Policy header", "", FIX["referrer"])
            if re.search(r"\d", lowered.get("server", "")):
                add("low", "Server header discloses version", lowered["server"], FIX["server"])
            if "x-powered-by" in lowered:
                add("low", "X-Powered-By discloses technology", lowered["x-powered-by"], FIX["powered"])

            # 3. exposure checks (baseline first to avoid SPA false positives)
            token = secrets.token_hex(6)
            base_resp = fetcher.get(f"{origin}/tracex-{token}", follow_redirects=False)
            baseline = _fingerprint(base_resp) if base_resp is not None else None
            items = EXPOSURES + (DEEP_EXPOSURES if deep else [])
            exposed, robots_disallow, skipped = check_exposures(fetcher, origin, items, baseline)

            if "WordPress" in techs:
                wp_found, _, wp_skipped = check_exposures(fetcher, origin, WORDPRESS_PROBES, baseline)
                exposed += wp_found
                skipped = skipped or wp_skipped
            for e in exposed:
                if e["severity"] != "info":
                    add(e["severity"], e["title"], e["path"], _exposure_fix(e["path"]))

            # 3b. robots.txt hints: are the "hidden" paths actually reachable?
            interesting: list[dict] = []
            for path in robots_disallow[:probe_cap]:
                if any(c in path for c in "*$") or not path.startswith("/") or fetcher.exhausted:
                    continue
                r = fetcher.get(origin + path, follow_redirects=False)
                if r is None or matches_baseline(r, baseline):
                    continue
                if r.status_code in (200, 401, 403):
                    interesting.append({"path": path, "status": r.status_code})
                    if r.status_code == 200:
                        add(
                            "low" if SENSITIVE_PATH.search(path) else "info",
                            "Path listed in robots.txt is publicly reachable",
                            path,
                            "robots.txt is not access control. Require authentication for private areas.",
                        )

            # 4. methods + CORS + HTTPS redirect ---------------------------------
            methods: list[str] = []
            opt = fetcher.request("OPTIONS", final_url)
            if opt is not None and opt.headers.get("allow"):
                methods = [m.strip().upper() for m in opt.headers["allow"].split(",")]
                if "TRACE" in methods:
                    add("medium", "HTTP TRACE method enabled", "",
                        "Disable it (Apache: `TraceEnable off`; nginx rejects it by default).")
                risky = [m for m in methods if m in ("PUT", "DELETE", "PATCH")]
                if risky:
                    add("low", "Write methods advertised", ", ".join(risky),
                        "Allow only the methods each route needs.")

            cors: dict[str, Any] = {}
            cr = fetcher.get(final_url, headers={"Origin": TEST_ORIGIN})
            if cr is not None:
                acao = cr.headers.get("access-control-allow-origin")
                acac = cr.headers.get("access-control-allow-credentials", "").lower() == "true"
                cors = {"allow_origin": acao or "-", "allow_credentials": acac}
                if acao == TEST_ORIGIN:
                    add(
                        "high" if acac else "medium",
                        "CORS reflects arbitrary Origin",
                        "with credentials allowed" if acac else "",
                        "Validate Origin against an allow-list; never reflect it, especially with credentials.",
                    )
                elif acao == "*":
                    add("low", "CORS allows any origin (*)", "",
                        "Restrict Access-Control-Allow-Origin unless the API is intentionally public.")

            if is_https and not local and split.hostname:
                r = fetcher.get(f"http://{split.hostname}/", follow_redirects=False)
                if r is not None:
                    loc = r.headers.get("location", "")
                    if r.status_code == 200 or (r.status_code in (301, 302, 303, 307, 308)
                                                and not loc.lower().startswith("https://")):
                        add("medium", "HTTP is not redirected to HTTPS",
                            f"http://{split.hostname}/ -> {r.status_code}",
                            "Redirect all HTTP traffic to HTTPS (301) and enable HSTS.")

            # 5. TLS ----------------------------------------------------------
            tls: dict[str, Any] = {}
            if is_https:
                tls = analyze_tls(split.hostname or "", split.port or 443)
                if tls.get("error"):
                    add("medium", "TLS handshake failed", tls["error"], "Check the certificate chain and server TLS config.")
                else:
                    if tls.get("trusted") is False:
                        add("high", "Certificate not trusted", tls.get("verify_error", ""),
                            "Install a certificate from a trusted CA (e.g. Let's Encrypt) with the full chain.")
                    if tls.get("protocol") in ("TLSv1", "TLSv1.1"):
                        add("high", "Obsolete TLS protocol", tls["protocol"], "Allow only TLS 1.2 and 1.3.")
                    days = tls.get("days_left")
                    if days is not None and days < 0:
                        add("high", "TLS certificate expired", f"{-days} days ago", "Renew the certificate now.")
                    elif days is not None and days < 30:
                        add("medium", "TLS certificate expires soon", f"{days} days left",
                            "Renew it and automate renewal (certbot/ACME).")
            else:
                add("info" if local else "medium", "Site served over plain HTTP", final_url,
                    "Serve the site over HTTPS and redirect HTTP to it.")

            # 6. cookies ------------------------------------------------------
            for c in cookies:
                if is_https and not c["secure"]:
                    add("medium", f"Cookie '{c['name']}' missing Secure", "", "Set the Secure attribute.")
                if not c["httponly"]:
                    add("medium" if SESSIONISH.search(c["name"]) else "low",
                        f"Cookie '{c['name']}' missing HttpOnly", "",
                        "Set HttpOnly so scripts cannot read the cookie (PHP: `session.cookie_httponly=1`).")
                if c["samesite"] == "-":
                    add("low", f"Cookie '{c['name']}' missing SameSite", "",
                        "Set SameSite=Lax (or Strict) to reduce CSRF risk.")

            # 7. crawl + JavaScript analysis (same origin, remaining budget) ----
            pages = {final_url: main}
            queue: list[str] = []
            parsers: dict[str, PageParser] = {}
            page_texts: dict[str, str] = {}

            def parse(url: str, resp: httpx.Response) -> None:
                if "html" not in resp.headers.get("content-type", "") and "<html" not in resp.text[:500].lower():
                    return
                page_texts[url] = resp.text[:300_000]
                p = PageParser(url)
                p.feed(page_texts[url])
                parsers[url] = p
                for link in p.links:
                    link = norm_url(link)
                    if (
                        origin_of(link) == origin
                        and link not in pages
                        and link not in queue
                        and not ASSET_EXT.search(urlsplit(link).path)
                    ):
                        queue.append(link)

            parse(final_url, main)

            js_texts: list[tuple[str, str]] = []
            main_scripts = parsers[final_url].scripts if final_url in parsers else []
            js_urls = []
            for s_ in main_scripts:
                if origin_of(s_["src"]) == origin and s_["src"] not in js_urls:
                    js_urls.append(s_["src"])
            for js_url in js_urls[:js_cap]:
                r = fetcher.get(js_url)
                if r is not None and r.status_code == 200:
                    js_texts.append((js_url, r.text[:500_000]))

            maps_checked = 0
            for js_url, text in js_texts:
                m = SOURCEMAP_RE.search(text[-2000:])
                if m and maps_checked < 3 and not m.group(1).startswith("data:") and not fetcher.exhausted:
                    map_url = urljoin(js_url, m.group(1))
                    if origin_of(map_url) == origin:
                        maps_checked += 1
                        r = fetcher.get(map_url)
                        if r is not None and r.status_code == 200 and '"sources"' in r.text[:5000]:
                            add("medium", "JavaScript source map exposed", urlsplit(map_url).path,
                                "Do not deploy .map files to production, or restrict them to developers.")

            while queue and len(pages) < page_cap and not fetcher.exhausted:
                url = queue.pop(0)
                resp = fetcher.get(url)
                pages[url] = resp
                if resp is not None:
                    parse(url, resp)

            # ---- aggregate what the crawl learned
            all_links = {l for p in parsers.values() for l in p.links}
            internal = sorted(l for l in all_links if origin_of(l) == origin)
            external_hosts = sorted(
                {
                    urlsplit(u).netloc
                    for p in parsers.values()
                    for u in (p.links + p.resources + [s["src"] for s in p.scripts])
                    if origin_of(u) != origin
                }
            )
            seen_forms: set[tuple] = set()
            forms = []
            for p in parsers.values():
                for f in p.forms:
                    key = (f["action"], f["method"], tuple(f["inputs"]))
                    if key not in seen_forms:
                        seen_forms.add(key)
                        forms.append(f)
            ext_scripts = [s_ for p in parsers.values() for s_ in p.scripts if origin_of(s_["src"]) != origin]
            no_sri = sorted({s_["src"] for s_ in ext_scripts if not s_["integrity"]})

            for f in forms:
                if f["has_password"] and urlsplit(f["action"]).scheme == "http" and not _is_local(f["action"]):
                    add("high", "Login form submits over plain HTTP", f["action"],
                        "Serve the login page and its action over HTTPS only.")
                if origin_of(f["action"]) != origin:
                    add("medium", "Form posts to another origin", f["action"],
                        "Confirm the third-party endpoint is trusted.")
            if no_sri:
                add("low", f"{len(no_sri)} external script(s) without SRI", ", ".join(no_sri[:3]),
                    'Add `integrity="sha384-..." crossorigin="anonymous"` to third-party scripts.')
            if is_https:
                mixed = sorted(
                    {u for p in parsers.values() for u in p.resources + [s_["src"] for s_ in p.scripts]
                     if u.startswith("http://")}
                )
                if mixed:
                    add("medium", "Mixed content (http:// resources on https page)", ", ".join(mixed[:3]),
                        "Load every resource over HTTPS.")

            # secrets, endpoints, emails, comments, libraries
            sources = [(u, t) for u, t in js_texts] + [(u, t) for u, t in page_texts.items()]
            secrets_found: list[dict] = []
            endpoints: set[str] = set()
            emails: set[str] = set()
            for src_url, text in sources:
                for sec in scan_secrets(text):
                    secrets_found.append({"file": urlsplit(src_url).path or "/", **sec})
                endpoints.update(find_endpoints(text))
                emails.update(find_emails(text))
            for sec in secrets_found:
                add("high", f"Possible secret in client-side code: {sec['type']}",
                    f"{sec['file']} ({sec['sample']})",
                    "Remove it from public code, rotate it, and call the third-party API from your server.")

            comments = sorted({
                c[:120] for p in parsers.values() for c in p.comments if SENSITIVE_COMMENT.search(c)
            })[:10]
            if comments:
                add("low", "HTML comments contain sensitive-looking words", f"{len(comments)} comment(s)",
                    "Strip comments from production HTML (build step or template engine).")

            libs = detect_libraries(
                " ".join(s_["src"] for p in parsers.values() for s_ in p.scripts),
                *[t[:600] for _, t in js_texts],
            )
            for lf in outdated_library_findings(libs):
                findings.append(lf)
            techs -= set(libs)  # drop bare names; keep the versioned form
            techs |= {f"{n} {v}" for n, v in libs.items()}

            if skipped or fetcher.exhausted:
                add("info", "Request budget reached",
                    "Some checks were skipped", "Run with --deep or --max-requests N for full coverage.")

            title_match = TITLE.search(body)
            findings = sort_findings(findings)
            counts = count_by_severity(findings)
            score = max(0, 100 - sum(PENALTY[s_] * n for s_, n in counts.items()))

            return {
                "url": final_url,
                "status": main.status_code,
                "title": " ".join(title_match.group(1).split()) if title_match else None,
                "requests_used": f"{fetcher.used}/{fetcher.limit}",
                "score": score,
                "grade": grade_for(score),
                "summary": counts,
                "findings": findings,
                "technologies": sorted(techs),
                "libraries": libs,
                "redirects": [f"{r.status_code} {r.url}" for r in main.history],
                "tls": tls,
                "methods": methods,
                "cors": cors,
                "cookies": cookies,
                "public_files": [e["path"] for e in exposed if e["severity"] == "info"],
                "exposed_paths": exposed,
                "interesting_paths": interesting,
                "robots_disallow": robots_disallow,
                "api_endpoints": sorted(endpoints)[:30],
                "secrets": secrets_found,
                "emails": sorted(emails)[:20],
                "comments": comments,
                "pages_crawled": len([p for p in pages.values() if p is not None]),
                "internal_links": len(internal),
                "forms": [
                    {"page": f["page"], "action": f["action"], "method": f["method"],
                     "inputs": f["inputs"], "password": f["has_password"]}
                    for f in forms
                ],
                "external_domains": external_hosts,
            }
