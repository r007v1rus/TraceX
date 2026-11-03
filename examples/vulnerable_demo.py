#!/usr/bin/env python3
"""A deliberately vulnerable web server for practising with TraceX.

It binds to 127.0.0.1 ONLY and every "secret" in it is fake. Never expose it
to a network or deploy it anywhere.

    python examples/vulnerable_demo.py            # serves on http://127.0.0.1:8000
    tracex webscan localhost:8000
"""

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer

INDEX = """<html><head><title>Vulnerable Demo</title>
<meta name="generator" content="DemoCMS 1.0">
<script src="/static/jquery-1.12.4.min.js"></script>
<script src="/static/app.js"></script>
<script src="https://cdn.example.net/widget.js"></script></head><body>
<!-- TODO: remove the admin password before launch -->
<h1>Demo shop</h1><a href="/about">About</a> <a href="/login">Login</a>
<p>Contact: support@demo.test</p>
<form action="/login" method="post"><input name="user"><input name="pw" type="password"></form>
</body></html>"""

ROUTES = {
    "/": (INDEX, "text/html"),
    "/about": ("<html><body><a href='/'>home</a></body></html>", "text/html"),
    "/login": ("<html><body>login page</body></html>", "text/html"),
    "/admin": ("<html><body>admin console</body></html>", "text/html"),
    "/robots.txt": ("User-agent: *\nDisallow: /admin\nDisallow: /backup\n", "text/plain"),
    "/static/jquery-1.12.4.min.js": ("/*! jQuery v1.12.4 | (c) jQuery Foundation */", "application/javascript"),
    # AKIAIOSFODNN7EXAMPLE is the fake key from AWS's own documentation.
    "/static/app.js": (
        'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";\n'
        'fetch("/api/v1/users");\nfetch("/api/v1/orders");\n'
        "//# sourceMappingURL=app.js.map",
        "application/javascript",
    ),
    "/static/app.js.map": ('{"version":3,"sources":["src/app.js"]}', "application/json"),
    "/.git/HEAD": ("ref: refs/heads/main\n", "text/plain"),
    "/.env": ("DB_PASSWORD=not-a-real-password\nAPI_KEY=not-a-real-key\n", "text/plain"),
    "/backup/": ("<html><title>Index of /backup/</title><h1>Index of /backup/</h1></html>", "text/html"),
}


class Handler(BaseHTTPRequestHandler):
    server_version = "DemoServer/1.2"

    def _send(self, code, body, ctype="text/html", extra=()):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Powered-By", "PHP/7.4.3")
        for key, value in extra:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        origin = self.headers.get("Origin")
        extra = []
        if self.path == "/":
            extra.append(("Set-Cookie", "PHPSESSID=demo123; Path=/"))
        if origin:  # reflects any origin, with credentials: a classic CORS mistake
            extra += [("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", "true")]
        if self.path in ROUTES:
            body, ctype = ROUTES[self.path]
            self._send(200, body, ctype, extra)
        else:
            self._send(404, "not found", "text/plain")

    def do_OPTIONS(self):
        self._send(200, "", "text/plain", [("Allow", "GET, POST, TRACE, DELETE")])

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8000)
    port = parser.parse_args().port
    print(f"Vulnerable demo on http://127.0.0.1:{port}  (Ctrl+C to stop)")
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
