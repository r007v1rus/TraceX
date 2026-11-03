from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx

from tracex.core.base import Module
from tracex.core.http import make_client

# name -> public profile URL template. Only sites that answer 200/404 reliably.
SITES: dict[str, str] = {
    "GitHub": "https://github.com/{u}",
    "GitLab": "https://gitlab.com/{u}",
    "Codeberg": "https://codeberg.org/{u}",
    "Dev.to": "https://dev.to/{u}",
    "PyPI": "https://pypi.org/user/{u}/",
    "Medium": "https://medium.com/@{u}",
}


def classify(status: int) -> str:
    if status == 200:
        return "found"
    if status == 404:
        return "not found"
    return "unknown"


class UsernameCheck(Module):
    """Checks whether a public profile exists for a username on a few sites."""

    name = "username"
    description = "Check if a username has a public profile on common developer sites"
    target_type = "username"

    def _check(self, client: httpx.Client, site: str, url: str) -> dict[str, str]:
        try:
            response = client.get(url)
            status = classify(response.status_code)
            note = f"HTTP {response.status_code}"
        except httpx.HTTPError as error:
            status, note = "unknown", type(error).__name__
        return {"site": site, "status": status, "url": url, "note": note}

    def collect(self, target: str, **_: Any) -> dict[str, Any]:
        with make_client(timeout=10.0) as client:
            with ThreadPoolExecutor(max_workers=6) as pool:
                futures = [
                    pool.submit(self._check, client, site, tpl.format(u=target))
                    for site, tpl in SITES.items()
                ]
                results = [f.result() for f in futures]

        found = sum(1 for r in results if r["status"] == "found")
        return {"found_on": found, "checked": len(results), "sites": results}
