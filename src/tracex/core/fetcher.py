from __future__ import annotations

import httpx


class Fetcher:
    """HTTP client wrapper that enforces a hard request budget."""

    def __init__(self, client: httpx.Client, limit: int) -> None:
        self.client = client
        self.limit = limit
        self.used = 0
        self.errors = 0

    @property
    def exhausted(self) -> bool:
        return self.used >= self.limit

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
    ) -> httpx.Response | None:
        """Send one request. Returns None if the budget is spent or it fails."""
        if self.exhausted:
            return None
        self.used += 1
        try:
            return self.client.request(
                method, url, headers=headers, follow_redirects=follow_redirects
            )
        except httpx.HTTPError:
            self.errors += 1
            return None

    def get(self, url: str, **kwargs) -> httpx.Response | None:
        return self.request("GET", url, **kwargs)
