import httpx

from tracex import __version__

USER_AGENT = f"TraceX/{__version__} (+authorized-recon)"


def make_client(
    timeout: float = 10.0, follow_redirects: bool = True, verify: bool = True
) -> httpx.Client:
    return httpx.Client(
        timeout=timeout,
        follow_redirects=follow_redirects,
        verify=verify,
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
    )
