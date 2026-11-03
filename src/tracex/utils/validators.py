import ipaddress
import re
from urllib.parse import urlsplit

_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_USERNAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,37}[A-Za-z0-9])?")


def validate_domain(domain: str) -> str:
    """
    Validate and normalize a domain name.
    Returns the normalized domain or raises ValueError.
    """

    domain = domain.strip().rstrip(".")

    if not domain:
        raise ValueError("Domain cannot be empty.")

    if len(domain) > 253:
        raise ValueError("Domain name is too long.")

    # Reject IP addresses
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("Please provide a domain, not an IP address.")

    # Convert internationalized domain names to ASCII
    try:
        domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("Invalid international domain name.")

    labels = domain.split(".")

    if len(labels) < 2:
        raise ValueError("A fully qualified domain is required.")

    for label in labels:
        if not _LABEL.fullmatch(label):
            raise ValueError(f"Invalid domain label: {label}")

    if len(labels[-1]) < 2:
        raise ValueError("Invalid top-level domain.")

    return domain


def validate_username(username: str) -> str:
    """Validate a username (letters, digits, '.', '_', '-'; max 39 chars)."""

    username = username.strip().lstrip("@")

    if not username:
        raise ValueError("Username cannot be empty.")

    if not _USERNAME.fullmatch(username):
        raise ValueError(
            "Invalid username: use 1-39 letters, digits, '.', '_' or '-' "
            "(must start and end with a letter or digit)."
        )

    return username


def validate_http_target(target: str) -> str:
    """
    Validate a target for the HTTP module.

    Accepts a public domain, ``localhost`` or an IP address, optionally with
    a scheme, a port and a path: ``example.com``, ``localhost:8080``,
    ``http://127.0.0.1:3000/login``.
    Returns a normalised string (scheme only kept if one was given).
    """

    raw = target.strip()
    if not raw:
        raise ValueError("Target cannot be empty.")

    scheme = ""
    if "://" in raw:
        scheme = raw.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            raise ValueError("Only http:// and https:// targets are supported.")

    try:
        parts = urlsplit(raw if scheme else f"//{raw}")
        host = parts.hostname
        port = parts.port
    except ValueError:
        raise ValueError("Invalid host or port.")

    if not host:
        raise ValueError("Could not find a host in the target.")

    if port is not None and not (1 <= port <= 65535):
        raise ValueError("Port must be between 1 and 65535.")

    try:
        ipaddress.ip_address(host)
        host_out = f"[{host}]" if ":" in host else host
    except ValueError:
        host_out = "localhost" if host == "localhost" else validate_domain(host)

    path = parts.path if parts.path not in ("", "/") else ""
    if parts.query:
        path += "?" + parts.query

    return (f"{scheme}://" if scheme else "") + host_out + (f":{port}" if port else "") + path
