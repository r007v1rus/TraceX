import pytest

from tracex.utils.validators import validate_domain, validate_username


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("example.com", "example.com"),
        ("  Example.COM.  ", "example.com"),
        ("sub.domain.example.org", "sub.domain.example.org"),
        ("bücher.de", "xn--bcher-kva.de"),
        ("a-b.co", "a-b.co"),
    ],
)
def test_valid_domains(raw, expected):
    assert validate_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["", "   ", "localhost", "192.168.1.1", "::1", "-bad.com", "bad-.com",
     "exa mple.com", "example.c", "a" * 64 + ".com", ("a." * 130) + "com",
     "exa_mple.com", "http://example.com"],
)
def test_invalid_domains(raw):
    with pytest.raises(ValueError):
        validate_domain(raw)


def test_ip_error_message():
    with pytest.raises(ValueError, match="not an IP"):
        validate_domain("8.8.8.8")


@pytest.mark.parametrize("raw, expected", [("octocat", "octocat"), ("@octo.cat_1", "octo.cat_1"), (" a ", "a")])
def test_valid_usernames(raw, expected):
    assert validate_username(raw) == expected


@pytest.mark.parametrize("raw", ["", "-bad", "bad-", "has space", "a/b", "x" * 40, "../etc"])
def test_invalid_usernames(raw):
    with pytest.raises(ValueError):
        validate_username(raw)
