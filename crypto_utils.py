
import hashlib
from urllib.parse import urlsplit, urlunsplit


def normalize_url(url: str) -> str:
    """
    Apply conservative URL normalization before fingerprinting.

    This is not a complete canonicalization standard.
    Paths and query strings are preserved because they may
    identify different resources.
    """
    if not isinstance(url, str):
        raise TypeError("URL must be a string.")

    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    if any(ord(char) < 32 for char in url):
        raise ValueError("URL contains control characters.")

    if any(char.isspace() for char in url):
        raise ValueError("URL cannot contain unescaped whitespace.")

    if "://" not in url:
        url = "https://" + url

    parts = urlsplit(url)

    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parts.hostname:
        raise ValueError("URL must contain a valid hostname.")

    # Normalize the hostname and scheme.
    scheme = parts.scheme.lower()
    hostname = parts.hostname.lower()

    # Preserve an explicitly specified port.
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port.") from exc

    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"

    netloc = hostname
    if port is not None:
        netloc = f"{netloc}:{port}"

    # Preserve path, query and fragment.
    normalized = urlunsplit((
        scheme,
        netloc,
        parts.path or "/",
        parts.query,
        parts.fragment,
    ))

    return normalized


def url_fingerprint(url: str) -> str:
    """
    Return the SHA-256 hex digest of the normalized URL.
    """
    normalized = normalize_url(url)
    return hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()


if __name__ == "__main__":
    examples = [
        "HTTPS://Example.com/login",
        "https://example.com/login",
        "https://example.com/verify",
    ]

    for example in examples:
        print("URL:         ", example)
        print("Normalized:  ", normalize_url(example))
        print("SHA-256:     ", url_fingerprint(example))
        print()
