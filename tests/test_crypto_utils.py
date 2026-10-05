
import hashlib
import pytest

from crypto_utils import normalize_url, url_fingerprint


def test_hostname_and_scheme_are_normalized():
    first = url_fingerprint("HTTPS://Example.com/login")
    second = url_fingerprint("https://example.com/login")

    assert first == second


def test_different_paths_have_different_fingerprints():
    login = url_fingerprint("https://example.com/login")
    verify = url_fingerprint("https://example.com/verify")

    assert login != verify


def test_fingerprint_is_sha256_hex():
    result = url_fingerprint("https://example.com")

    assert len(result) == 64
    assert all(char in "0123456789abcdef" for char in result)


def test_empty_url_is_rejected():
    with pytest.raises(ValueError):
        normalize_url("")


def test_unsupported_scheme_is_rejected():
    with pytest.raises(ValueError):
        normalize_url("ftp://example.com")
