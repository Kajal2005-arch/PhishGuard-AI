
import re
import numpy as np
import pandas as pd

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "dot_count",
    "hyphen_count",
    "at_count",
    "question_count",
    "equal_count",
    "ampersand_count",
    "percent_count",
    "digit_count",
    "letter_count",
    "slash_count",
    "underscore_count",
    "https_present",
    "ip_address_present",
    "suspicious_word_count",
    "subdomain_count",
]

SUSPICIOUS_WORDS = [
    "login", "verify", "update", "secure",
    "account", "signin", "password", "bank",
    "confirm", "paypal", "wallet", "suspended",
]


def extract_features(urls):
    """Extract lexical features from a list or Series of URLs."""

    urls = pd.Series(urls).fillna("").astype(str).reset_index(drop=True)

    features = pd.DataFrame(index=urls.index)

    # Work with the URL text without visiting the website.
    text = urls.str.lower()

    # Extract a hostname from URLs with or without a scheme.
    normalized = text.where(
        text.str.match(r"^[a-z][a-z0-9+.-]*://"),
        "http://" + text
    )

    hostname = normalized.str.extract(
        r"^[a-z][a-z0-9+.-]*://([^/?#]*)",
        expand=False
    ).fillna("")

    hostname = hostname.str.rsplit("@", n=1).str[-1]
    hostname = hostname.str.split(":", n=1).str[0]

    features["url_length"] = text.str.len()
    features["hostname_length"] = hostname.str.len()
    features["path_length"] = (
        text.str.len() - hostname.str.len()
    ).clip(lower=0)

    features["dot_count"] = text.str.count(r"\.")
    features["hyphen_count"] = text.str.count("-")
    features["at_count"] = text.str.count("@")
    features["question_count"] = text.str.count(r"\?")
    features["equal_count"] = text.str.count("=")
    features["ampersand_count"] = text.str.count("&")
    features["percent_count"] = text.str.count("%")
    features["digit_count"] = text.str.count(r"\d")
    features["letter_count"] = text.str.count(r"[a-z]")
    features["slash_count"] = text.str.count("/")
    features["underscore_count"] = text.str.count("_")

    features["https_present"] = (
        text.str.startswith("https://")
    ).astype(int)

    # Detect IPv4-looking hosts.
    ip_pattern = (
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )

    features["ip_address_present"] = (
        hostname.str.match(ip_pattern)
    ).astype(int)

    # Count suspicious terms as a heuristic, not a verdict.
    features["suspicious_word_count"] = sum(
        text.str.count(re.escape(word))
        for word in SUSPICIOUS_WORDS
    )

    features["subdomain_count"] = (
        hostname.str.count(r"\.") - 1
    ).clip(lower=0)

    return features[FEATURE_NAMES].replace(
        [np.inf, -np.inf], np.nan
    ).fillna(0)
