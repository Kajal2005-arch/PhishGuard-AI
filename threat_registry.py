
from crypto_utils import url_fingerprint
from signature_utils import (
    generate_key_pair,
    sign_record,
    verify_record_signature,
)


def create_threat_record(url, status, source, private_key):
    """Create and sign a threat-intelligence record."""
    if status not in {"reported_phishing", "reported_legitimate"}:
        raise ValueError("Unsupported threat status.")

    if not isinstance(source, str) or not source.strip():
        raise ValueError("Source must be a non-empty string.")

    record = {
        "url_fingerprint": url_fingerprint(url),
        "status": status,
        "source": source.strip(),
    }

    signature = sign_record(record, private_key)

    return {
        "record": record,
        "signature": signature,
    }


def verify_threat_record(signed_record, public_key):
    """Verify a signed record before trusting its contents."""
    if not isinstance(signed_record, dict):
        return False

    record = signed_record.get("record")
    signature = signed_record.get("signature")

    if not isinstance(record, dict) or not isinstance(signature, str):
        return False

    # Check the record's expected structure.
    expected_fields = {
        "url_fingerprint",
        "status",
        "source",
    }

    if set(record.keys()) != expected_fields:
        return False

    if record["status"] not in {
        "reported_phishing",
        "reported_legitimate",
    }:
        return False

    if not isinstance(record["source"], str) or not record["source"].strip():
        return False

    fingerprint = record["url_fingerprint"]

    if (
        not isinstance(fingerprint, str)
        or len(fingerprint) != 64
        or any(c not in "0123456789abcdef" for c in fingerprint)
    ):
        return False

    return verify_record_signature(record, signature, public_key)


if __name__ == "__main__":
    # Demo only: generate a temporary key pair in memory.
    private_key, public_key = generate_key_pair()

    signed_record = create_threat_record(
        url="https://example.com/login",
        status="reported_phishing",
        source="demo",
        private_key=private_key,
    )

    print(
        "Original record valid:",
        verify_threat_record(signed_record, public_key),
    )

    tampered_record = {
        "record": {
            **signed_record["record"],
            "status": "reported_legitimate",
        },
        "signature": signed_record["signature"],
    }

    print(
        "Tampered record valid:",
        verify_threat_record(tampered_record, public_key),
    )
