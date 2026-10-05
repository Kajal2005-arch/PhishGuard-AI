
from signature_utils import (
    generate_key_pair,
    sign_record,
    verify_record_signature,
)


def test_valid_signature_verifies():
    private_key, public_key = generate_key_pair()
    record = {"url": "https://example.com", "status": "phishing"}
    signature = sign_record(record, private_key)

    assert verify_record_signature(record, signature, public_key) is True


def test_modified_record_fails():
    private_key, public_key = generate_key_pair()
    record = {"url": "https://example.com", "status": "phishing"}
    signature = sign_record(record, private_key)

    modified_record = {"url": "https://example.com", "status": "safe"}

    assert verify_record_signature(
        modified_record, signature, public_key
    ) is False


def test_wrong_key_fails():
    private_key, public_key = generate_key_pair()
    _, another_public_key = generate_key_pair()
    record = {"url": "https://example.com", "status": "phishing"}
    signature = sign_record(record, private_key)

    assert verify_record_signature(
        record, signature, another_public_key
    ) is False


def test_key_order_does_not_matter():
    private_key, public_key = generate_key_pair()
    first = {"url": "https://example.com", "status": "phishing"}
    second = {"status": "phishing", "url": "https://example.com"}
    signature = sign_record(first, private_key)

    assert verify_record_signature(second, signature, public_key) is True
