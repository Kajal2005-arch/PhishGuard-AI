
import pytest

from signature_utils import generate_key_pair
from threat_registry import (
    create_threat_record,
    verify_threat_record,
)


@pytest.fixture
def keys():
    return generate_key_pair()


@pytest.fixture
def signed_record(keys):
    private_key, _ = keys

    return create_threat_record(
        url="https://example.com/login",
        status="reported_phishing",
        source="demo",
        private_key=private_key,
    )


def test_valid_record_passes(keys, signed_record):
    _, public_key = keys

    assert verify_threat_record(signed_record, public_key) is True


def test_tampered_record_fails(keys, signed_record):
    _, public_key = keys

    tampered = {
        "record": {
            **signed_record["record"],
            "status": "reported_legitimate",
        },
        "signature": signed_record["signature"],
    }

    assert verify_threat_record(tampered, public_key) is False


def test_wrong_key_fails(signed_record):
    _, wrong_public_key = generate_key_pair()

    assert verify_threat_record(
        signed_record, wrong_public_key
    ) is False


def test_invalid_record_structure_is_rejected(keys):
    _, public_key = keys

    assert verify_threat_record({}, public_key) is False


def test_unsupported_status_is_rejected(keys):
    private_key, public_key = keys

    with pytest.raises(ValueError):
        create_threat_record(
            url="https://example.com",
            status="unknown",
            source="demo",
            private_key=private_key,
        )
