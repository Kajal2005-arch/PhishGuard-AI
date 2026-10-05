
import json

from signature_utils import generate_key_pair, sign_record, save_public_key
from verified_threat_store import load_verified_records
from threat_store import save_registry


def test_loads_valid_signed_record(tmp_path):
    private_key, public_key = generate_key_pair()

    record = {
        "url_fingerprint": "a" * 64,
        "status": "reported_phishing",
        "source": "test_source",
    }

    signed_record = {
        "record": record,
        "signature": sign_record(record, private_key),
    }

    public_key_path = tmp_path / "public.pem"
    registry_path = tmp_path / "registry.json"

    save_public_key(public_key, str(public_key_path))
    save_registry([signed_record], registry_path)

    result = load_verified_records(public_key_path, registry_path)

    assert result == [signed_record]


def test_rejects_tampered_record(tmp_path):
    private_key, public_key = generate_key_pair()

    record = {
        "url_fingerprint": "a" * 64,
        "status": "reported_phishing",
        "source": "test_source",
    }

    signed_record = {
        "record": record,
        "signature": sign_record(record, private_key),
    }

    signed_record["record"]["status"] = "reported_legitimate"

    public_key_path = tmp_path / "public.pem"
    registry_path = tmp_path / "registry.json"

    save_public_key(public_key, str(public_key_path))
    save_registry([signed_record], registry_path)

    result = load_verified_records(public_key_path, registry_path)

    assert result == []


def test_rejects_malformed_record(tmp_path):
    _, public_key = generate_key_pair()

    public_key_path = tmp_path / "public.pem"
    registry_path = tmp_path / "registry.json"

    save_public_key(public_key, str(public_key_path))
    registry_path.write_text(
        json.dumps([{"unexpected": "structure"}]),
        encoding="utf-8",
    )

    result = load_verified_records(public_key_path, registry_path)

    assert result == []
