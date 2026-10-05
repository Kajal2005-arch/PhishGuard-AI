
import json

import pytest

from threat_store import load_registry, save_registry


def test_save_and_reload_registry(tmp_path):
    path = tmp_path / "threat_registry.json"

    records = [
        {
            "record": {
                "url_fingerprint": "a" * 64,
                "status": "reported_phishing",
                "source": "test_source",
            },
            "signature": "example_signature",
        }
    ]

    save_registry(records, path)
    loaded_records = load_registry(path)

    assert loaded_records == records


def test_missing_registry_returns_empty_list(tmp_path):
    path = tmp_path / "missing.json"

    assert load_registry(path) == []


def test_invalid_json_raises_error(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text("{invalid json", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid JSON"):
        load_registry(path)


def test_registry_must_be_a_list(tmp_path):
    path = tmp_path / "invalid_structure.json"
    path.write_text(
        json.dumps({"record": "not a list"}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="JSON list"):
        load_registry(path)


def test_save_rejects_non_list(tmp_path):
    path = tmp_path / "registry.json"

    with pytest.raises(TypeError, match="list"):
        save_registry({"record": "not a list"}, path)

    assert not path.exists()
