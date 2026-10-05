
import json

import pytest

from audit_log import (
    append_audit_event,
    load_audit_log,
    verify_audit_entries,
)


def test_append_and_load_events(tmp_path):
    path = tmp_path / "audit.jsonl"

    append_audit_event("scan_completed", {"url_fingerprint": "abc"}, path)
    append_audit_event("report_checked", {"verified": True}, path)

    entries = load_audit_log(path)

    assert len(entries) == 2
    assert verify_audit_entries(entries)


def test_detects_modified_entry(tmp_path):
    path = tmp_path / "audit.jsonl"

    append_audit_event("scan_completed", {"result": "test"}, path)
    entries = load_audit_log(path)

    entries[0]["entry"]["details"]["result"] = "modified"

    assert not verify_audit_entries(entries)


def test_detects_deleted_middle_entry(tmp_path):
    path = tmp_path / "audit.jsonl"

    append_audit_event("first", {}, path)
    append_audit_event("second", {}, path)
    append_audit_event("third", {}, path)

    entries = load_audit_log(path)
    del entries[1]

    assert not verify_audit_entries(entries)


def test_corrupted_json_is_rejected(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("{broken json\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid audit JSON"):
        load_audit_log(path)
