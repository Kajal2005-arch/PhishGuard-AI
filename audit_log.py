
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_AUDIT_PATH = Path("data") / "audit_log.jsonl"
GENESIS_HASH = "0" * 64


def canonicalize(entry):
    return json.dumps(
        entry,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def calculate_entry_hash(entry):
    return hashlib.sha256(canonicalize(entry)).hexdigest()


def verify_audit_entries(entries):
    """Verify the sequence and hashes of an audit log."""
    previous_hash = GENESIS_HASH

    for item in entries:
        if not isinstance(item, dict):
            return False

        entry = item.get("entry")
        stored_hash = item.get("hash")

        if not isinstance(entry, dict):
            return False

        if entry.get("previous_hash") != previous_hash:
            return False

        if not isinstance(stored_hash, str):
            return False

        if calculate_entry_hash(entry) != stored_hash:
            return False

        previous_hash = stored_hash

    return True


def load_audit_log(path=DEFAULT_AUDIT_PATH):
    path = Path(path)

    if not path.exists():
        return []

    entries = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid audit JSON on line {line_number}"
                ) from exc

            entries.append(item)

    if not verify_audit_entries(entries):
        raise ValueError("Audit log integrity verification failed.")

    return entries


def append_audit_event(event_type, details, path=DEFAULT_AUDIT_PATH):
    if not isinstance(event_type, str) or not event_type.strip():
        raise ValueError("Event type must be a non-empty string.")

    if not isinstance(details, dict):
        raise TypeError("Event details must be a dictionary.")

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Verify existing history before appending anything.
    entries = load_audit_log(path)
    previous_hash = entries[-1]["hash"] if entries else GENESIS_HASH

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "details": details,
        "previous_hash": previous_hash,
    }

    item = {
        "entry": entry,
        "hash": calculate_entry_hash(entry),
    }

    # Append one JSON record per line.
    with path.open("a", encoding="utf-8", newline="\n") as file:
        file.write(json.dumps(item, ensure_ascii=False) + "\n")
        file.flush()
        os.fsync(file.fileno())

    return item
