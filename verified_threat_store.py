
from pathlib import Path

from signature_utils import load_public_key
from threat_registry import verify_threat_record
from threat_store import load_registry


def load_verified_records(
    public_key_path,
    registry_path=Path("data") / "threat_registry.json",
):
    """
    Load registry records and return only records with
    valid signatures from the supplied public key.
    """
    public_key = load_public_key(Path(public_key_path))
    records = load_registry(registry_path)

    verified_records = []

    for signed_record in records:
        try:
            if verify_threat_record(signed_record, public_key):
                verified_records.append(signed_record)
        except (TypeError, ValueError, KeyError):
            # Malformed records must not be trusted.
            continue

    return verified_records
