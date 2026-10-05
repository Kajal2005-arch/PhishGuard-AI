
import json
import tempfile
from pathlib import Path

from key_manager import load_or_create_key_pair
from threat_store import save_registry
from verified_threat_store import load_verified_records


def main():
    _, public_key = load_or_create_key_pair()

    project_root = Path(__file__).resolve().parent
    public_key_path = project_root / "keys" / "ed25519_public.pem"
    original_path = project_root / "data" / "threat_registry.json"

    with original_path.open("r", encoding="utf-8") as file:
        records = json.load(file)

    if not records:
        print("No records available for the test.")
        return

    tampered_records = json.loads(json.dumps(records))
    tampered_records[0]["record"]["status"] = "reported_legitimate"

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir) / "tampered_registry.json"
        save_registry(tampered_records, temp_path)

        verified = load_verified_records(
            public_key_path,
            temp_path,
        )

    print("Original records:", len(records))
    print("Records verified after tampering:", len(verified))
    print("Tampering detected:", len(verified) < len(tampered_records))


if __name__ == "__main__":
    main()
