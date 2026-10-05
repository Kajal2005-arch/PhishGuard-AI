
from pathlib import Path

from key_manager import load_or_create_key_pair
from signature_utils import load_public_key
from threat_store import load_registry
from verified_threat_store import load_verified_records


ROOT = Path(__file__).resolve().parent


def main():
    _, public_key = load_or_create_key_pair()

    public_key_path = ROOT / "keys" / "ed25519_public.pem"
    registry_path = ROOT / "data" / "threat_registry.json"

    # Ensure the public key loaded from disk matches the key manager.
    stored_public_key = load_public_key(str(public_key_path))

    assert (
        stored_public_key.public_bytes_raw()
        == public_key.public_bytes_raw()
    ), "Stored public key does not match the key manager."

    records = load_registry(registry_path)
    verified = load_verified_records(public_key_path, registry_path)

    print("Records stored:", len(records))
    print("Records verified:", len(verified))
    print("Persistence and signature verification passed.")


if __name__ == "__main__":
    main()
