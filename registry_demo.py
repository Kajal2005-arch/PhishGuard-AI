
from pathlib import Path

from key_manager import load_or_create_key_pair
from signature_utils import save_public_key
from threat_registry import (
    create_threat_record,
    verify_threat_record,
)
from threat_store import load_registry, save_registry


ROOT = Path(__file__).resolve().parent
REGISTRY_PATH = ROOT / "data" / "threat_registry.json"
PUBLIC_KEY_PATH = ROOT / "keys" / "ed25519_public.pem"


def main():
    private_key, public_key = load_or_create_key_pair()

    # Save the public key so the verification workflow can load it.
    save_public_key(public_key, str(PUBLIC_KEY_PATH))

    url = input("Enter a URL to register as a reported threat: ").strip()
    if not url:
        print("No URL entered. Nothing was saved.")
        return

    # This creates a signed report; it does not independently prove
    # that the URL is malicious.
    signed_record = create_threat_record(
        url=url,
        status="reported_phishing",
        source="PhishGuard-AI demo",
        private_key=private_key,
    )

    # Verify before adding the record to the registry.
    if not verify_threat_record(signed_record, public_key):
        print("Signature verification failed. Record not saved.")
        return

    records = load_registry(REGISTRY_PATH)
    records.append(signed_record)
    save_registry(records, REGISTRY_PATH)

    print("\nSigned report saved successfully.")
    print("Signature valid:", verify_threat_record(signed_record, public_key))
    print("Registry records:", len(records))
    print("URL fingerprint:", signed_record["record"]["url_fingerprint"])


if __name__ == "__main__":
    main()
