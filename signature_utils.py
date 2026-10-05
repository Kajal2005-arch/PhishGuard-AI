
import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonicalize_record(record: dict) -> bytes:
    """Convert a record into consistent bytes before signing."""
    if not isinstance(record, dict):
        raise TypeError("Record must be a dictionary.")

    canonical_json = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )

    return canonical_json.encode("utf-8")


def generate_key_pair():
    """Generate an Ed25519 private and public key pair."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def sign_record(record: dict, private_key: Ed25519PrivateKey) -> str:
    """Sign a record and return its Base64-encoded signature."""
    record_bytes = canonicalize_record(record)
    signature = private_key.sign(record_bytes)
    return base64.b64encode(signature).decode("ascii")


def verify_record_signature(
    record: dict,
    signature_b64: str,
    public_key: Ed25519PublicKey,
) -> bool:
    """Return True only if the signature verifies for this record."""
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        public_key.verify(signature, canonicalize_record(record))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def save_public_key(public_key: Ed25519PublicKey, path: str) -> None:
    """Save the public key in PEM format."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, "wb") as file:
        file.write(pem)


def load_public_key(path: str) -> Ed25519PublicKey:
    """Load a public key from a PEM file."""
    with open(path, "rb") as file:
        key = serialization.load_pem_public_key(file.read())

    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("The file does not contain an Ed25519 public key.")

    return key


if __name__ == "__main__":
    private_key, public_key = generate_key_pair()

    threat_record = {
        "url": "https://example.com/login",
        "status": "reported_phishing",
        "source": "demo",
    }

    signature = sign_record(threat_record, private_key)

    print("Valid record:", verify_record_signature(
        threat_record, signature, public_key
    ))

    tampered_record = {
        **threat_record,
        "status": "verified_safe",
    }

    print("Tampered record:", verify_record_signature(
        tampered_record, signature, public_key
    ))
