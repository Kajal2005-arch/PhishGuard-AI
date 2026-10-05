
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

KEY_DIR = Path(__file__).resolve().parent / "keys"
PRIVATE_KEY_PATH = KEY_DIR / "ed25519_private.pem"
PUBLIC_KEY_PATH = KEY_DIR / "ed25519_public.pem"


def load_or_create_key_pair():
    """Load the existing Ed25519 keys or create them once."""
    KEY_DIR.mkdir(parents=True, exist_ok=True)

    if PRIVATE_KEY_PATH.exists() != PUBLIC_KEY_PATH.exists():
        raise RuntimeError(
            "Only one key file exists. Restore the matching key pair "
            "from a trusted backup before continuing."
        )

    if PRIVATE_KEY_PATH.exists():
        with PRIVATE_KEY_PATH.open("rb") as file:
            private_key = serialization.load_pem_private_key(
                file.read(),
                password=None,
            )

        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("Private key must be an Ed25519 key.")

        public_key = private_key.public_key()

        with PUBLIC_KEY_PATH.open("rb") as file:
            stored_public_key = serialization.load_pem_public_key(
                file.read()
            )

        if not isinstance(stored_public_key, Ed25519PublicKey):
            raise TypeError("Public key must be an Ed25519 key.")

        if (
            stored_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            != public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ):
            raise RuntimeError(
                "Private and public keys do not match. "
                "Do not overwrite either key."
            )

        return private_key, public_key

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Exclusive creation avoids silently overwriting an existing key.
    with PRIVATE_KEY_PATH.open("xb") as file:
        file.write(private_pem)

    try:
        with PUBLIC_KEY_PATH.open("xb") as file:
            file.write(public_pem)
    except Exception:
        # Do not leave an incomplete key pair that could be reused.
        PRIVATE_KEY_PATH.unlink(missing_ok=True)
        raise

    return private_key, public_key


if __name__ == "__main__":
    private_key, public_key = load_or_create_key_pair()

    print("Ed25519 key pair is ready.")
    print(f"Private key exists: {PRIVATE_KEY_PATH.exists()}")
    print(f"Public key exists: {PUBLIC_KEY_PATH.exists()}")
    print("Private key:", PRIVATE_KEY_PATH)
    print("Public key:", PUBLIC_KEY_PATH)
