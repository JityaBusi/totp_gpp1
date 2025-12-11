import base64
import os

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


def load_private_key(path: str = "student_private.pem"):
    """Load RSA private key from PEM file."""
    with open(path, "rb") as f:
        key_data = f.read()

    private_key = serialization.load_pem_private_key(
        key_data,
        password=None,
    )
    return private_key


def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP with SHA-256.

    Returns:
        Decrypted hex seed (64-character string)
    """

    # 1. Base64 decode the encrypted seed string
    encrypted_bytes = base64.b64decode(encrypted_seed_b64)

    # 2. RSA/OAEP decrypt with SHA-256
    decrypted_bytes = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 3. Decode bytes to UTF-8 string
    seed = decrypted_bytes.decode("utf-8")

    # 4. Validate: must be 64-character hex string
    if len(seed) != 64:
        raise ValueError(f"Decrypted seed length is {len(seed)}, expected 64")

    allowed = set("0123456789abcdef")
    if not all(c in allowed for c in seed):
        raise ValueError("Decrypted seed is not a valid hex string")

    # 5. Return hex seed
    return seed


def main():
    # Make sure encrypted_seed.txt exists (from previous step)
    with open("encrypted_seed.txt", "r", encoding="utf-8") as f:
        encrypted_seed_b64 = f.read().strip()

    # Load your private key
    private_key = load_private_key("student_private.pem")

    # Decrypt
    hex_seed = decrypt_seed(encrypted_seed_b64, private_key)

    # Ensure data/ directory exists
    os.makedirs("data", exist_ok=True)

    # Store at data/seed.txt
    output_path = os.path.join("data", "seed.txt")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(hex_seed)

    print("Decrypted seed:", hex_seed)
    print(f"Saved to {output_path}")


if __name__ == "__main__":
    main()