from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64

def generate_rsa_keypair(key_size: int = 4096):
    # 1. Generate private key with public exponent 65537
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    # 2. Extract public key
    public_key = private_key.public_key()

    # 3. Serialize private key into PEM format (PKCS8)
    private_pem = private_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.PKCS8,
        encryption_algorithm = serialization.NoEncryption()
    )

    # 4. Serialize public key into PEM format
    public_pem = public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save the files
    with open("student_private.pem", "wb") as f:
        f.write(private_pem)

    with open("student_public.pem", "wb") as f:
        f.write(public_pem)

    print("✔ Generated student_private.pem and student_public.pem")

    return private_key, public_key

def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

def decrypt_seed(encrypted_seed_b64: str, private_key):
    ciphertext = base64.b64decode(encrypted_seed_b64)
    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )
    return decrypted.hex()  # 64-char hex string


if __name__ == "__main__":
    generate_rsa_keypair()
