# from pathlib import Path

# # Read encrypted seed
# encrypted_seed_b64 = Path("encrypted_seed.txt").read_text().strip()


# # Print first 80 chars to verify
# print("Encrypted seed loaded:")
# print(encrypted_seed_b64[:80])

# ===== IMPORTS =====
from pathlib import Path
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

# ===== REST OF THE CODE =====
# Read encrypted seed
encrypted_seed_b64 = Path("encrypted_seed.txt").read_text().strip()
print("Encrypted seed loaded:")
print(encrypted_seed_b64[:80])

# Load private key
private_key_path = "student_private.pem"  # update with your private key file
with open(private_key_path, "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# Decrypt seed
decrypted_bytes = private_key.decrypt(
    base64.b64decode(encrypted_seed_b64),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
decrypted_seed = decrypted_bytes.decode("utf-8")

# Validate
if len(decrypted_seed) != 64:
    raise ValueError("Invalid seed length")
if not all(c in "0123456789abcdef" for c in decrypted_seed):
    raise ValueError("Seed contains invalid characters")

print("Decrypted seed:", decrypted_seed)

