#!/usr/bin/env python3

import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# ---------------------------
# CONFIG: Set your file paths
# ---------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))

# PEM files are expected to be in project root
PRIVATE_KEY_PATH = os.path.join(PROJECT_ROOT, "student_private.pem")
PUBLIC_KEY_PATH = os.path.join(PROJECT_ROOT, "student_public.pem")

# Example commit hash (replace with actual commit you want to test)
COMMIT_HASH = "06af1b6ef96102b5c66ef85111fa39eb894c1b49"

# ---------------------------
# Load private key
# ---------------------------
with open(PRIVATE_KEY_PATH, "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )

# ---------------------------
# Sign the commit hash (ASCII)
# ---------------------------
signature = private_key.sign(
    COMMIT_HASH.encode("utf-8"),  # ASCII encoding
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print(f"Signature (hex preview): {signature.hex()[:64]}...")  # first 64 chars

# ---------------------------
# Load public key
# ---------------------------
with open(PUBLIC_KEY_PATH, "rb") as f:
    public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )

# ---------------------------
# Verify signature
# ---------------------------
try:
    public_key.verify(
        signature,
        COMMIT_HASH.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("✅ Signature verification successful!")
except Exception as e:
    print("❌ Signature verification failed:", e)
