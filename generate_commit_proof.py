#!/usr/bin/env python3
"""
generate_commit_proof.py

Usage:
  python generate_commit_proof.py \
    --student-key student_private.pem \
    --instructor-key instructor_public.pem \
    [--student-key-pass PASSWORD]

Outputs:
  Commit Hash: <40-char-hex>
  Encrypted Signature (base64): <single-line base64 string>
"""

import argparse
import base64
import subprocess
import sys
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.padding import MGF1

# -------------------------
# Cryptographic primitives
# -------------------------
def sign_message(message: str, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Sign a message using RSA-PSS with SHA-256.

    - message: ASCII string (commit hash). We sign message.encode('utf-8')
    - private_key: RSAPrivateKey object from cryptography
    - returns: signature bytes
    """
    message_bytes = message.encode("utf-8")  # CRITICAL: sign ASCII/UTF-8 string, not binary hex
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def encrypt_with_public_key(data: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """
    Encrypt data using RSA/OAEP with SHA-256.

    - data: bytes to encrypt (the signature)
    - public_key: RSAPublicKey object
    - returns: ciphertext bytes
    """
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext


# -------------------------
# Helper functions
# -------------------------
def get_git_commit_hash(repo_path: Path = Path(".")) -> str:
    """Return the latest commit hash (40-character hex) from git in repo_path."""
    try:
        # Use subprocess to call git; ensure we call from the repo root
        res = subprocess.run(
            ["git", "log", "-1", "--format=%H"],
            cwd=str(repo_path),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        commit_hash = res.stdout.strip()
        if len(commit_hash) != 40 or any(c not in "0123456789abcdef" for c in commit_hash.lower()):
            raise ValueError(f"Unexpected commit hash format: '{commit_hash}'")
        return commit_hash
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"git command failed: {e.stderr.strip() or e}") from e


def load_private_key(path: Path, password: Optional[str] = None) -> rsa.RSAPrivateKey:
    pem = path.read_bytes()
    pwd = password.encode("utf-8") if password is not None else None
    key = serialization.load_pem_private_key(pem, password=pwd)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Loaded private key is not an RSA private key")
    return key


def load_public_key(path: Path) -> rsa.RSAPublicKey:
    pem = path.read_bytes()
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("Loaded public key is not an RSA public key")
    return key


# -------------------------
# Main CLI
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="Generate commit proof: sign commit hash, encrypt signature, base64 output.")
    parser.add_argument("--student-key", "-s", required=True, help="Path to student_private.pem (PEM, RSA private key)")
    parser.add_argument("--instructor-key", "-i", required=True, help="Path to instructor_public.pem (PEM, RSA public key)")
    parser.add_argument("--student-key-pass", "-p", default=None, help="Password for student private key, if encrypted")
    parser.add_argument("--repo-path", "-r", default=".", help="Path to git repository (default: current directory)")
    args = parser.parse_args()

    student_key_path = Path(args.student_key)
    instructor_key_path = Path(args.instructor_key)
    repo_path = Path(args.repo_path)

    if not student_key_path.exists():
        print(f"Student private key not found: {student_key_path}", file=sys.stderr)
        sys.exit(2)
    if not instructor_key_path.exists():
        print(f"Instructor public key not found: {instructor_key_path}", file=sys.stderr)
        sys.exit(2)

    try:
        commit_hash = get_git_commit_hash(repo_path)
    except Exception as e:
        print(f"Failed to get git commit hash: {e}", file=sys.stderr)
        sys.exit(3)

    try:
        student_priv = load_private_key(student_key_path, args.student_key_pass)
    except Exception as e:
        print(f"Failed to load student private key: {e}", file=sys.stderr)
        sys.exit(4)

    try:
        instructor_pub = load_public_key(instructor_key_path)
    except Exception as e:
        print(f"Failed to load instructor public key: {e}", file=sys.stderr)
        sys.exit(5)

    # Sign commit hash
    try:
        signature = sign_message(commit_hash, student_priv)
    except Exception as e:
        print(f"Failed to sign commit hash: {e}", file=sys.stderr)
        sys.exit(6)

    # Encrypt signature with instructor public key
    try:
        ciphertext = encrypt_with_public_key(signature, instructor_pub)
    except Exception as e:
        print(f"Failed to encrypt signature: {e}", file=sys.stderr)
        sys.exit(7)

    # Base64 encode ciphertext and print results
    b64 = base64.b64encode(ciphertext).decode("ascii")
    print("Commit Hash:", commit_hash)
    print("Encrypted Signature (base64):")
    print(b64)


if __name__ == "__main__":
    main()
