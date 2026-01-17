from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from pathlib import Path

from app.crypto_operations import load_private_key, decrypt_seed

router = APIRouter()

SEED_PATH = Path("/data/seed.bin")
PRIVATE_KEY_PATH = Path("/app/student_private.pem")


class DecryptSeedRequest(BaseModel):
    encrypted_seed: str


@router.post("/decrypt-seed")
def decrypt_seed_endpoint(payload: DecryptSeedRequest):
    """
    Decrypt evaluator-provided encrypted seed using PKI and store it.
    """

    # 1. Load private key
    try:
        private_key = load_private_key(PRIVATE_KEY_PATH)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Private key load failed: {e}",
        )

    # 2. Decrypt seed
    try:
        seed_hex = decrypt_seed(payload.encrypted_seed, private_key)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Seed decryption failed: {e}",
        )

    # 3. Persist seed
    try:
        SEED_PATH.parent.mkdir(parents=True, exist_ok=True)
        SEED_PATH.write_bytes(seed_hex.encode("utf-8"))
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to store seed: {e}",
        )

    # REQUIRED exact response
    return {"status": "seed stored"}
