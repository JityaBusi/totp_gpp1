from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel
from pathlib import Path

from app.crypto_operations import load_private_key, decrypt_seed
from app.totp_generator import generate_totp_code, verify_totp_code
from app.decrypt_seed import router as decrypt_seed_router

# app = FastAPI(title="PKI-based 2FA Microservice")
app = FastAPI(title="PKI-based 2FA Microservice")
app.include_router(decrypt_seed_router)

# Register router AFTER app creation
app.include_router(decrypt_seed_router)

# ---------- Fixed paths (MANDATORY) ----------
SEED_PATH = Path("/data/seed.bin")
PRIVATE_KEY_PATH = Path("/app/student_private.pem")

# ---------- Request models ----------
class DecryptSeedRequest(BaseModel):
    encrypted_seed: str


class VerifyRequest(BaseModel):
    code: str | None = None


# ---------- Helpers ----------
def read_seed_bytes() -> bytes:
    if not SEED_PATH.exists():
        raise FileNotFoundError("Seed not decrypted yet")
    return SEED_PATH.read_bytes()


# ---------- Endpoints ----------
@app.post("/decrypt-seed")
def decrypt_seed_endpoint(payload: DecryptSeedRequest = Body(...)):
    try:
        private_key = load_private_key(PRIVATE_KEY_PATH)
        seed_bytes = decrypt_seed(payload.encrypted_seed, private_key)

        SEED_PATH.parent.mkdir(parents=True, exist_ok=True)
        SEED_PATH.write_bytes(seed_bytes)

        return {"status": "seed stored"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/generate-2fa")
def generate_2fa():
    try:
        seed_bytes = read_seed_bytes()
        code, valid_for = generate_totp_code(seed_bytes)
        return {"code": code, "valid_for": valid_for}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/verify-2fa")
def verify_2fa(payload: VerifyRequest):
    if not payload.code:
        raise HTTPException(status_code=400, detail="Missing code")

    try:
        seed_bytes = read_seed_bytes()
        valid = verify_totp_code(seed_bytes, payload.code, valid_window=1)
        return {"valid": bool(valid)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
def health():
    return {"status": "ok"}
