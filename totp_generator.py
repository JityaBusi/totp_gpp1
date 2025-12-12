import base64
import binascii
import time
import pyotp


def hex_to_base32(hex_seed: str) -> str:
    """
    Convert 64-char hex seed to base32 string (for TOTP libraries).
    """
    # hex -> raw bytes
    raw = binascii.unhexlify(hex_seed)
    # bytes -> base32 string
    return base64.b32encode(raw).decode("ascii")


def generate_totp_code(hex_seed: str) -> str:
    """
    Generate current 6-digit TOTP code from 64-char hex seed.
    """
    base32_seed = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)  # SHA-1 default
    return totp.now()


def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify TOTP code with ±valid_window periods tolerance.
    """
    base32_seed = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
    return totp.verify(code, valid_window=valid_window)
