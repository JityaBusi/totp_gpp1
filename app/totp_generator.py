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


def generate_totp_code(hex_seed: str):
    """
    Generate current 6-digit TOTP code and seconds remaining in this 30-second window.
    Returns:
        code (str), valid_for (int)
    """
    base32_seed = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
    code = totp.now()
    remaining = totp.interval - (int(time.time()) % totp.interval)
    return code, remaining


def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify TOTP code with ±valid_window periods tolerance.
    """
    base32_seed = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
    return totp.verify(code, valid_window=valid_window)
