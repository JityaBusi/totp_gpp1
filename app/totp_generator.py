import base64
import binascii
import time
import hmac
import hashlib


def hex_to_base32(hex_seed: str) -> str:
    """
    Convert a 64-character hex seed to a base32 string for TOTP usage.
    """
    raw = binascii.unhexlify(hex_seed)
    return base64.b32encode(raw).decode("ascii")


class TOTP:
    """
    RFC 6238-compliant TOTP generator and verifier.
    """

    def __init__(self, hex_seed: str, digits: int = 6, interval: int = 30, digest=hashlib.sha1):
        self.base32_seed = hex_to_base32(hex_seed)
        self.digits = digits
        self.interval = interval
        self.digest = digest

    def _int_to_bytes(self, i: int) -> bytes:
        return i.to_bytes(8, "big")

    def _truncate(self, hmac_digest: bytes) -> int:
        """
        Dynamic truncation per RFC 4226.
        """
        offset = hmac_digest[-1] & 0x0F
        code = (
            ((hmac_digest[offset] & 0x7F) << 24)
            | ((hmac_digest[offset + 1] & 0xFF) << 16)
            | ((hmac_digest[offset + 2] & 0xFF) << 8)
            | (hmac_digest[offset + 3] & 0xFF)
        )
        return code % (10 ** self.digits)

    def generate(self, for_time: int = None) -> (str, int):
        """
        Generate the current TOTP code and seconds remaining in the interval.
        """
        now = for_time or int(time.time())
        counter = now // self.interval
        key = base64.b32decode(self.base32_seed, casefold=True)
        hmac_digest = hmac.new(key, self._int_to_bytes(counter), self.digest).digest()
        code = str(self._truncate(hmac_digest)).zfill(self.digits)
        remaining = self.interval - (now % self.interval)
        return code, remaining

    def verify(self, code: str, valid_window: int = 1, for_time: int = None) -> bool:
        """
        Verify a TOTP code within ±valid_window intervals.
        """
        now = for_time or int(time.time())
        for offset in range(-valid_window, valid_window + 1):
            test_time = now + offset * self.interval
            generated_code, _ = self.generate(for_time=test_time)
            if hmac.compare_digest(generated_code, code):
                return True
        return False


# --- Helper Functions for Convenience ---

def generate_totp_code(hex_seed: str):
    totp = TOTP(hex_seed)
    return totp.generate()


def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    totp = TOTP(hex_seed)
    return totp.verify(code, valid_window=valid_window)
